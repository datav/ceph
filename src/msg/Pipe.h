// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#ifndef CEPH_MSGR_PIPE_H
#define CEPH_MSGR_PIPE_H

#include "msg_types.h"
#include "Messenger.h"
#include "auth/AuthSessionHandler.h"


class SimpleMessenger;
class IncomingQueue;
class DispatchQueue;

  /**
   * The Pipe is the most complex SimpleMessenger component. It gets
   * two threads, one each for reading and writing on a socket it's handed
   * at creation time, and is responsible for everything that happens on
   * that socket. Besides message transmission, it's responsible for
   * propagating socket errors to the SimpleMessenger and then sticking
   * around in a state where it can provide enough data for the SimpleMessenger
   * to provide reliable Message delivery when it manages to reconnect.
   */
  class Pipe : public RefCountedObject {
    /**
     * The Reader thread handles all reads off the socket -- not just
     * Messages, but also acks and other protocol bits (excepting startup,
     * when the Writer does a couple of reads).
     * All the work is implemented in Pipe itself, of course.
     */
    class Reader : public Thread {
      Pipe *pipe;
    public:
      Reader(Pipe *p) : pipe(p) {}
      void *entry() { pipe->reader(); return 0; }
    } reader_thread;
    friend class Reader;

    /**
     * The Writer thread handles all writes to the socket (after startup).
     * All the work is implemented in Pipe itself, of course.
     */
    class Writer : public Thread {
      Pipe *pipe;
    public:
      Writer(Pipe *p) : pipe(p) {}
      void *entry() { pipe->writer(); return 0; }
    } writer_thread;
    friend class Writer;

    /**
     * The DelayedDelivery is for injecting delays into Message delivery off
     * the socket. It is only enabled if delays are requested, and if they
     * are then it pulls Messages off the DelayQueue and puts them into the
     * in_q (SimpleMessenger::dispatch_queue).
     * Please note that this probably has issues with Pipe shutdown and
     * replacement semantics. I've tried, but no guarantees.
     */
    class DelayedDelivery: public Thread {
      Pipe *pipe;
      std::deque< pair<utime_t,Message*> > delay_queue;
      Mutex delay_lock;
      Cond delay_cond;
      bool stop_delayed_delivery;

    public:
      DelayedDelivery(Pipe *p)
	: pipe(p),
	  delay_lock("Pipe::DelayedDelivery::delay_lock"),
	  stop_delayed_delivery(false) { }
      ~DelayedDelivery() {
	discard();
      }
      void *entry();
      void queue(utime_t release, Message *m) {
	Mutex::Locker l(delay_lock);
	delay_queue.push_back(make_pair(release, m));
	delay_cond.Signal();
      }
      void discard();
      void flush();
      void stop() {
	delay_lock.Lock();
	stop_delayed_delivery = true;
	delay_cond.Signal();
	delay_lock.Unlock();
      }
    } *delay_thread;
    friend class DelayedDelivery;

  public:
    Pipe(SimpleMessenger *r, int st, Connection *con);
    ~Pipe();

    SimpleMessenger *msgr;
    uint64_t conn_id;
    ostream& _pipe_prefix(std::ostream *_dout);

    enum {
      STATE_ACCEPTING,
      STATE_CONNECTING,
      STATE_OPEN,
      STATE_STANDBY,
      STATE_CLOSED,
      STATE_CLOSING,
      STATE_WAIT       // just wait for racing connection
    };

    static const char *get_state_name(int s) {
      switch (s) {
      case STATE_ACCEPTING: return "accepting";
      case STATE_CONNECTING: return "connecting";
      case STATE_OPEN: return "open";
      case STATE_STANDBY: return "standby";
      case STATE_CLOSED: return "closed";
      case STATE_CLOSING: return "closing";
      case STATE_WAIT: return "wait";
      default: return "UNKNOWN";
      }
    }
    const char *get_state_name() {
      return get_state_name(state);
    }

    int sd;
    int port;
    int peer_type;
    entity_addr_t peer_addr;
    Messenger::Policy policy;
    
    Mutex pipe_lock;
    int state;

    // session_security handles any signatures or encryptions required for this pipe's msgs. PLR

    AuthSessionHandler *session_security;

  protected:
    friend class SimpleMessenger;
    Connection *connection_state;

    utime_t backoff;         // backoff time

    bool reader_running, reader_needs_join;
    bool writer_running;

    map<int, list<Message*> > out_q;  // priority queue for outbound msgs
    DispatchQueue *in_q;
    list<Message*> sent;
    Cond cond;
    bool keepalive;
    bool halt_delivery; //if a pipe's queue is destroyed, stop adding to it
    bool close_on_empty;
    
    __u32 connect_seq, peer_global_seq;
    uint64_t out_seq;
    uint64_t in_seq, in_seq_acked;
    
    int accept();   // server handshake
    int connect();  // client handshake
    void reader();
    void writer();
    void unlock_maybe_reap();

    int randomize_out_seq();

    int read_message(Message **pm);
    int write_message(Message *m);
    /**
     * Write the given data (of length len) to the Pipe's socket. This function
     * will loop until all passed data has been written out.
     * If more is set, the function will optimize socket writes
     * for additional data (by passing the MSG_MORE flag, aka TCP_CORK).
     *
     * @param msg The msghdr to write out
     * @param len The length of the data in msg
     * @param more Should be set true if this is one part of a larger message
     * @return 0, or -1 on failure (unrecoverable -- close the socket).
     */
    int do_sendmsg(struct msghdr *msg, int len, bool more=false);
    int write_ack(uint64_t s);
    int write_keepalive();

    void fault(bool reader=false);

    void was_session_reset();

    /* Clean up sent list */
    void handle_ack(uint64_t seq);

    public:
    Pipe(const Pipe& other);
    const Pipe& operator=(const Pipe& other);

    void start_reader();
    void start_writer();
    void maybe_start_delay_thread();
    void join_reader();

    // public constructors
    static const Pipe& Server(int s);
    static const Pipe& Client(const entity_addr_t& pi);

    __u32 get_out_seq() { return out_seq; }

    bool is_queued() { return !out_q.empty() || keepalive; }

    entity_addr_t& get_peer_addr() { return peer_addr; }

    void set_peer_addr(const entity_addr_t& a) {
      if (&peer_addr != &a)  // shut up valgrind
        peer_addr = a;
      connection_state->set_peer_addr(a);
    }
    void set_peer_type(int t) {
      peer_type = t;
      connection_state->set_peer_type(t);
    }

    void register_pipe();
    void unregister_pipe();
    void join() {
      if (writer_thread.is_started())
        writer_thread.join();
      if (reader_thread.is_started())
        reader_thread.join();
      if (delay_thread) {
	delay_thread->stop();
	delay_thread->join();
      }
    }
    void stop();

    void send(Message *m) {
      pipe_lock.Lock();
      _send(m);
      pipe_lock.Unlock();
    }
    void _send(Message *m) {
      out_q[m->get_priority()].push_back(m);
      cond.Signal();
    }
    void _send_keepalive() {
      keepalive = true;
      cond.Signal();
    }
    Message *_get_next_outgoing() {
      Message *m = 0;
      while (!m && !out_q.empty()) {
        map<int, list<Message*> >::reverse_iterator p = out_q.rbegin();
        if (!p->second.empty()) {
          m = p->second.front();
          p->second.pop_front();
        }
        if (p->second.empty())
          out_q.erase(p->first);
      }
      return m;
    }

    /* Remove all messages from the sent queue. Add those with seq > max_acked
     * to the highest priority outgoing queue. */
    void requeue_sent(uint64_t max_acked=0);
    void discard_out_queue();

    void shutdown_socket() {
      if (sd >= 0)
        ::shutdown(sd, SHUT_RDWR);
    }

    /**
     * do a blocking read of len bytes from socket
     *
     * @param buf buffer to read into
     * @param len exact number of bytes to read
     * @return 0 for success, or -1 on error
     */
    int tcp_read(char *buf, int len);

    /**
     * wait for bytes to become available on the socket
     *
     * @return 0 for success, or -1 on error
     */
    int tcp_read_wait();

    /**
     * non-blocking read of available bytes on socket
     *
     * This is expected to be used after tcp_read_wait(), and will return
     * an error if there is no data on the socket to consume.
     *
     * @param buf buffer to read into
     * @param len maximum number of bytes to read
     * @return bytes read, or -1 on error or when there is no data
     */
    int tcp_read_nonblocking(char *buf, int len);

    /**
     * blocking write of bytes to socket
     *
     * @param buf buffer
     * @param len number of bytes to write
     * @return 0 for success, or -1 on error
     */
    int tcp_write(const char *buf, int len);

  };


#endif
