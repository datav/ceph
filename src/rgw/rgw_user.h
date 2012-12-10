#ifndef CEPH_RGW_USER_H
#define CEPH_RGW_USER_H

#include <string>

#include "include/types.h"
#include "rgw_common.h"
#include "rgw_tools.h"

#include "rgw_rados.h"

#include "rgw_string.h"

using namespace std;

#define RGW_USER_ANON_ID "anonymous"

#define SECRET_KEY_LEN 40
#define PUBLIC_ID_LEN 20

/**
 * A string wrapper that includes encode/decode functions
 * for easily accessing a UID in all forms
 */
struct RGWUID
{
  string user_id;
  void encode(bufferlist& bl) const {
    ::encode(user_id, bl);
  }
  void decode(bufferlist::iterator& bl) {
    ::decode(user_id, bl);
  }
};
WRITE_CLASS_ENCODER(RGWUID)

/**
 * Get the anonymous (ie, unauthenticated) user info.
 */
extern void rgw_get_anon_user(RGWUserInfo& info);

/**
 * verify that user is an actual user, and not the anonymous user
 */
extern bool rgw_user_is_authenticated(RGWUserInfo& info);
/**
 * Save the given user information to storage.
 * Returns: 0 on success, -ERR# on failure.
 */
extern int rgw_store_user_info(RGWRados *store, RGWUserInfo& info, bool exclusive);
/**
 * Given an email, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_uid(RGWRados *store, string& user_id, RGWUserInfo& info);
/**
 * Given an swift username, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_email(RGWRados *store, string& email, RGWUserInfo& info);
/**
 * Given an swift username, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_swift(RGWRados *store, string& swift_name, RGWUserInfo& info);
/**
 * Given an access key, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_access_key(RGWRados *store, string& access_key, RGWUserInfo& info);
/**
 * Given an RGWUserInfo, deletes the user and its bucket ACLs.
 */
extern int rgw_delete_user(RGWRados *store, RGWUserInfo& user);
/**
 * Store a list of the user's buckets, with associated functinos.
 */
class RGWUserBuckets
{
  map<string, RGWBucketEnt> buckets;

public:
  RGWUserBuckets() {}
  void encode(bufferlist& bl) const {
    ::encode(buckets, bl);
  }
  void decode(bufferlist::iterator& bl) {
    ::decode(buckets, bl);
  }
  /**
   * Check if the user owns a bucket by the given name.
   */
  bool owns(string& name) {
    map<string, RGWBucketEnt>::iterator iter;
    iter = buckets.find(name);
    return (iter != buckets.end());
  }

  /**
   * Add a (created) bucket to the user's bucket list.
   */
  void add(RGWBucketEnt& bucket) {
    buckets[bucket.bucket.name] = bucket;
  }

  /**
   * Remove a bucket from the user's list by name.
   */
  void remove(string& name) {
    map<string, RGWBucketEnt>::iterator iter;
    iter = buckets.find(name);
    if (iter != buckets.end()) {
      buckets.erase(iter);
    }
  }

  /**
   * Get the user's buckets as a map.
   */
  map<string, RGWBucketEnt>& get_buckets() { return buckets; }

  /**
   * Cleanup data structure
   */
  void clear() { buckets.clear(); }

  size_t count() { return buckets.size(); }
};
WRITE_CLASS_ENCODER(RGWUserBuckets)

/**
 * Get all the buckets owned by a user and fill up an RGWUserBuckets with them.
 * Returns: 0 on success, -ERR# on failure.
 */
extern int rgw_read_user_buckets(RGWRados *store, string user_id, RGWUserBuckets& buckets, bool need_stats);

/**
 * Store the set of buckets associated with a user.
 * This completely overwrites any previously-stored list, so be careful!
 * Returns 0 on success, -ERR# otherwise.
 */
extern int rgw_write_buckets_attr(RGWRados *store, string user_id, RGWUserBuckets& buckets);

extern int rgw_add_bucket(RGWRados *store, string user_id, rgw_bucket& bucket);
extern int rgw_remove_user_bucket_info(RGWRados *store, string user_id, rgw_bucket& bucket);

/*
 * remove the different indexes
 */
extern int rgw_remove_key_index(RGWRados *store, RGWAccessKey& access_key);
extern int rgw_remove_uid_index(RGWRados *store, string& uid);
extern int rgw_remove_email_index(RGWRados *store, string& email);
extern int rgw_remove_swift_name_index(RGWRados *store, string& swift_name);

enum
{
  RGW_USER_ID_UID,
  RGW_USER_ID_EMAIL,
  RGW_USER_ID_SWIFT_NAME,
  RGW_USER_ID_ACCESS_KEY,
  RGW_ANONYMOUS_USER
};

enum ObjectKeyType {
  KEY_TYPE_SWIFT,
  KEY_TYPE_S3,
};

static bool char_is_unreserved_url(char c)
{
  if (isalnum(c))
    return true;

  switch (c) {
  case '-':
  case '.':
  case '_':
  case '~':
    return true;
  default:
    return false;
  }
}

static bool validate_access_key(string& key)
{
  const char *p = key.c_str();
  while (*p) {
    if (!char_is_unreserved_url(*p))
      return false;
    p++;
  }
  return true;
}

static int remove_object(RGWRados *store, rgw_bucket& bucket, std::string& object)
{
  int ret = -EINVAL;
  RGWRadosCtx *rctx = new RGWRadosCtx(store);
  rgw_obj obj(bucket,object);

  ret = store->delete_obj(rctx, obj);

  return ret;
}

static int remove_bucket(RGWRados *store, rgw_bucket& bucket, bool delete_children)
{
  int ret;
  map<RGWObjCategory, RGWBucketStats> stats;
  std::vector<RGWObjEnt> objs;
  std::string prefix, delim, marker, ns;
  map<string, bool> common_prefixes;
  rgw_obj obj;
  RGWBucketInfo info;
  bufferlist bl;

  ret = store->get_bucket_stats(bucket, stats);
  if (ret < 0)
    return ret;

  obj.bucket = bucket;
  int max = 1000;

  ret = rgw_get_obj(store, NULL, store->params.domain_root, bucket.name, bl, NULL);

  bufferlist::iterator iter = bl.begin();
  try {
    ::decode(info, iter);
  } catch (buffer::error& err) {
    //cerr << "ERROR: could not decode buffer info, caught buffer::error" << std::endl;
    return -EIO;
  }

  if (delete_children) {
    ret = store->list_objects(bucket, max, prefix, delim, marker, objs, common_prefixes,
                              false, ns, (bool *)false, NULL);
    if (ret < 0)
      return ret;

    while (objs.size() > 0) {
      std::vector<RGWObjEnt>::iterator it = objs.begin();
      for (it = objs.begin(); it != objs.end(); it++) {
        ret = remove_object(store, bucket, (*it).name);
        if (ret < 0)
          return ret;
      }
      objs.clear();

      ret = store->list_objects(bucket, max, prefix, delim, marker, objs, common_prefixes,
                                false, ns, (bool *)false, NULL);
      if (ret < 0)
        return ret;
    }
  }

  ret = store->delete_bucket(bucket);
  if (ret < 0) {
    //cerr << "ERROR: could not remove bucket " << bucket.name << std::endl;

    return ret;
  }

  ret = rgw_remove_user_bucket_info(store, info.owner, bucket);
  if (ret < 0) {
    //cerr << "ERROR: unable to remove user bucket information" << std::endl;
  }

  return ret;
}


/* new functionality */
class RGWUser;

class RGWAccessKeyPool 
{
  std::map<std::string, int, ltstr_nocase> key_type_map;
  std::string user_id;
  RGWRados *store;
  RGWUser *user;

  // we don't want to allow keys for the anonymous user or a null user
  bool keys_allowed;

private:
  bool get_key_type(std::string requested_type, int &dest);

  bool create_key(map<string, string> key_attrs);
  bool generate_key(map<string, string> key_attrs);
  bool modify_key(map<string, string> key_attrs);

public:

  RGWAccessKeyPool(RGWUser *user);

  bool add(map<string, string> key_attrs, bool defer_save);
  bool remove(map<string, string> key_attrs, bool defer_save);
};

class RGWSubUserPool
{
  string user_id;
  RGWRados *store;
  RGWUser *user;
  bool subusers_allowed;

  map<string, RGWSubUser> *subuser_map;

public:

  RGWSubUserPool(RGWUser *rgw_user);

  bool add(map<string, string> params, bool defer_save);
  bool remove(map<string, string> params, bool defer_save);
  bool modify(map<string, string> params, bool defer_save);
};

//class RGWUserCaps
//{
//  map<string, uint32_t> caps;
//
//  int get_cap(const string& cap, string& type, uint32_t *perm);
//  int parse_cap_perm(const string& str, uint32_t *perm);
//  int add_cap(const string& cap);
//  int remove_cap(const string& cap);
//public:
//  int add_from_string(const string& str);
//  int remove_from_string(const string& str);
//
//  void encode(bufferlist& bl) const {
//     ENCODE_START(1, 1, bl);
//     ::encode(caps, bl);
//     ENCODE_FINISH(bl);
//  }
//  void decode(bufferlist::iterator& bl) {
//     DECODE_START(1, bl);
//     ::decode(caps, bl);
//     DECODE_FINISH(bl);
//  }
//  int check_cap(const string& cap, uint32_t perm);
//  void dump(Formatter *f) const;
//};
//WRITE_CLASS_ENCODER(RGWUserCaps);


class RGWUserCapPool
{

  RGWUser *user;
  RGWUserCaps *caps;
  bool caps_allowed;
  
private:
public:

  RGWUserCapPool(RGWUser *user);
  ~RGWUserCapPool();

  bool add(const string& str);
  bool remove(const string& str);
};



class RGWUser
{

private:
  RGWUserInfo user_info;
  RGWRados *store;

  map<string, RGWAccessKey> *access_keys;
  map<string, RGWAccessKey> *swift_keys;

  string user_id;
  bool failure;

  void set_failure() { failure = true; };

public:
  RGWUser(RGWRados *_store, pair<string, string> user);
  RGWUser(RGWRados *_store );
  RGWUser();
  
  /* API Contracted Members */
  RGWUserCapPool *caps;
  RGWAccessKeyPool *keys;
  RGWSubUserPool *subusers;

  /* API Contracted Methods */
  bool add(map<string,string> attrs);
  bool remove(map<string, string> params);
  bool modify(map<string,string> attrs);
  bool info (map<string, string> identification, RGWUserInfo &fetched_info);

  friend class RGWAccessKeyPool;
  friend class RGWSubUserPool;
  friend class RGWUserCapPool;
};












#endif
