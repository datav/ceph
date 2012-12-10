#include <errno.h>

#include <string>
#include <map>

#include "common/errno.h"
#include "rgw_rados.h"
#include "rgw_acl.h"

#include "include/types.h"
#include "rgw_user.h"
#include "rgw_string.h"

// until everything is moved from rgw_common
#include "rgw_common.h"

#define dout_subsys ceph_subsys_rgw

using namespace std;


/**
 * Get the anonymous (ie, unauthenticated) user info.
 */
void rgw_get_anon_user(RGWUserInfo& info)
{
  info.user_id = RGW_USER_ANON_ID;
  info.display_name.clear();
  info.access_keys.clear();
}

bool rgw_user_is_authenticated(RGWUserInfo& info)
{
  return (info.user_id != RGW_USER_ANON_ID);
}

/**
 * Save the given user information to storage.
 * Returns: 0 on success, -ERR# on failure.
 */
int rgw_store_user_info(RGWRados *store, RGWUserInfo& info, bool exclusive)
{
  bufferlist bl;
  info.encode(bl);
  string md5;
  int ret;
  map<string,bufferlist> attrs;

  map<string, RGWAccessKey>::iterator iter;
  for (iter = info.swift_keys.begin(); iter != info.swift_keys.end(); ++iter) {
    RGWAccessKey& k = iter->second;
    /* check if swift mapping exists */
    RGWUserInfo inf;
    int r = rgw_get_user_info_by_swift(store, k.id, inf);
    if (r >= 0 && inf.user_id.compare(info.user_id) != 0) {
      ldout(store->ctx(), 0) << "WARNING: can't store user info, swift id already mapped to another user" << dendl;
      return -EEXIST;
    }
  }

  if (info.access_keys.size()) {
    /* check if access keys already exist */
    RGWUserInfo inf;
    map<string, RGWAccessKey>::iterator iter = info.access_keys.begin();
    for (; iter != info.access_keys.end(); ++iter) {
      RGWAccessKey& k = iter->second;
      int r = rgw_get_user_info_by_access_key(store, k.id, inf);
      if (r >= 0 && inf.user_id.compare(info.user_id) != 0) {
        ldout(store->ctx(), 0) << "WARNING: can't store user info, access key already mapped to another user" << dendl;
        return -EEXIST;
      }
    }
  }

  bufferlist uid_bl;
  RGWUID ui;
  ui.user_id = info.user_id;
  ::encode(ui, uid_bl);
  ::encode(info, uid_bl);

  ret = rgw_put_system_obj(store, store->params.user_uid_pool, info.user_id, uid_bl.c_str(), uid_bl.length(), exclusive);
  if (ret < 0)
    return ret;

  if (info.user_email.size()) {
    ret = rgw_put_system_obj(store, store->params.user_email_pool, info.user_email, uid_bl.c_str(), uid_bl.length(), exclusive);
    if (ret < 0)
      return ret;
  }

  if (info.access_keys.size()) {
    map<string, RGWAccessKey>::iterator iter = info.access_keys.begin();
    for (; iter != info.access_keys.end(); ++iter) {
      RGWAccessKey& k = iter->second;
      ret = rgw_put_system_obj(store, store->params.user_keys_pool, k.id, uid_bl.c_str(), uid_bl.length(), exclusive);
      if (ret < 0)
        return ret;
    }
  }

  map<string, RGWAccessKey>::iterator siter;
  for (siter = info.swift_keys.begin(); siter != info.swift_keys.end(); ++siter) {
    RGWAccessKey& k = siter->second;
    ret = rgw_put_system_obj(store, store->params.user_swift_pool, k.id, uid_bl.c_str(), uid_bl.length(), exclusive);
    if (ret < 0)
      return ret;
  }

  return ret;
}

int rgw_get_user_info_from_index(RGWRados *store, string& key, rgw_bucket& bucket, RGWUserInfo& info)
{
  bufferlist bl;
  RGWUID uid;

  int ret = rgw_get_obj(store, NULL, bucket, key, bl);
  if (ret < 0)
    return ret;

  bufferlist::iterator iter = bl.begin();
  try {
    ::decode(uid, iter);
    if (!iter.end())
      info.decode(iter);
  } catch (buffer::error& err) {
    ldout(store->ctx(), 0) << "ERROR: failed to decode user info, caught buffer::error" << dendl;
    return -EIO;
  }

  return 0;
}

/**
 * Given an email, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
int rgw_get_user_info_by_uid(RGWRados *store, string& uid, RGWUserInfo& info)
{
  return rgw_get_user_info_from_index(store, uid, store->params.user_uid_pool, info);
}

/**
 * Given an email, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
int rgw_get_user_info_by_email(RGWRados *store, string& email, RGWUserInfo& info)
{
  return rgw_get_user_info_from_index(store, email, store->params.user_email_pool, info);
}

/**
 * Given an swift username, finds the user_info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_swift(RGWRados *store, string& swift_name, RGWUserInfo& info)
{
  return rgw_get_user_info_from_index(store, swift_name, store->params.user_swift_pool, info);
}

/**
 * Given an access key, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_access_key(RGWRados *store, string& access_key, RGWUserInfo& info)
{
  return rgw_get_user_info_from_index(store, access_key, store->params.user_keys_pool, info);
}

static void get_buckets_obj(string& user_id, string& buckets_obj_id)
{
  buckets_obj_id = user_id;
  buckets_obj_id += RGW_BUCKETS_OBJ_PREFIX;
}

static int rgw_read_buckets_from_attr(RGWRados *store, string& user_id, RGWUserBuckets& buckets)
{
  bufferlist bl;
  rgw_obj obj(store->params.user_uid_pool, user_id);
  int ret = store->get_attr(NULL, obj, RGW_ATTR_BUCKETS, bl);
  if (ret)
    return ret;

  bufferlist::iterator iter = bl.begin();
  try {
    buckets.decode(iter);
  } catch (buffer::error& err) {
    ldout(store->ctx(), 0) << "ERROR: failed to decode buckets info, caught buffer::error" << dendl;
    return -EIO;
  }
  return 0;
}

/**
 * Get all the buckets owned by a user and fill up an RGWUserBuckets with them.
 * Returns: 0 on success, -ERR# on failure.
 */
int rgw_read_user_buckets(RGWRados *store, string user_id, RGWUserBuckets& buckets, bool need_stats)
{
  int ret;
  buckets.clear();
  if (store->supports_omap()) {
    string buckets_obj_id;
    get_buckets_obj(user_id, buckets_obj_id);
    bufferlist bl;
    rgw_obj obj(store->params.user_uid_pool, buckets_obj_id);
    bufferlist header;
    map<string,bufferlist> m;

    ret = store->omap_get_all(obj, header, m);
    if (ret == -ENOENT)
      ret = 0;

    if (ret < 0)
      return ret;

    for (map<string,bufferlist>::iterator q = m.begin(); q != m.end(); q++) {
      bufferlist::iterator iter = q->second.begin();
      RGWBucketEnt bucket;
      ::decode(bucket, iter);
      buckets.add(bucket);
    }
  } else {
    ret = rgw_read_buckets_from_attr(store, user_id, buckets);
    switch (ret) {
    case 0:
      break;
    case -ENODATA:
      ret = 0;
      return 0;
    default:
      return ret;
    }
  }

  list<string> buckets_list;

  if (need_stats) {
    map<string, RGWBucketEnt>& m = buckets.get_buckets();
    int r = store->update_containers_stats(m);
    if (r < 0)
      ldout(store->ctx(), 0) << "ERROR: could not get stats for buckets" << dendl;

  }
  return 0;
}

/**
 * Store the set of buckets associated with a user on a n xattr
 * not used with all backends
 * This completely overwrites any previously-stored list, so be careful!
 * Returns 0 on success, -ERR# otherwise.
 */
int rgw_write_buckets_attr(RGWRados *store, string user_id, RGWUserBuckets& buckets)
{
  bufferlist bl;
  buckets.encode(bl);

  rgw_obj obj(store->params.user_uid_pool, user_id);

  int ret = store->set_attr(NULL, obj, RGW_ATTR_BUCKETS, bl);

  return ret;
}

int rgw_add_bucket(RGWRados *store, string user_id, rgw_bucket& bucket)
{
  int ret;
  string& bucket_name = bucket.name;

  if (store->supports_omap()) {
    bufferlist bl;

    RGWBucketEnt new_bucket;
    new_bucket.bucket = bucket;
    new_bucket.size = 0;
    time(&new_bucket.mtime);
    ::encode(new_bucket, bl);

    string buckets_obj_id;
    get_buckets_obj(user_id, buckets_obj_id);

    rgw_obj obj(store->params.user_uid_pool, buckets_obj_id);
    ret = store->omap_set(obj, bucket_name, bl);
    if (ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: error adding bucket to directory: "
          << cpp_strerror(-ret)<< dendl;
    }
  } else {
    RGWUserBuckets buckets;

    ret = rgw_read_user_buckets(store, user_id, buckets, false);
    RGWBucketEnt new_bucket;

    switch (ret) {
    case 0:
    case -ENOENT:
    case -ENODATA:
      new_bucket.bucket = bucket;
      new_bucket.size = 0;
      time(&new_bucket.mtime);
      buckets.add(new_bucket);
      ret = rgw_write_buckets_attr(store, user_id, buckets);
      break;
    default:
      ldout(store->ctx(), 10) << "rgw_write_buckets_attr returned " << ret << dendl;
      break;
    }
  }

  return ret;
}

int rgw_remove_user_bucket_info(RGWRados *store, string user_id, rgw_bucket& bucket)
{
  int ret;

  if (store->supports_omap()) {
    bufferlist bl;

    string buckets_obj_id;
    get_buckets_obj(user_id, buckets_obj_id);

    rgw_obj obj(store->params.user_uid_pool, buckets_obj_id);
    ret = store->omap_del(obj, bucket.name);
    if (ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: error removing bucket from directory: "
          << cpp_strerror(-ret)<< dendl;
    }
  } else {
    RGWUserBuckets buckets;

    ret = rgw_read_user_buckets(store, user_id, buckets, false);

    if (ret == 0 || ret == -ENOENT) {
      buckets.remove(bucket.name);
      ret = rgw_write_buckets_attr(store, user_id, buckets);
    }
  }

  return ret;
}

int rgw_remove_key_index(RGWRados *store, RGWAccessKey& access_key)
{
  rgw_obj obj(store->params.user_keys_pool, access_key.id);
  int ret = store->delete_obj(NULL, obj);
  return ret;
}

int rgw_remove_uid_index(RGWRados *store, string& uid)
{
  rgw_obj obj(store->params.user_uid_pool, uid);
  int ret = store->delete_obj(NULL, obj);
  return ret;
}

int rgw_remove_email_index(RGWRados *store, string& email)
{
  rgw_obj obj(store->params.user_email_pool, email);
  int ret = store->delete_obj(NULL, obj);
  return ret;
}

int rgw_remove_swift_name_index(RGWRados *store, string& swift_name)
{
  rgw_obj obj(store->params.user_swift_pool, swift_name);
  int ret = store->delete_obj(NULL, obj);
  return ret;
}

/**
 * delete a user's presence from the RGW system.
 * First remove their bucket ACLs, then delete them
 * from the user and user email pools. This leaves the pools
 * themselves alone, as well as any ACLs embedded in object xattrs.
 */
int rgw_delete_user(RGWRados *store, RGWUserInfo& info) {
  RGWUserBuckets user_buckets;
  int ret = rgw_read_user_buckets(store, info.user_id, user_buckets, false);
  if (ret < 0)
    return ret;

  map<string, RGWBucketEnt>& buckets = user_buckets.get_buckets();
  vector<rgw_bucket> buckets_vec;
  for (map<string, RGWBucketEnt>::iterator i = buckets.begin();
      i != buckets.end();
      ++i) {
    RGWBucketEnt& bucket = i->second;
    buckets_vec.push_back(bucket.bucket);
  }
  map<string, RGWAccessKey>::iterator kiter = info.access_keys.begin();
  for (; kiter != info.access_keys.end(); ++kiter) {
    ldout(store->ctx(), 10) << "removing key index: " << kiter->first << dendl;
    ret = rgw_remove_key_index(store, kiter->second);
    if (ret < 0 && ret != -ENOENT) {
      ldout(store->ctx(), 0) << "ERROR: could not remove " << kiter->first << " (access key object), should be fixed (err=" << ret << ")" << dendl;
      return ret;
    }
  }

  map<string, RGWAccessKey>::iterator siter = info.swift_keys.begin();
  for (; siter != info.swift_keys.end(); ++siter) {
    RGWAccessKey& k = siter->second;
    ldout(store->ctx(), 10) << "removing swift subuser index: " << k.id << dendl;
    /* check if swift mapping exists */
    ret = rgw_remove_swift_name_index(store, k.id);
    if (ret < 0 && ret != -ENOENT) {
      ldout(store->ctx(), 0) << "ERROR: could not remove " << k.id << " (swift name object), should be fixed (err=" << ret << ")" << dendl;
      return ret;
    }
  }

  rgw_obj email_obj(store->params.user_email_pool, info.user_email);
  ldout(store->ctx(), 10) << "removing email index: " << info.user_email << dendl;
  ret = store->delete_obj(NULL, email_obj);
  if (ret < 0 && ret != -ENOENT) {
    ldout(store->ctx(), 0) << "ERROR: could not remove " << info.user_id << ":" << email_obj << ", should be fixed (err=" << ret << ")" << dendl;
    return ret;
  }

  string buckets_obj_id;
  get_buckets_obj(info.user_id, buckets_obj_id);
  rgw_obj uid_bucks(store->params.user_uid_pool, buckets_obj_id);
  ldout(store->ctx(), 10) << "removing user buckets index" << dendl;
  ret = store->delete_obj(NULL, uid_bucks);
  if (ret < 0 && ret != -ENOENT) {
    ldout(store->ctx(), 0) << "ERROR: could not remove " << info.user_id << ":" << uid_bucks << ", should be fixed (err=" << ret << ")" << dendl;
    return ret;
  }
  
  rgw_obj uid_obj(store->params.user_uid_pool, info.user_id);
  ldout(store->ctx(), 10) << "removing user index: " << info.user_id << dendl;
  ret = store->delete_obj(NULL, uid_obj);
  if (ret < 0 && ret != -ENOENT) {
    ldout(store->ctx(), 0) << "ERROR: could not remove " << info.user_id << ":" << uid_obj << ", should be fixed (err=" << ret << ")" << dendl;
    return ret;
  }

  return 0;
}

/* new functionality */



RGWAccessKeyPool::RGWAccessKeyPool(RGWUser *user) {

  if (!user) {
    keys_allowed = false;
    return;
  }

  store = user->store;

  // if the user id hasn't been set the user id hasn't been initialized yet or is anonymous
  if (user->user_id == RGW_USER_ANON_ID) {
    keys_allowed = false;
    return;
  }

  user_id = user->user_id;
}

bool RGWAccessKeyPool::get_key_type(std::string requested_type, int &dest) {
  std::map<std::string, int, ltstr_nocase> key_type_map;

  key_type_map["swift"] = KEY_TYPE_SWIFT;
  key_type_map["s3"] = KEY_TYPE_S3;

  if (!key_type_map.count(requested_type))
    return false;

  dest = key_type_map[requested_type];

  return true;
}

// create a key from passed parameters
bool RGWAccessKeyPool::create_key(map<string, string> key_attrs) {

  string id;
  string key;
  string subuser;
  bool type_found = false;

  RGWAccessKey new_key;
  RGWUserInfo duplicate_check;

  int key_type = KEY_TYPE_S3; // default to S3

  if (!keys_allowed)
    return false;

  if (!key_attrs.count("id"))
    return false;

  id = key_attrs["id"];

  if (!key_attrs.count("key"))
    return false;

  key = key_attrs["key"];

  if (key_attrs.count("subuser"))
    subuser = key_attrs["subuser"];

  if (key_attrs.count("key_type"))
    type_found = get_key_type(key_attrs["key_type"], key_type);

  if (key_attrs.count("key_type") && !type_found)
    return false;
  

  // check that the access key is valid
  if (key_type == KEY_TYPE_S3 && !validate_access_key(id))
    return false;

  // force subusers to have swift keys
  if (!subuser.empty()) {
    key_type = KEY_TYPE_SWIFT;
    new_key.subuser = subuser;
  }

  // check for invalid characters in an S3 key
  if (key_type == KEY_TYPE_S3 && !validate_access_key(key))
    return false;

  // validate a SWIFT access key
  if (key_type == KEY_TYPE_SWIFT) {
    string swift_access = user_id;
    swift_access.append(":");
    swift_access.append(subuser);

    // check that we're adding the swift key to the right user
    if (strcmp(swift_access.c_str(), id.c_str()) != 0)
      return false;
  }

  // check that the key isn't a duplicate
  if (key_type == KEY_TYPE_S3) {
    if (rgw_get_user_info_by_access_key(store, id, duplicate_check))
      return false;
  } else if (key_type == KEY_TYPE_SWIFT) {
    if (rgw_get_user_info_by_swift(store, id, duplicate_check))
      return false;
  }

  new_key.id = id;
  new_key.key = key;

  if (key_type == KEY_TYPE_S3)
    user->user_info.access_keys[id] = new_key;
  else if (key_type == KEY_TYPE_SWIFT)
    user->user_info.swift_keys[id] = new_key;

  return true;
}

// Generate a new random key
bool RGWAccessKeyPool::generate_key(map<string, string> key_attrs) {

  string id;
  string key;
  string subuser;
  string duplicate_check_id;
  bool access_supplied;
  bool secret_supplied;
  bool type_found = false;

  RGWAccessKey new_key;
  RGWUserInfo duplicate_check;

  int ret = -1;
  int key_type = KEY_TYPE_S3; // default to S3

  if (!keys_allowed)
    return false;

  if (key_attrs.count("key_type"))
    type_found = get_key_type(key_attrs["key_type"], key_type);

  if (key_attrs.count("key_type") && !type_found)
    return false;
  
  if (key_attrs.count("subuser"))
    subuser = key_attrs["subuser"];

  if (key_attrs.count("id"))
    id = key_attrs["id"];  

  if (!id.empty())
    access_supplied = true;

  if (key_attrs.count("key"))
    key = key_attrs["key"];

  if (!key.empty())
    secret_supplied = true;

  // this isn't a modify key operation, return error if the key exists
  if (access_supplied && key_type == KEY_TYPE_S3)
    ret = rgw_get_user_info_by_access_key(store, id, duplicate_check);

  if (access_supplied && key_type == KEY_TYPE_SWIFT)
    ret = rgw_get_user_info_by_swift(store, id, duplicate_check);

  // ret should be < 0 if not set in the previous two commands
  if (ret >= 0)
    return false;

  // check that the subuser exists
  if (!subuser.empty() && !user->user_info.subusers.count(subuser))
    return false;

  // force subusers to have swift keys
  if (!subuser.empty()) {
    key_type = KEY_TYPE_SWIFT;
    new_key.subuser = subuser;
  }

  // Generate the secret key
  if (!secret_supplied) {
    char secret_key_buf[SECRET_KEY_LEN + 1];

    ret = gen_rand_base64(g_ceph_context, secret_key_buf, sizeof(secret_key_buf));
    if (ret < 0)
      return false;

    key = secret_key_buf;
  }

  // Generate the access key
  if (key_type == KEY_TYPE_S3 && !access_supplied) {
    char public_id_buf[PUBLIC_ID_LEN + 1];

    do {
      ret = gen_rand_alphanumeric_upper(g_ceph_context, public_id_buf, sizeof(public_id_buf));
      if (ret < 0)
        return false;

      id = public_id_buf;
      duplicate_check_id = id;
    } while (!rgw_get_user_info_by_access_key(store, duplicate_check_id, duplicate_check));
  }

  if (key_type == KEY_TYPE_SWIFT && !access_supplied) {
    id = user_id;
    id.append(":");
    id.append(subuser);

    // check that the access key doesn't exist
    if (rgw_get_user_info_by_swift(store, id, duplicate_check))
      return false;
  }

  // check that the access key is valid
  if (key_type == KEY_TYPE_S3 && !validate_access_key(id))
    return false;

  // finally create the new key
  new_key.id = id;
  new_key.key = key;

  if (key_type == KEY_TYPE_S3)
    user->user_info.access_keys[id] = new_key;
  else if (key_type == KEY_TYPE_SWIFT)
    user->user_info.swift_keys[id] = new_key;

  return true;
}

// modify an existing key
bool RGWAccessKeyPool::modify_key(map<string, string> key_attrs) {
  string id;
  string key;
  int key_type;
 // bool found;
  bool secret_supplied;
  bool type_found = false;
  RGWAccessKey modify_key;

  map<string, RGWAccessKey>::iterator kiter;

  if (key_attrs.count("key_type"))
    type_found = get_key_type(key_attrs["key_type"], key_type);

  if (key_attrs.count("key_type") && !type_found)
    return false;

  if (key_attrs["id"].empty())
    return false;

  id = key_attrs["id"];

  if (key_type == KEY_TYPE_SWIFT) 
    modify_key = user->user_info.swift_keys[id];
  
  if (key_type == KEY_TYPE_S3) 
    modify_key = user->user_info.access_keys[id];
  
  if (!key_attrs.count("key"))
    secret_supplied = false;

  if (!secret_supplied) {
    char secret_key_buf[SECRET_KEY_LEN + 1];

    int ret = gen_rand_base64(g_ceph_context, secret_key_buf, sizeof(secret_key_buf));
    if (ret < 0)
      return false;

    key = secret_key_buf;
  } else {
    key = key_attrs["key"];
    if (key.empty())
      return false;
  }

  // update the access key with the new secret key
  modify_key.key = key;

  return true;
}

// select whether to create a key from passed parameters or to generate a new key
bool RGWAccessKeyPool::add(map<string, string> key_attrs, bool defer_save) {
  map<string, string> passed_key_attrs;
  int op;
  int ret = 0;
  int found_key_type;
  bool key_type_specified;
  bool exisitng_key = false;
  bool created;
  string access_key;
  string secret_key;

  enum {
    CREATE_KEY,
    GENERATE_KEY,
    MODIFY_KEY
  };

  // see if a key type was specified
  if (key_attrs.count("key_type")) {
    if (!get_key_type(key_attrs["key_type"], found_key_type))
      return false;

    key_type_specified = true;
  }
  

  // try and find the key first
  if (key_attrs.count("access_key")) {

    access_key = key_attrs["access_key"];

    // if the key type was specified, great...
    if (found_key_type == KEY_TYPE_SWIFT) {
      exisitng_key = user->user_info.swift_keys.count(access_key);
    }

    if (found_key_type == KEY_TYPE_S3) {
      exisitng_key = user->user_info.access_keys.count(access_key);
    }

    /*
     * ... if not since there is nothing preventing an S3 key from having a colon
     * we have to traverse both access key maps
     */

    // try the swift keys first
    if (!key_type_specified && !exisitng_key) {
      exisitng_key = user->user_info.swift_keys.count(access_key);

      if (exisitng_key)
        found_key_type = KEY_TYPE_SWIFT;
    }

    if (!key_type_specified && !exisitng_key) {
      exisitng_key = user->user_info.access_keys.count(access_key);

      if (exisitng_key)
        found_key_type = KEY_TYPE_S3;
    }
    
  }
  
  if (exisitng_key)
    op = MODIFY_KEY;

  if (!exisitng_key && key_attrs.count("access_key") && key_attrs.count("secret_key"))
    op = CREATE_KEY;

  if (key_attrs.count("gen_secret") && key_attrs.count("gen_access"))
    op = GENERATE_KEY;

  if (!exisitng_key && !key_attrs.count("access_key") && !key_attrs.count("secret_key"))
    op = GENERATE_KEY;
  

  // build the list of attributes to pass
  
  if (key_attrs.count("access_key"))
    passed_key_attrs["id"] = key_attrs["access_key"];

  if (key_attrs.count("secret_key"))
    passed_key_attrs["key"] = key_attrs["secret"];

  if (key_attrs.count("gen_secret"))
    passed_key_attrs["gen_secret"] = key_attrs["gen_secret"];

  if (key_attrs.count("subuser"))
    passed_key_attrs["subuser"] = key_attrs["subuser"];

  if (key_type_specified)
    passed_key_attrs["key_type"] = found_key_type;

  // get the results of the key op
  switch (op) {
  case GENERATE_KEY:
    created = generate_key(passed_key_attrs);
    break;
  case CREATE_KEY:
    created = create_key(passed_key_attrs);
    break;
  case MODIFY_KEY:
    created = modify_key(passed_key_attrs);
    break;
  }

  if (!created)
    return false;

  // store the updated info
  if (!defer_save) 
    ret = rgw_store_user_info(store, user->user_info, false);

    if (ret < 0)
      return false;


  return true;
}

bool RGWAccessKeyPool::remove(map<string, string> key_attrs, bool defer_save) {

  int key_type = KEY_TYPE_S3; // default to S3
  bool key_type_specified;
  map<string, RGWAccessKey> *keys_map;
  map<string, RGWAccessKey>::iterator kiter;
  string subuser;
  string access_key;

  if (!keys_allowed)
    return false;

  if (key_attrs.count("access_key"))
    access_key = key_attrs["access_key"];

  if (access_key.empty() && !key_attrs.count("subuser"))
    return false;

  if (key_attrs.count("subuser"))
    subuser = key_attrs["subuser"];

  if (key_attrs.count("key_type")) {
    if (!get_key_type(key_attrs["key_type"], key_type))
      return false;

    key_type_specified = true;
  }

  // one day it will be safe to assume that subusers always have swift keys
  //if (!subuser.empty())
  //  key_type = KEY_TYPE_SWIFT


  if (key_type_specified && key_type == KEY_TYPE_SWIFT) {
    if (subuser.empty())
      return false;
    
    if (access_key.empty()) {
      access_key = user->user_id;
      access_key.append(":");
      access_key.append(subuser);
    }
    
    keys_map = user->swift_keys;
    
    kiter = keys_map->find(access_key);
    if (kiter == keys_map->end())
      return false;
  } 

  if (key_type_specified && key_type == KEY_TYPE_S3)  {
    keys_map = user->access_keys;
    
    kiter = keys_map->find(access_key);
    if (kiter == keys_map->end())
      return false;
  }

  if (!key_type_specified) {
    bool found = false;
    

    if (!found) {
      keys_map = user->swift_keys;
      kiter = keys_map->find(access_key);

      if (kiter != keys_map->end())
        found = true;
    }

    if (!found) {
      keys_map = user->access_keys;
      kiter = keys_map->find(access_key);

      if (kiter != keys_map->end())
        found = true;
    }
    
    if (!found)
      return false;
  }

  rgw_remove_key_index(store, kiter->second);
  keys_map->erase(kiter);
  if ((rgw_store_user_info(store, user->user_info, false)) < 0) {
    return false;  
  }


  return true;
}


RGWSubUserPool::RGWSubUserPool(RGWUser *user) {

  if (!user) {
      subusers_allowed = false;
      return;
    }

    store = user->store;

    // if the user id hasn't been set the user id hasn't been initialized yet or is anonymous
    if (user->user_id == RGW_USER_ANON_ID) {
      subusers_allowed = false;
      return;
    }

    user_id = user->user_id;

  subuser_map = &(user->user_info.subusers);
}

bool RGWSubUserPool::add(map<string, string> params, bool defer_update) {
  string name;
  string perm_mask_str;
  map<string, string> key_attr;
  bool defer_save = true;
  int ret = 0;
  uint32_t perm_mask = 0;

  RGWSubUser subuser;

  if (!params.count("subuser"))
      return false;

  name = params["subuser"];
  if (name.empty())
    return false;

  // no duplicates
  if (user->user_info.subusers.count("subuser"))
    return false;

  // generate keys if need be
  if (params.count("gen_secret")) {
    key_attr["subuser"] = name;
    key_attr["key_type"] = "swift";
  }

  if (!user->keys->add(key_attr, defer_save))
    return false;

  // create the subuser
  subuser.name = name;

  if (params.count("access")) {
    if (stringtoul(params["access"].c_str(), &perm_mask) < 0)
      return false;

    subuser.perm_mask = perm_mask;
  }

  // insert the subuser into user info
  user->user_info.subusers[name] = subuser;

  // attempt to save the subuser
  if (!defer_update) 
    ret = rgw_store_user_info(store, user->user_info, false);

  if (ret < 0)
    return false;

  return true;
}

bool RGWSubUserPool::remove(map<string, string> params, bool defer_update) {

  bool purge_keys = false;
  string name;
  int ret = 0;

  map<string, string> key_attrs;
  map<string, RGWSubUser> subuser_map;
  map<string, RGWSubUser>::iterator siter;


  if (!params.count("subuser"))
    return false;

  name = params["subuser"];
  if (name.empty())
    return false;


  siter = subuser_map.find(name); 
  if (siter == subuser_map.end())
    return false;

  if (params.count("purge_keys"))
    purge_keys = str_to_bool(params["purge_keys"].c_str(), 0);
    
    if (purge_keys) {
      string access_key = user->user_id;
      access_key.append(":");
      access_key.append(name);

      key_attrs["access_key"] = access_key;
      key_attrs["key_type"] = "swift";

      bool success = user->keys->remove(key_attrs,false);
      if (!success)
        return false;
    }
  
  //remove the subuser from the user info
  subuser_map.erase(siter);

  // attempt to save the subuser
  if (!defer_update) 
    ret = rgw_store_user_info(store, user->user_info, false);

  if (ret < 0)
    return false;

  return true;
}

bool RGWSubUserPool::modify(map<string, string> params, bool defer_save) {
  string name;
  string perm_mask_str;
  map<string, string> key_attr;
  map<string, RGWSubUser> subuser_map;
  uint32_t perm_mask = 0;
  int ret;

  RGWSubUser *subuser;

  if (!params.count("subuser"))
    return false;

  name = params["subuser"];
  if (name.empty())
    return false;

  subuser_map =  user->user_info.subusers;

  if (!subuser_map.count("name"))
    return false;

  subuser = &subuser_map[name];

  if (params.count("gen_secret") || params.count("secret_key")) {
    string access_key = user->user_id;
    access_key.append(":");
    access_key.append(name);
    
    key_attr["access_key"] = access_key;
  }

  if (params.count("gen_secret"))
    key_attr["gen_secret"] = params["gen_secret"];

  if (params.count("secret_key"))
    key_attr["secret_key"] = params["secret_key"];
  
  // one day it will be safe to assume that subusers only have swift keys
  //key_attr["key_type"] = swift;
  
  bool success = user->keys->add(key_attr, true);
  if (!success)
    return false;

  if (params.count("access")) {
    if (stringtoul(params["access"], &perm_mask) < 0)
      return false;

    subuser->perm_mask = perm_mask;
  }

  // attempt to save the subuser
  if (!defer_save)
    ret = rgw_store_user_info(store, user->user_info, false);

  if (ret < 0)
    return false;

  return true;
}


RGWUserCapPool::RGWUserCapPool(RGWUser *user) {

  if (!user) {
      caps_allowed = false;
      return;
    }

    // if the user id hasn't been set the user id hasn't been initialized yet or is anonymous
    if (user->user_id == RGW_USER_ANON_ID) {
      caps_allowed = false;
      return;
    }

  caps = &(user->user_info.caps);

}

bool RGWUserCapPool::add(const string& cap)
{

  // eventually replace add_from_string with this function
  int r = caps->add_from_string(cap);
  if (r < 0)
    return false;


  return true;
}

bool RGWUserCapPool::remove(const string& cap)
{

  // eventually replace remove_from_string with this function
  int r = caps->remove_from_string(cap);
  if (r < 0)
    return false;

  return true;
}












RGWUser::RGWUser(RGWRados *_store, pair<string, string> user) {
  if (!_store)
    return;

  store = _store;
  //int ret;

//  switch (id_type) {
//  case RGW_USER_ID_UID:
//    if (!id_value.empty())
//      ret = rgw_get_user_info_by_uid(store, id_value, user_info);
//    break;
//  case RGW_USER_ID_EMAIL:
//    if (!id_value.empty())
//      ret = rgw_get_user_info_by_email(store, id_value, user_info);
//    break;
//  case RGW_USER_ID_SWIFT_NAME:
//    if (!id_value.empty())
//      ret = rgw_get_user_info_by_swift(store, id_value, user_info);
//    break;
//  case RGW_USER_ID_ACCESS_KEY:
//    if (!id_value.empty())
//      ret = rgw_get_user_info_by_access_key(store, id_value, user_info);
//    break;
//  case RGW_ANONYMOUS_USER:
//    rgw_get_anon_user(user_info);
//    break;
//  }


  access_keys = &(user_info.swift_keys);
  swift_keys = &(user_info.swift_keys);

  /* API wrappers */
  keys = new RGWAccessKeyPool(this);
  caps = new RGWUserCapPool(this);
  subusers = new RGWSubUserPool(this);

}


RGWUser::RGWUser(RGWRados *_store ) {
  if (!_store) {
    set_failure();
    return;
  }

  store = _store;
  return;
}

RGWUser::RGWUser() {
  rgw_get_anon_user(user_info);

  return;
}

bool RGWUser::add(map<string,string> attrs) {
  bool keys_provided = false;

  // need function to create default keys in map
  map<string, string> temp_attrs;

  if (!attrs.count("user_id"))
    return false;

  temp_attrs["user_id"] = attrs["user_id"];

  if (!attrs.count("display_name"))
    return false;

  temp_attrs["display_name"] = attrs["display_name"];

  if (attrs.count("user_email"))
    temp_attrs["user_email"] = attrs["user_email"];

  if (attrs.count("access_key") && attrs.count("secret_key")) {
    keys_provided = true;
    temp_attrs["access_key"] = attrs["access_key"];
    temp_attrs["secret_key"] = attrs["secret_key"];
  }



  //int ret = rgw_store_user_info(store, user_info, bool exclusive);

  return true;
}


bool RGWUser::remove(map<string, string> params) {
  RGWUserBuckets buckets;

  string uid;
  string purge_data_str;
  int ret;
  bool purge_data = false;

  if (params.count("user_id"))
    uid = params["user_id"];

  if (uid.empty())
    uid = user_id;

  if (params.count("purge_data"))
    purge_data_str = params["purge_data"];

  if (strcasecmp(purge_data_str.c_str(), "true"))
    purge_data = true;



  if (rgw_read_user_buckets(store, user_id, buckets, false) >= 0) {
    map<string, RGWBucketEnt>& m = buckets.get_buckets();

    if (m.size() > 0 && purge_data) {
      for (std::map<string, RGWBucketEnt>::iterator it = m.begin(); it != m.end(); it++) {
        ret = remove_bucket(store, ((*it).second).bucket, true);

        if (ret < 0)
          return false;
      }
    }

    if (m.size() > 0 && !purge_data) {
      //cerr << "ERROR: specify --purge-data to remove a user with a non-empty bucket list" << std::endl;
      return false;
    }
  }
  rgw_delete_user(store, user_info);

  return true;
}

bool RGWUser::modify(map<string,string> attrs) {
  map<string, string> subuser_attrs;
  map<string, string> key_attrs;
  string cap;


  // ensure that the user info has been populated or is populate-able
  if (!attrs.count("user_id") && user_id == RGW_USER_ANON_ID)
    return false;

  // if the user_id was passed in, try and populate the internal user info from it
  if (attrs.count("user_id") && user_id == RGW_USER_ANON_ID)
    user_id = attrs["user_id"];

  // if the user info hasn't already been populated...attempt to
  int ret = rgw_get_user_info_by_uid(store, user_id, user_info);

  if (user_id == RGW_USER_ANON_ID && ret < 0)
    return false;

  // make sure we are not adding a duplicate email
  RGWUserInfo duplicate_check;
  if (attrs.count("email")) {
    if (rgw_get_user_info_by_email(store, attrs["email"], duplicate_check) >= 0)
      return false;

    user_info.user_email = attrs["email"];
  }

  // update the remaining user info
  if (attrs.count("display_name"))
    user_info.display_name = attrs["display_name"];

  if (attrs.count("max_buckets"))
    stringtoul(attrs["max_buckets"], &user_info.max_buckets);


  if (attrs.count("suspended")) {
    __u8 is_suspended;

    is_suspended = rgw_str_to_bool(attrs["suspended"].c_str(), 0);
    user_info.suspended = is_suspended;
  }


  // modify subusers

  // modify caps

  // modify keys

  return true;

}

bool RGWUser::info(map<string, string> id, RGWUserInfo &fetched_info) {

  if (id.count("user_id")) {
    if (rgw_get_user_info_by_uid(store, id["user_id"], fetched_info) >= 0)
      return true;
  }

  if (id.count("email")) {
    if (rgw_get_user_info_by_email(store, id["email"], fetched_info) >= 0)
      return true;
  }

  if (id.count("access_key")) {
    if (rgw_get_user_info_by_access_key(store, id["email"], fetched_info) >= 0)
      return true;
  }

  return false;
}



