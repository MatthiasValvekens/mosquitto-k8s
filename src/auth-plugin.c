#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>


# define mosquitto_auth_opt mosquitto_opt

#include "go-k8s-auth.h"

#define AuthRejected 0
#define AuthGranted 1

int mosquitto_auth_plugin_version(void) {
  return 4;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  /*
    Pass auth_opts hash as keys and values char* arrays to Go in order to initialize them there.
  */

  GoInt32 opts_count = auth_opt_count;
  
  char *keys[auth_opt_count];
  char *values[auth_opt_count];
  int i;
  struct mosquitto_auth_opt *o;
  for (i = 0, o = auth_opts; i < auth_opt_count; i++, o++) {
    keys[i] = o->key;
    values[i] = o->value;
  }

  GoSlice keysSlice = {keys, auth_opt_count, auth_opt_count};
  GoSlice valuesSlice = {values, auth_opt_count, auth_opt_count};

  char versionArray[10];
  sprintf(versionArray, "%i.%i.%i", LIBMOSQUITTO_MAJOR, LIBMOSQUITTO_MINOR, LIBMOSQUITTO_REVISION);


  AuthPluginInit(keysSlice, valuesSlice, opts_count, versionArray);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count) {
  AuthPluginCleanup();
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload) {
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password)
{
  const char* clientid = mosquitto_client_id(client);
  if (username == NULL || password == NULL) {
    printf("error: received null username or password for unpwd check\n");
    fflush(stdout);
    return MOSQ_ERR_AUTH;
  }

  GoUint8 ret = AuthUnpwdCheck((char *)username, (char *)password, (char *)clientid);

  switch (ret)
  {
  case AuthGranted:
    return MOSQ_ERR_SUCCESS;
    break;
  case AuthRejected:
    return MOSQ_ERR_AUTH;
    break;
  default:
    fprintf(stderr, "unknown plugin error: %d\n", ret);
    return MOSQ_ERR_UNKNOWN;
  }
}

int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
  const char* clientid = mosquitto_client_id(client);
  const char* username = mosquitto_client_username(client);
  const char* topic = msg->topic;
  if (clientid == NULL || username == NULL || topic == NULL || access < 1) {
    printf("error: received null username, clientid or topic, or access is equal or less than 0 for acl check\n");
    fflush(stdout);
    return MOSQ_ERR_ACL_DENIED;
  }

  GoUint8 ret = AuthAclCheck((char *)clientid, (char *)username, (char *)topic, access);

  switch (ret)
  {
  case AuthGranted:
    return MOSQ_ERR_SUCCESS;
    break;
  case AuthRejected:
    return MOSQ_ERR_ACL_DENIED;
    break;
  default:
    fprintf(stderr, "unknown plugin error: %d\n", ret);
    return MOSQ_ERR_UNKNOWN;
  }
}

int mosquitto_auth_psk_key_get(void *user_data, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
{
  return MOSQ_ERR_AUTH;
}
