/*
   MOD AUTH GSSAPI

   Copyright (C) 2014 Simo Sorce <simo@redhat.com>

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

#include "mod_auth_gssapi.h"

#define MOD_AUTH_GSSAPI_VERSION PACKAGE_NAME "/" PACKAGE_VERSION

module AP_MODULE_DECLARE_DATA auth_gssapi_module;

APLOG_USE_MODULE(auth_gssapi);

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

static const char ntlm_oid[] = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";
gss_OID_desc ntlm_mech_oid = { 10, &ntlm_oid };

static char *mag_status(request_rec *req, int type, uint32_t err)
{
    uint32_t maj_ret, min_ret;
    gss_buffer_desc text;
    uint32_t msg_ctx;
    char *msg_ret;
    int len;

    msg_ret = NULL;
    msg_ctx = 0;
    do {
        maj_ret = gss_display_status(&min_ret, err, type,
                                     GSS_C_NO_OID, &msg_ctx, &text);
        if (maj_ret != GSS_S_COMPLETE) {
            return msg_ret;
        }

        len = text.length;
        if (msg_ret) {
            msg_ret = apr_psprintf(req->pool, "%s, %*s",
                                   msg_ret, len, (char *)text.value);
        } else {
            msg_ret = apr_psprintf(req->pool, "%*s", len, (char *)text.value);
        }
        gss_release_buffer(&min_ret, &text);
    } while (msg_ctx != 0);

    return msg_ret;
}

static char *mag_error(request_rec *req, const char *msg,
                       uint32_t maj, uint32_t min)
{
    char *msg_maj;
    char *msg_min;

    msg_maj = mag_status(req, GSS_C_GSS_CODE, maj);
    msg_min = mag_status(req, GSS_C_MECH_CODE, min);
    return apr_psprintf(req->pool, "%s: [%s (%s)]", msg, msg_maj, msg_min);
}

static APR_OPTIONAL_FN_TYPE(ssl_is_https) *mag_is_https = NULL;

static int mag_post_config(apr_pool_t *cfgpool, apr_pool_t *log,
                           apr_pool_t *temp, server_rec *s)
{
    /* FIXME: create mutex to deal with connections and contexts ? */
    mag_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
    mag_post_config_session();
    ap_add_version_component(cfgpool, MOD_AUTH_GSSAPI_VERSION);

    return OK;
}

static int mag_pre_connection(conn_rec *c, void *csd)
{
    struct mag_conn *mc;

    mc = apr_pcalloc(c->pool, sizeof(struct mag_conn));
    if (!mc) return DECLINED;

    mc->parent = c->pool;
    ap_set_module_config(c->conn_config, &auth_gssapi_module, (void*)mc);
    return OK;
}

static apr_status_t mag_conn_destroy(void *ptr)
{
    struct mag_conn *mc = (struct mag_conn *)ptr;
    uint32_t min;

    if (mc->ctx) {
        (void)gss_delete_sec_context(&min, &mc->ctx, GSS_C_NO_BUFFER);
        mc->established = false;
    }
    return APR_SUCCESS;
}

static bool mag_conn_is_https(conn_rec *c)
{
    if (mag_is_https) {
        if (mag_is_https(c)) return true;
    }

    return false;
}

static char *escape(apr_pool_t *pool, const char *name,
                    char find, const char *replace)
{
    char *escaped = NULL;
    char *namecopy;
    char *n;
    char *p;

    namecopy = apr_pstrdup(pool, name);
    if (!namecopy) goto done;

    p = strchr(namecopy, find);
    if (!p) return namecopy;

    /* first segment */
    n = namecopy;
    while (p) {
        /* terminate previous segment */
        *p = '\0';
        if (escaped) {
            escaped = apr_pstrcat(pool, escaped, n, replace, NULL);
        } else {
            escaped = apr_pstrcat(pool, n, replace, NULL);
        }
        if (!escaped) goto done;
        /* move to next segment */
        n = p + 1;
        p = strchr(n, find);
    }
    /* append last segment if any */
    if (*n) {
        escaped = apr_pstrcat(pool, escaped, n, NULL);
    }

done:
    if (!escaped) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, NULL,
                     "OOM escaping name");
    }
    return escaped;
}

static void mag_store_deleg_creds(request_rec *req,
                                  char *dir, char *clientname,
                                  gss_cred_id_t delegated_cred,
                                  char **ccachefile)
{
    gss_key_value_element_desc element;
    gss_key_value_set_desc store;
    char *value;
    uint32_t maj, min;
    char *escaped;

    /* We need to escape away '/', we can't have path separators in
     * a ccache file name */
    /* first double escape the esacping char (~) if any */
    escaped = escape(req->pool, clientname, '~', "~~");
    if (!escaped) return;
    /* then escape away the separator (/) if any */
    escaped = escape(req->pool, escaped, '/', "~");
    if (!escaped) return;

    value = apr_psprintf(req->pool, "FILE:%s/%s", dir, escaped);
    if (!value) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, NULL,
                     "OOM storing delegated credentials");
        return;
    }

    element.key = "ccache";
    element.value = value;
    store.elements = &element;
    store.count = 1;

    maj = gss_store_cred_into(&min, delegated_cred, GSS_C_INITIATE,
                              GSS_C_NULL_OID, 1, 1, &store, NULL, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                      mag_error(req, "failed to store delegated creds",
                                maj, min));
    }

    *ccachefile = value;
}

typedef struct _ad_sids
{
  char **sids;
  unsigned int count;

} ad_sids;

/* The following structs are designed to get the size and location of each data type, 
 *  * not to represent the details of the inner data structures
 *   */
typedef struct _kerb_validation_info_header
{
  unsigned char rpc_headeaders[20];
} kerb_validation_info_header;

typedef struct _rpc_unicode_string_header
{
  unsigned char length[8];
  unsigned char element[4];
} rpc_unicode_string_header;

typedef struct _kerb_validation_info
{
  unsigned char logon_time[8];
  unsigned char logon_off_time[8];
  unsigned char kick_off_time[8];
  unsigned char password_last_set[8];
  unsigned char password_can_change[8];
  unsigned char password_must_change[8];
  unsigned char p_effective_name[8];
  unsigned char p_full_name[8];
  unsigned char p_logon_script[8];
  unsigned char p_profile_path[8];
  unsigned char p_home_directory[8];
  unsigned char p_home_directory_drive[8];
  unsigned char logon_count[2];
  unsigned char bad_password_count[2];
  unsigned char user_id[4];
  unsigned char primary_group_id[4];
  unsigned char group_count[4];
  unsigned char p_group_ids[4];
  unsigned char user_flags[4];
  unsigned char user_session_key[16];
  unsigned char p_logon_server[8];
  unsigned char p_logon_domain_name[8];
  unsigned char p_logon_domain_id[4];
  unsigned char reserved1[8];
  unsigned char user_account_control[4];
  unsigned char reserved2[28];
  unsigned char sid_count[4];
  unsigned char p_extra_sids[4];
  unsigned char p_resource_group_domain_sid[4];
  unsigned char resource_group_count[4];
  unsigned char p_resource_group_ids[4];
} kerb_validation_info;

/* data length of various SID components */
#define SID_REVISION_STR_LEN      3
#define SID_ID_AUTH_STR_LEN       3
#define SID_SUB_AUTH_STR_LEN      10
#define SID_REVISION_LEN          1
#define SID_ID_AUTH_LEN           1
#define SID_SUB_AUTH_LEN          4
#define SID_SUB_AUTH_NUM_LEN      6
#define RELATIVE_SID_TOTAL_LEN    8
#define RELATIVE_SID_LEN          4
#define LOGON_DOMAIN_SID_AUTH_LEN 4
#define EXTRA_SID_HEADER_LEN      4
#define EXTRA_SID_STRUCT_LEN      8
#define EXTRA_SID_AUTH_LEN 4

/* RPC String and other data length */
#define RPC_STRING_LEN            4
#define RPC_STRING_MAX_LEN        8
#define PROFILE_STRING_NUM        6
#define LOGON_STRING_NUM          2
#define GROUP_LEN                 4
#define BIT_NUM_IN_BYTE           8

static unsigned int
get_decimal (unsigned int pos, unsigned int len,
	     unsigned char *validation_data)
{
  unsigned int i, j;
  for (i = 0, j = 0; i < len; i++)
    {
      j += (unsigned int) validation_data[pos + i] << (BIT_NUM_IN_BYTE * i);
    }
  return j;
}

static unsigned int
get_rpc_string_buffer_size (int pos, unsigned char *validation_data)
{
  unsigned int ret, actual_elems;
  ret =
    get_decimal (pos + RPC_STRING_MAX_LEN, RPC_STRING_LEN, validation_data);
  actual_elems = (ret % 2) ? ret + 1 : ret;
  return RPC_STRING_MAX_LEN + RPC_STRING_LEN + actual_elems * 2;
}

static char *
get_string_sid (unsigned int pos, unsigned int *sid_pos,
		unsigned char *validation_data, request_rec * r)
{
  unsigned int next_pos;
  unsigned int sub_auth_num;
  unsigned int revision;
  unsigned int identifier_auth;
  unsigned int sub_auth;
  unsigned int i;
  unsigned int len;
  char sid_header[] = "S-";
  char *sid, *p_sid;

  revision = get_decimal (pos, SID_REVISION_LEN, validation_data);
  next_pos = pos + SID_REVISION_LEN;

  sub_auth_num =
    get_decimal (next_pos, SID_SUB_AUTH_NUM_LEN, validation_data);
  next_pos += SID_SUB_AUTH_NUM_LEN;

  identifier_auth = get_decimal (next_pos, SID_ID_AUTH_LEN, validation_data);
  next_pos += SID_ID_AUTH_LEN;

  len = strlen (sid_header) + SID_REVISION_STR_LEN + strlen ("-") +
    SID_ID_AUTH_STR_LEN + strlen ("-") +
    SID_SUB_AUTH_STR_LEN * (sub_auth_num + 1) + strlen ("-") * sub_auth_num +
    1;

  sid = (char *) apr_pcalloc (r->pool, len);
  p_sid = sid;
  /* sid is large enough to hold SID components */
  sprintf (p_sid, "%s%u-%u-", sid_header, revision, identifier_auth);
  p_sid = sid + strlen (sid);

  for (i = 0; i < sub_auth_num; i++)
    {
      sub_auth = get_decimal (next_pos, SID_SUB_AUTH_LEN, validation_data);
      if (i == sub_auth_num - 1)
	sprintf (p_sid, "%u", sub_auth);
      else
	sprintf (p_sid, "%u-", sub_auth);
      p_sid = sid + strlen (sid);
      next_pos += SID_SUB_AUTH_LEN;
    }

  *sid_pos = next_pos;
  return sid;
}

static ad_sids *extract_sids (request_rec * r, unsigned char *validation_data)
{
  unsigned int i, j;
  unsigned int group_count;
  unsigned int group_count_pos;
  unsigned int group_pos;
  unsigned int logon_domain_id_pos;
  unsigned int extra_sid_count;
  unsigned int extra_sid_pos;
  unsigned int extra_sid_data_pos;
  unsigned int domain_sid_str_len;
  unsigned int logon_string_pos;
  unsigned int count = 0;
  char *sid;
  char **sids;
  ad_sids *client_sids;
  kerb_validation_info kerb_info;

  client_sids =
    (ad_sids *) apr_pcalloc (r->connection->pool, sizeof (ad_sids));
  group_count_pos =
    sizeof (kerb_validation_info_header) + &kerb_info.group_count[0] -
    &kerb_info.logon_time[0];
  group_count =
    get_decimal (group_count_pos, sizeof (kerb_info.group_count),
		 validation_data);

  extra_sid_count =
    get_decimal (sizeof (kerb_validation_info_header) +
		 &kerb_info.sid_count[0] - &kerb_info.logon_time[0],
		 sizeof (kerb_info.sid_count), validation_data);

  for (i = 0, j = 0; i < PROFILE_STRING_NUM; i++)
    {
      j += get_rpc_string_buffer_size (sizeof (kerb_validation_info_header) +
				       sizeof (kerb_validation_info) + j,
				       validation_data);
    }

  group_pos =
    sizeof (kerb_validation_info_header) + sizeof (kerb_validation_info) + j;
  for (i = 0, j = group_pos + GROUP_LEN; i < group_count; i++)
    {
      j += RELATIVE_SID_TOTAL_LEN;
    }
  logon_string_pos = j;

  for (i = 0, j = 0; i < LOGON_STRING_NUM; i++)
    {
      j += get_rpc_string_buffer_size (logon_string_pos + j, validation_data);
    }

  client_sids = apr_pcalloc (r->connection->pool, sizeof (ad_sids));
  sids =
    apr_pcalloc (r->connection->pool,
		 sizeof (char *) * (group_count + extra_sid_count));
  client_sids->sids = sids;

  logon_domain_id_pos = logon_string_pos + j + LOGON_DOMAIN_SID_AUTH_LEN;
  sid = get_string_sid (logon_domain_id_pos, &extra_sid_pos, validation_data, r);
  domain_sid_str_len = strlen (sid);

  for (i = 0, j = group_pos + GROUP_LEN; i < group_count; i++)
    {
      sprintf (sid + domain_sid_str_len, "-%u",
	       get_decimal (j, RELATIVE_SID_LEN, validation_data));
      j += RELATIVE_SID_TOTAL_LEN;
      client_sids->sids[count] = apr_pstrdup (r->connection->pool, sid);
      ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r, "Group sid number %d: %s",
		     count, client_sids->sids[count]);
      count++;
    }
  
  if (extra_sid_count)
    {
      unsigned int next_sid_pos = 0;
      extra_sid_data_pos =
	extra_sid_pos + EXTRA_SID_HEADER_LEN +
	EXTRA_SID_STRUCT_LEN * extra_sid_count;
      for (i = 0, j = extra_sid_data_pos + EXTRA_SID_AUTH_LEN;
	   i < extra_sid_count; i++)
	{
	  char *str_sid = get_string_sid (j, &next_sid_pos, validation_data, r);
	  client_sids->sids[count] =
	    apr_pstrdup (r->connection->pool, str_sid);
	  ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r,
			 "Group sid number %d: %s", count,
			 client_sids->sids[count]);
	  count++;
	  j = next_sid_pos + EXTRA_SID_AUTH_LEN;	  
	}
    }

  client_sids->count = count;
  return client_sids;
}

static int mag_auth(request_rec *req)
{
    const char *type;
    const char *auth_type;
    size_t auth_type_len = 0;
    struct mag_config *cfg;
    const char *auth_header;
    char *auth_header_type;
    char *auth_header_value;
    int ret = HTTP_UNAUTHORIZED;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t *pctx;
    gss_buffer_desc input = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    gss_name_t client = GSS_C_NO_NAME;
    gss_cred_id_t user_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t acquired_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_usage_t cred_usage = GSS_C_ACCEPT;
    uint32_t flags;
    uint32_t vtime;
    uint32_t maj, min;
    char *reply;
    size_t replen;
    char *clientname;
    gss_OID mech_type = GSS_C_NO_OID;
    gss_OID_set desired_mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc lname = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc mech_buff = GSS_C_EMPTY_BUFFER;
    bool is_ntlm = false;
    struct mag_conn *mc = NULL;
    bool is_basic = false;
    gss_ctx_id_t user_ctx = GSS_C_NO_CONTEXT;
    gss_name_t server = GSS_C_NO_NAME;
    int mn_name;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    gss_buffer_desc attr_value = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc display_value = GSS_C_EMPTY_BUFFER;
  int authenticated = 0;
  int complete = 0;
  int more = -1;
  int i;
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
    const char *user_ccache = NULL;
    const char *orig_ccache = NULL;
#endif

    type = ap_auth_type(req);
    if ((type == NULL) || (strcasecmp(type, "GSSAPI") != 0)) {
        return DECLINED;
    }

    cfg = ap_get_module_config(req->per_dir_config, &auth_gssapi_module);

    /* implicit auth for subrequests if main auth already happened */
    if (!ap_is_initial_req(req)) {
        type = ap_auth_type(req->main);
        if ((type != NULL) && (strcasecmp(type, "GSSAPI") == 0)) {
            /* warn if the subrequest location and the main request
             * location have different configs */
            if (cfg != ap_get_module_config(req->main->per_dir_config,
                                            &auth_gssapi_module)) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING||APLOG_NOERRNO, 0,
                              req, "Subrequest authentication bypass on "
                                   "location with different configuration!");
            }
            if (req->main->user) {
                req->user = apr_pstrdup(req->pool, req->main->user);
                return OK;
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "The main request is tasked to establish the "
                              "security context, can't proceed!");
                return HTTP_UNAUTHORIZED;
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, req,
                          "Subrequest GSSAPI auth with no auth on the main "
                          "request. This operation may fail if other "
                          "subrequests already established a context or the "
                          "mechanism requires multiple roundtrips.");
        }
    }

    if (cfg->ssl_only) {
        if (!mag_conn_is_https(req->connection)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Not a TLS connection, refusing to authenticate!");
            goto done;
        }
    }

    if (cfg->gss_conn_ctx) {
        mc = (struct mag_conn *)ap_get_module_config(
                                                req->connection->conn_config,
                                                &auth_gssapi_module);
        if (!mc) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, req,
                          "Failed to retrieve connection context!");
            goto done;
        }
    }

    /* if available, session always supersedes connection bound data */
    if (cfg->use_sessions) {
        mag_check_session(req, cfg, &mc);
    }

    auth_header = apr_table_get(req->headers_in, "Authorization");

    if (mc) {
        /* register the context in the memory pool, so it can be freed
         * when the connection/request is terminated */
        apr_pool_userdata_set(mc, "mag_conn_ptr",
                              mag_conn_destroy, mc->parent);

        if (mc->established && !auth_header) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, req,
                          "Already established context found!");
            apr_table_set(req->subprocess_env, "GSS_NAME", mc->gss_name);
            req->ap_auth_type = apr_pstrdup(req->pool, mc->auth_type);
            req->user = apr_pstrdup(req->pool, mc->user_name);
            ret = OK;
            goto done;
        }
        pctx = &mc->ctx;
    } else {
        pctx = &ctx;
    }

    if (!auth_header) goto done;

    auth_header_type = ap_getword_white(req->pool, &auth_header);
    if (!auth_header_type) goto done;

    if (strcasecmp(auth_header_type, "Negotiate") == 0) {
        auth_type = "Negotiate";
        auth_type_len = 10;
        auth_header_value = ap_getword_white(req->pool, &auth_header);
        if (!auth_header_value) goto done;
        input.length = apr_base64_decode_len(auth_header_value) + 1;
        input.value = apr_pcalloc(req->pool, input.length);
        if (!input.value) goto done;
        input.length = apr_base64_decode(input.value, auth_header_value);
    } else if ((strcasecmp(auth_header_type, "NTLM") == 0)  &&
               (cfg->use_ntlm_auth == true)) {
        auth_type = "NTLM";
        auth_type_len = 5;
        is_ntlm = true;
        auth_header_value = ap_getword_white(req->pool, &auth_header);
        if (!auth_header_value) goto done;
        input.length = apr_base64_decode_len(auth_header_value) + 1;
        input.value = apr_pcalloc(req->pool, input.length);
        if (!input.value) goto done;
        input.length = apr_base64_decode(input.value, auth_header_value);
    } else if ((strcasecmp(auth_header_type, "Basic") == 0) &&
               (cfg->use_basic_auth == true)) {
        auth_type = "Basic";
        auth_type_len = 6;
        is_basic = true;

        gss_buffer_desc ba_user;
        gss_buffer_desc ba_pwd;

        ba_pwd.value = ap_pbase64decode(req->pool, auth_header);
        if (!ba_pwd.value) goto done;
        ba_user.value = ap_getword_nulls_nc(req->pool,
                                            (char **)&ba_pwd.value, ':');
        if (!ba_user.value) goto done;
        if (((char *)ba_user.value)[0] == '\0' ||
            ((char *)ba_pwd.value)[0] == '\0') {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Invalid empty user or password for Basic Auth");
            goto done;
        }
        ba_user.length = strlen(ba_user.value);
        ba_pwd.length = strlen(ba_pwd.value);
        maj = gss_import_name(&min, &ba_user, GSS_C_NT_USER_NAME, &client);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "In Basic Auth, %s",
                          mag_error(req, "gss_import_name() failed",
                                    maj, min));
            goto done;
        }
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
        /* Set a per-thread ccache in case we are using kerberos,
         * it is not elegant but avoids interference between threads */
        long long unsigned int rndname;
        apr_status_t rs;
        rs = apr_generate_random_bytes((unsigned char *)(&rndname),
                                       sizeof(long long unsigned int));
        if (rs != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Failed to generate random ccache name");
            goto done;
        }
        user_ccache = apr_psprintf(req->pool, "MEMORY:user_%qu", rndname);
        maj = gss_krb5_ccache_name(&min, user_ccache, &orig_ccache);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "In Basic Auth, %s",
                          mag_error(req, "gss_krb5_ccache_name() "
                                    "failed", maj, min));
            goto done;
        }
#endif
        maj = gss_acquire_cred_with_password(&min, client, &ba_pwd,
                                             GSS_C_INDEFINITE,
                                             GSS_C_NO_OID_SET,
                                             GSS_C_INITIATE,
                                             &user_cred, NULL, NULL);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "In Basic Auth, %s",
                          mag_error(req, "gss_acquire_cred_with_password() "
                                    "failed", maj, min));
            goto done;
        }
        gss_release_name(&min, &client);
    } else {
        goto done;
    }

    req->ap_auth_type = apr_pstrdup(req->pool, auth_type);

#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
    if (cfg->use_s4u2proxy) {
        cred_usage = GSS_C_BOTH;
    }
    if (cfg->cred_store) {
        maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                    GSS_C_NO_OID_SET, cred_usage,
                                    cfg->cred_store, &acquired_cred,
                                    NULL, NULL);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                          mag_error(req, "gss_acquire_cred_from() failed",
                                    maj, min));
            goto done;
        }
    }
#endif

    if (is_ntlm || 1) {
        maj = gss_create_empty_oid_set(&min, &desired_mechs);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "%s", mag_error(req, "gss_create_empty_oid_set()"
                                              " failed", maj, min));
            goto done;
        }
        maj = gss_add_oid_set_member(&min, &ntlm_mech_oid, &desired_mechs);
        if (GSS_ERROR(maj)) {
            gss_release_oid_set(&min, &desired_mechs);
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "%s", mag_error(req, "gss_add_oid_set_member()"
                                              " failed", maj, min));
            goto done;
        }
    }
        if (!acquired_cred) {
            /* Try to acquire default acceptor creds */
            maj = gss_acquire_cred(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                   /*desired_mechs*/ NULL, cred_usage,
                                   &acquired_cred, NULL, NULL);
            if (GSS_ERROR(maj)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "%s", mag_error(req, "gss_acquire_cred_from()"
                                              " failed", maj, min));
                goto done;
            }

           // maj = gss_set_neg_mechs(&min, acquired_cred, desired_mechs);
            if (GSS_ERROR(maj)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "%s", mag_error(req, "gss_set_neg_mechs()"
                                              " failed", maj, min));
                goto done;
            }

            gss_release_oid_set(&min, &desired_mechs);
        }
    maj = gss_inquire_cred(&min, acquired_cred, &server,
                           NULL, NULL, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "%s", mag_error(req, "gss_inquired_cred() "
                                      "failed", maj, min));
        goto done;
    }

    if (is_basic) {
        /* output and input are inverted here, this is intentional */
        maj = gss_init_sec_context(&min, user_cred, &user_ctx, server,
                                   GSS_C_NO_OID, 0, 300,
                                   GSS_C_NO_CHANNEL_BINDINGS, &output,
                                   NULL, &input, NULL, NULL);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "%s", mag_error(req, "gss_init_sec_context() "
                                          "failed", maj, min));
            goto done;
        }
    }

    maj = gss_accept_sec_context(&min, pctx, acquired_cred,
                                 &input, GSS_C_NO_CHANNEL_BINDINGS,
                                 &client, &mech_type, &output, &flags, &vtime,
                                 &delegated_cred);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                      mag_error(req, "gss_accept_sec_context() failed",
                                maj, min));
        goto done;
    }
    maj = gss_oid_to_str(&min, mech_type, &mech_buff);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                      mag_error(req, "gss_oid_to_str() failed",
                                maj, min));
        goto here;
    }
    if(mech_buff.length && mech_buff.value)
        fprintf(stderr, "Mech OID from accept: %.*s\n",
                mech_buff.length, (char *) mech_buff.value);
    else
        fprintf(stderr, "No Mech OID from accept\n");
    gss_release_buffer(&min, &mech_buff);
here:
    mech_type = GSS_C_NULL_OID;
    maj = gss_inquire_name(&min, client, &mn_name, &mech_type, &attrs);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                      mag_error(req, "gss_map_name_to_any() failed",
                                maj, min));
        goto done;
    }

    if(attrs == GSS_C_NO_BUFFER_SET || !attrs || !attrs->count)
        fprintf(stderr, "No authz data\n");
    else {
        char *tst_grp = calloc(1,1000);
        int tlen = apr_base64_decode(tst_grp, "AQUAAAAAAAUVAAAAHqNECUqBjc8BXYmpdwQAAA==");
        char *t_str = get_string_sid(0, &tlen, tst_grp, req);
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "TST SID: %s", t_str);

        gss_buffer_desc pac_name = {
		.value = "urn:mspac:",
		.length = sizeof("urn:mspac:")-1
	};
        more = -1;
        attr_value.value = NULL;
        display_value.value = NULL;
        maj = gss_get_name_attribute (&min,
                                      client,
                                      &pac_name,
                                      &authenticated,
                                      &complete,
                                      &attr_value,
                                      &display_value,
                                      &more);
        if (GSS_ERROR(maj)) {
                     ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                         mag_error(req, "gss_map_name_to_any() failed",
                                maj, min));
                     goto done;
        }

        fprintf(stderr, "authenticated: %d - complete: %d - more: %d\n", authenticated, complete, more);
        fprintf(stderr, "attr_value.value: %s\n", (char *) attr_value.value);
        fprintf(stderr, "attr_value.length: %d\n", attr_value.length);
        fprintf(stderr, "display_value.value: %s\n", (char *) display_value.value);
        gss_release_buffer (&min, &attr_value);
        gss_release_buffer (&min, &display_value);

        fprintf(stderr, "initial count: %d\n", attrs->count);
        for(i = 1; i < attrs->count; i++) {
            more = -1;
            while(more) {
                attr_value.value = NULL;
                display_value.value = NULL;
                maj = gss_get_name_attribute (&min,
				              client,
				              &attrs->elements[i],
				              &authenticated,
				              &complete,
				              &attr_value, 
                                              &display_value, 
                                              &more);
                 if (GSS_ERROR(maj)) {
                     ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                         mag_error(req, "gss_map_name_to_any() failed",
                                maj, min));
                     goto done;
                }
                
                ad_sids *sids = extract_sids(req, attr_value.value);
                if (sids) {
                    int j;
                    for (j = 0; j < sids->count; j++) {
	                ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, req,
		    	     "%s MAG SID: %s", req->user,  //ah, user not yet set
		    	     sids->sids[j]);
	             }
	        }

                attr_value.value = NULL;
                maj = gsskrb5_extract_authz_data_from_sec_context(&min, *pctx, 128, &attr_value);
                if (GSS_ERROR(maj)) {
                     ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                         mag_error(req, "gsskrb5_extract_authz_data_from_sec_context() failed",
                                maj, min));
                     goto done;
                }
                fprintf(stderr, "i: %d - authenticated: %d - complete: %d - more: %d\n", i, authenticated, complete, more);
                fprintf(stderr, "attr_value.value: %s\n", (char *) attr_value.value);
                fprintf(stderr, "attr_value.length: %d\n", attr_value.length);
                fprintf(stderr, "display_value.value: %s\n", (char *) display_value.value);
                gss_release_buffer (&min, &attr_value);
                gss_release_buffer (&min, &display_value);
            }
        fprintf(stderr, "count: %d\n", attrs->count);
        }  
    }

    gss_release_buffer_set (&min, &attrs);













    if(is_ntlm) {
        if(mech_type->length != ntlm_mech_oid.length ||
            memcmp(mech_type->elements, ntlm_mech_oid.elements, mech_type->length)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Not NTLM mech inside NTLM authentication - aborting");
            gss_delete_sec_context(&min, pctx, GSS_C_NO_BUFFER);
            gss_release_buffer(&min, &output);
            output.length = 0;
            goto done;
        }
    }

    if (is_basic) {
        while (maj == GSS_S_CONTINUE_NEEDED) {
            gss_release_buffer(&min, &input);
            /* output and input are inverted here, this is intentional */
            maj = gss_init_sec_context(&min, user_cred, &user_ctx, server,
                                       GSS_C_NO_OID, 0, 300,
                                       GSS_C_NO_CHANNEL_BINDINGS, &output,
                                       NULL, &input, NULL, NULL);
            if (GSS_ERROR(maj)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "%s", mag_error(req, "gss_init_sec_context() "
                                              "failed", maj, min));
                goto done;
            }
            gss_release_buffer(&min, &output);
            maj = gss_accept_sec_context(&min, pctx, acquired_cred,
                                         &input, GSS_C_NO_CHANNEL_BINDINGS,
                                         &client, &mech_type, &output, &flags,
                                         &vtime, &delegated_cred);
            if (GSS_ERROR(maj)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "%s", mag_error(req, "gss_accept_sec_context()"
                                              " failed", maj, min));
                goto done;
            }
        }
    } else if (maj == GSS_S_CONTINUE_NEEDED) {
        if (!mc) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Mechanism needs continuation but neither "
                          "GssapiConnectionBound nor "
                          "GssapiUseSessions are available");
            gss_delete_sec_context(&min, pctx, GSS_C_NO_BUFFER);
            gss_release_buffer(&min, &output);
            output.length = 0;
        }
        /* auth not complete send token and wait next packet */
        goto done;
    }

    /* Always set the GSS name in an env var */
    maj = gss_display_name(&min, client, &name, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                      mag_error(req, "gss_display_name() failed",
                                maj, min));
        goto done;
    }
    clientname = apr_pstrndup(req->pool, name.value, name.length);
    apr_table_set(req->subprocess_env, "GSS_NAME", clientname);

#ifdef HAVE_GSS_STORE_CRED_INTO
    if (cfg->deleg_ccache_dir && delegated_cred != GSS_C_NO_CREDENTIAL) {
        char *ccachefile = NULL;

        mag_store_deleg_creds(req, cfg->deleg_ccache_dir, clientname,
                              delegated_cred, &ccachefile);

        if (ccachefile) {
            apr_table_set(req->subprocess_env, "KRB5CCNAME", ccachefile);
        }
    }
#endif

    if (cfg->map_to_local) {
        maj = gss_localname(&min, client, mech_type, &lname);
        if (maj != GSS_S_COMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                          mag_error(req, "gss_localname() failed", maj, min));
            goto done;
        }
        req->user = apr_pstrndup(req->pool, lname.value, lname.length);
    } else {
        req->user = clientname;
    }

    if (mc) {
        mc->user_name = apr_pstrdup(mc->parent, req->user);
        mc->gss_name = apr_pstrdup(mc->parent, clientname);
        mc->established = true;
        if (vtime == GSS_C_INDEFINITE || vtime < MIN_SESS_EXP_TIME) {
            vtime = MIN_SESS_EXP_TIME;
        }
        mc->expiration = time(NULL) + vtime;
        if (cfg->use_sessions) {
            mag_attempt_session(req, cfg, mc);
        }
        mc->auth_type = auth_type;
    }

    ret = OK;

done:
    if (ret == HTTP_UNAUTHORIZED || !is_basic) {
        if (output.length != 0) {
            replen = apr_base64_encode_len(output.length) + 1;
            reply = apr_pcalloc(req->pool, auth_type_len + replen);
            if (reply) {
                memcpy(reply, auth_type, auth_type_len);
                reply[auth_type_len -1] = ' ';
                apr_base64_encode(&reply[auth_type_len], output.value, output.length);
                apr_table_add(req->err_headers_out,
                              "WWW-Authenticate", reply);
            }
        } else if (ret == HTTP_UNAUTHORIZED) {
            apr_table_add(req->err_headers_out,
                          "WWW-Authenticate", "Negotiate");
            if (cfg->use_ntlm_auth)
                apr_table_add(req->err_headers_out,
                          "WWW-Authenticate", "NTLM");
            if (cfg->use_basic_auth) {
                apr_table_add(req->err_headers_out,
                              "WWW-Authenticate",
                              apr_psprintf(req->pool, "Basic realm=\"%s\"",
                                           ap_auth_name(req)));
            }
        }
    }
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
    if (user_ccache != NULL) {
        maj = gss_krb5_ccache_name(&min, orig_ccache, NULL);
        if (maj != GSS_S_COMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Failed to restore per-thread ccache, %s",
                          mag_error(req, "gss_krb5_ccache_name() "
                                    "failed", maj, min));
        }
    }
#endif
    gss_delete_sec_context(&min, &user_ctx, &output);
    gss_release_cred(&min, &user_cred);
    gss_release_cred(&min, &acquired_cred);
    gss_release_cred(&min, &delegated_cred);
    gss_release_buffer(&min, &output);
    gss_release_name(&min, &client);
    gss_release_name(&min, &server);
    gss_release_buffer(&min, &name);
    gss_release_buffer(&min, &lname);
    return ret;
}


static void *mag_create_dir_config(apr_pool_t *p, char *dir)
{
    struct mag_config *cfg;

    cfg = (struct mag_config *)apr_pcalloc(p, sizeof(struct mag_config));
    if (!cfg) return NULL;
    cfg->pool = p;

    return cfg;
}

static const char *mag_ssl_only(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->ssl_only = on ? true : false;
    return NULL;
}

static const char *mag_map_to_local(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->map_to_local = on ? true : false;
    return NULL;
}

static const char *mag_conn_ctx(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->gss_conn_ctx = on ? true : false;
    return NULL;
}

static const char *mag_use_sess(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->use_sessions = on ? true : false;
    return NULL;
}

static const char *mag_use_s4u2p(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->use_s4u2proxy = on ? true : false;

    if (cfg->deleg_ccache_dir == NULL) {
        cfg->deleg_ccache_dir = apr_pstrdup(parms->pool, "/tmp");
        if (!cfg->deleg_ccache_dir) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0,
                         parms->server, "%s", "OOM setting deleg_ccache_dir.");
        }
    }
    return NULL;
}

static const char *mag_sess_key(cmd_parms *parms, void *mconfig, const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    struct databuf key;
    unsigned char *val;
    apr_status_t rc;
    const char *k;
    int l;

    if (strncmp(w, "key:", 4) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Invalid key format, expected prefix 'key:'");
        return NULL;
    }
    k = w + 4;

    l = apr_base64_decode_len(k);
    val = apr_palloc(parms->temp_pool, l);
    if (!val) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Failed to get memory to decode key");
        return NULL;
    }

    key.length = (int)apr_base64_decode_binary(val, k);
    key.value = (unsigned char *)val;

    if (key.length < 32) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Invalid key length, expected >=32 got %d", key.length);
        return NULL;
    }

    rc = SEAL_KEY_CREATE(cfg->pool, &cfg->mag_skey, &key);
    if (rc != OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Failed to import sealing key!");
    }
    return NULL;
}

#define MAX_CRED_OPTIONS 10

static const char *mag_cred_store(cmd_parms *parms, void *mconfig,
                                  const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    gss_key_value_element_desc *elements;
    uint32_t count;
    size_t size;
    const char *p;
    char *value;
    char *key;

    p = strchr(w, ':');
    if (!p) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "%s [%s]", "Invalid syntax for GssapiCredStore option", w);
        return NULL;
    }

    key = apr_pstrndup(parms->pool, w, (p-w));
    value = apr_pstrdup(parms->pool, p + 1);
    if (!key || !value) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "%s", "OOM handling GssapiCredStore option");
        return NULL;
    }

    if (!cfg->cred_store) {
        cfg->cred_store = apr_pcalloc(parms->pool,
                                      sizeof(gss_key_value_set_desc));
        if (!cfg->cred_store) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                         "%s", "OOM handling GssapiCredStore option");
            return NULL;
        }
        size = sizeof(gss_key_value_element_desc) * MAX_CRED_OPTIONS;
        cfg->cred_store->elements = apr_palloc(parms->pool, size);
        if (!cfg->cred_store->elements) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                         "%s", "OOM handling GssapiCredStore option");
        }
    }

    elements = cfg->cred_store->elements;
    count = cfg->cred_store->count;

    if (count >= MAX_CRED_OPTIONS) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Too many GssapiCredStore options (MAX: %d)",
                     MAX_CRED_OPTIONS);
        return NULL;
    }
    cfg->cred_store->count++;

    elements[count].key = key;
    elements[count].value = value;

    return NULL;
}

static const char *mag_deleg_ccache_dir(cmd_parms *parms, void *mconfig,
                                        const char *value)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    cfg->deleg_ccache_dir = apr_pstrdup(parms->pool, value);
    if (!cfg->deleg_ccache_dir) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "%s", "OOM handling GssapiDelegCcacheDir option");
    }

    return NULL;
}

static const char *mag_use_basic_auth(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    cfg->use_basic_auth = on ? true : false;
    return NULL;
}

static const char *mag_use_ntlm_auth(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    cfg->use_ntlm_auth = on ? true : false;
    return NULL;
}

static const command_rec mag_commands[] = {
    AP_INIT_FLAG("GssapiSSLonly", mag_ssl_only, NULL, OR_AUTHCFG,
                  "Work only if connection is SSL Secured"),
    AP_INIT_FLAG("GssapiLocalName", mag_map_to_local, NULL, OR_AUTHCFG,
                  "Translate principals to local names"),
    AP_INIT_FLAG("GssapiConnectionBound", mag_conn_ctx, NULL, OR_AUTHCFG,
                  "Authentication is bound to the TCP connection"),
    AP_INIT_FLAG("GssapiUseSessions", mag_use_sess, NULL, OR_AUTHCFG,
                  "Authentication uses mod_sessions to hold status"),
    AP_INIT_RAW_ARGS("GssapiSessionKey", mag_sess_key, NULL, OR_AUTHCFG,
                     "Key Used to seal session data."),
#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
    AP_INIT_FLAG("GssapiUseS4U2Proxy", mag_use_s4u2p, NULL, OR_AUTHCFG,
                  "Initializes credentials for s4u2proxy usage"),
#endif
#ifdef HAVE_GSS_STORE_CRED_INTO
    AP_INIT_ITERATE("GssapiCredStore", mag_cred_store, NULL, OR_AUTHCFG,
                    "Credential Store"),
    AP_INIT_RAW_ARGS("GssapiDelegCcacheDir", mag_deleg_ccache_dir, NULL,
                     OR_AUTHCFG, "Directory to store delegated credentials"),
#endif
#ifdef HAVE_GSS_ACQUIRE_CRED_WITH_PASSWORD
    AP_INIT_FLAG("GssapiBasicAuth", mag_use_basic_auth, NULL, OR_AUTHCFG,
                     "Allows use of Basic Auth for authentication"),
#endif
    AP_INIT_FLAG("GssapiNTLMAuth", mag_use_ntlm_auth, NULL, OR_AUTHCFG,
                     "Allows use of NTML Auth without Negotiate"),
    { NULL }
};

static void
mag_register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(mag_auth, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(mag_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(mag_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_gssapi_module =
{
    STANDARD20_MODULE_STUFF,
    mag_create_dir_config,
    NULL,
    NULL,
    NULL,
    mag_commands,
    mag_register_hooks
};
