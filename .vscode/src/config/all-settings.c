/* WARNING: THIS FILE IS GENERATED - DO NOT PATCH!
   It's not enough alone in any case, because the defaults may be
   coming from the individual *-settings.c in some situations. If you
   wish to modify defaults, change the other *-settings.c files and
   just delete this file. This file will be automatically regenerated
   by make. (This file is distributed in the tarball only because some
   systems might not have Perl installed.) */
#include "lib.h"
#include "array.h"
#include "str.h"
#include "ipwd.h"
#include "var-expand.h"
#include "file-lock.h"
#include "fsync-mode.h"
#include "hash-format.h"
#include "net.h"
#include "unichar.h"
#include "uri-util.h"
#include "hash-method.h"
#include "settings.h"
#include "master-interface.h"
#include "message-header-parser.h"
#include "imap-urlauth-worker-common.h"
#include "mailbox-list.h"
#include "doc.h"
#include "all-settings.h"
#include <unistd.h>
#define CONFIG_BINARY
#define PLUGIN_BUILD
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict/dict.h */
struct dict_settings {
	pool_t pool;
	const char *dict_name;
	const char *dict_driver;
	ARRAY_TYPE(const_string) dicts;
};
struct dict_op_settings {
	const char *username;
	/* home directory for the user, if known */
	const char *home_dir;

	/* If non-zero, number of seconds until the added keys expire. See the
	   documentation how this is implemented for different drivers. */
	unsigned int expire_secs;

	/* Don't log a warning if the transaction commit took a long time.
	   This is needed if there are no guarantees that an asynchronous
	   commit will finish up anytime soon. Mainly useful for transactions
	   which aren't especially important whether they finish or not. */
	bool no_slowness_warning;
	/* Hide values when logging about this transaction. */
	bool hide_log_values;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dns-client/dns-lookup.h */
struct dns_client_settings {
	pool_t pool;
	const char *dns_client_socket_path;
	const char *base_dir;
	unsigned int timeout_msecs;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-fs/fs-api.h */
struct fs_settings {
	pool_t pool;
	const char *fs_name;
	const char *fs_driver;
	ARRAY_TYPE(const_string) fs;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-http/http-client.h */
struct http_client_settings {
	pool_t pool;
	/* A copy of base_dir setting. FIXME: this should not be here. */
	const char *base_dir;
	/* How long to cache DNS records internally
	   (default = HTTP_CLIENT_DEFAULT_DNS_TTL_MSECS) */
	unsigned int dns_ttl_msecs;

	/* User-Agent: header (default: none) */
	const char *user_agent;

	/* Proxy on unix socket */
	const char *proxy_socket_path;
	/* URL for normal proxy (ignored if proxy_socket_path is set) */
	const char *proxy_url;
	/* Credentials for proxy */
	const char *proxy_username;
	const char *proxy_password;

	/* Directory for writing raw log data for debugging purposes */
	const char *rawlog_dir;

	/* Maximum time a connection will idle. if parallel connections are
	   idle, the duplicates will end earlier based on how many idle
	   connections exist to that same service. */
	unsigned int max_idle_time_msecs;

	/* Maximum number of parallel connections per peer (default = 1) */
	unsigned int max_parallel_connections;

	/* Maximum number of pipelined requests per connection (default = 1) */
	unsigned int max_pipelined_requests;

	/* FALSE = Don't automatically act upon redirect responses. The
	   redirects are returned as a regular response. TRUE = Handle
	   redirects as long as request_max_redirects isn't reached. */
	bool auto_redirect;

	/* FALSE = Never automatically retry requests. Explicit
	   http_client_request_try_retry() calls can still retry requests
	   as long as request_max_attempts isn't reached. */
	bool auto_retry;

	/* FALSE = If we use a proxy, delegate SSL negotiation to proxy, rather
	   than creating a CONNECT tunnel through the proxy for the SSL link */
	bool proxy_ssl_tunnel;

	/* Maximum number of redirects for a request
	   (default = 0; redirects result in
	   HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT)
	 */
	unsigned int request_max_redirects;

	/* Maximum number of attempts for a request. 0 means the same as 1. */
	unsigned int request_max_attempts;
	/* If non-zero, override max_attempts for GET/HEAD requests. */
	unsigned int read_request_max_attempts;
	/* If non-zero, override max_attempts for PUT/POST requests. */
	unsigned int write_request_max_attempts;
	/* If non-zero, override max_attempts for DELETE requests. */
	unsigned int delete_request_max_attempts;

	/* Maximum number of connection attempts to a host before all associated
	   requests fail.

	   if > 0, the maximum will be enforced across all IPs for that host,
	   meaning that IPs may be tried more than once eventually if the number
	   of IPs is smaller than the specified maximum attempts. If the number
	   of IPs is higher than the maximum attempts, not all IPs are tried.
	   If 0, all IPs are tried at most once.
	 */
	unsigned int max_connect_attempts;

	/* Initial backoff time; doubled at each connection failure
	   (default = HTTP_CLIENT_DEFAULT_BACKOFF_TIME_MSECS) */
	unsigned int connect_backoff_time_msecs;
	/* Maximum backoff time
	   (default = HTTP_CLIENT_DEFAULT_BACKOFF_MAX_TIME_MSECS) */
	unsigned int connect_backoff_max_time_msecs;

	/* Response header limits */
	uoff_t response_hdr_max_size;
	uoff_t response_hdr_max_field_size;
	unsigned int response_hdr_max_fields;

	/* Max total time to wait for HTTP request to finish this can be
	   overridden/reset for individual requests using
	   http_client_request_set_timeout() and friends.
	   (default is no timeout)
	 */
	unsigned int request_absolute_timeout_msecs;
	/* Max time to wait for HTTP request to finish before retrying.
	   (default = HTTP_CLIENT_DEFAULT_REQUEST_TIMEOUT_MSECS) */
	unsigned int request_timeout_msecs;
	/* If non-zero, override request_timeout for GET/HEAD requests. */
	unsigned int read_request_timeout_msecs;
	/* If non-zero, override request_timeout for PUT/POST requests. */
	unsigned int write_request_timeout_msecs;
	/* If non-zero, override request_timeout for DELETE requests. */
	unsigned int delete_request_timeout_msecs;
	/* Max time to wait for connect() (and SSL handshake) to finish before
	   retrying. (default = request_timeout_msecs) */
	unsigned int connect_timeout_msecs;
	/* Time to wait for connect() (and SSL handshake) to finish for the
	   first connection before trying the next IP in parallel.
	   (default = 0; wait until current connection attempt finishes) */
	unsigned int soft_connect_timeout_msecs;

	/* Maximum acceptable delay in seconds for automatically
	   retrying/redirecting requests. If a server sends a response with a
	   Retry-After header that causes a delay longer than this, the request
	   is not automatically retried and the response is returned */
	unsigned int max_auto_retry_delay_secs;

	/* The kernel send/receive buffer sizes used for the connection sockets.
	   Configuring this is mainly useful for the test suite. The kernel
	   defaults are used when these settings are 0. */
	uoff_t socket_send_buffer_size;
	uoff_t socket_recv_buffer_size;

	/* generated: */
	struct http_url *parsed_proxy_url;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-http/http-server.h */
#define HTTP_SERVER_DEFAULT_MAX_PAYLOAD_SIZE (1024 * 1024 * 1024 * 10ULL)
struct http_server_settings {
	pool_t pool;
	const char *base_dir;
	const char *rawlog_dir;

	/* The maximum time in milliseconds a client is allowed to be idle
	   before it is disconnected. */
	unsigned int max_client_idle_time_msecs;

	/* Maximum number of pipelined requests per connection (default = 1) */
	unsigned int max_pipelined_requests;

	/* Request limits */
	uoff_t request_max_target_length;
	uoff_t request_max_payload_size;
	/* Request header limits */
	uoff_t request_hdr_max_size;
	uoff_t request_hdr_max_field_size;
	unsigned int request_hdr_max_fields;

	/* Hidden settings */
	const char *default_host;
	/* The kernel send/receive buffer sizes used for the connection sockets.
	   Configuring this is mainly useful for the test suite. The kernel
	   defaults are used when these settings are 0. */
	uoff_t socket_send_buffer_size;
	uoff_t socket_recv_buffer_size;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-master/master-service-settings.h */

/* <settings checks> */
#ifdef DOVECOT_PRO_EDITION
#  define VERBOSE_PROCTITLE_DEFAULT TRUE
#else
#  define VERBOSE_PROCTITLE_DEFAULT FALSE
#endif
/* </settings checks> */
#define MASTER_SERVICE_BINARY_CONFIG_DEFAULTS "<default config>"
struct master_service_settings {
	pool_t pool;
	const char *base_dir;
	const char *state_dir;
	const char *instance_name;
	const char *log_path;
	const char *info_log_path;
	const char *debug_log_path;
	const char *log_timestamp;
	const char *log_debug;
	const char *log_core_filter;
	const char *process_shutdown_filter;
	const char *syslog_facility;
	const char *stats_writer_socket_path;
	const char *auth_master_socket_path;
	const char *dovecot_storage_version;
	ARRAY_TYPE(const_string) import_environment;
	bool version_ignore;
	bool shutdown_clients;
	bool verbose_proctitle;

	const char *haproxy_trusted_networks;
	unsigned int haproxy_timeout;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-master/service-settings.h */

/* <settings checks> */
enum service_user_default {
	SERVICE_USER_DEFAULT_NONE = 0,
	SERVICE_USER_DEFAULT_INTERNAL,
	SERVICE_USER_DEFAULT_LOGIN
};

enum service_type {
	SERVICE_TYPE_UNKNOWN,
	SERVICE_TYPE_LOG,
	SERVICE_TYPE_ANVIL,
	SERVICE_TYPE_CONFIG,
	SERVICE_TYPE_LOGIN,
	SERVICE_TYPE_STARTUP,
	/* Worker processes are intentionally limited to their process_limit,
	   and they can regularly reach it. There shouldn't be unnecessary
	   warnings about temporarily reaching the limit. */
	SERVICE_TYPE_WORKER,
};

struct config_service {
	const struct service_settings *set;
	const struct setting_keyvalue *defaults;
};
ARRAY_DEFINE_TYPE(config_service, struct config_service);
/* </settings checks> */
struct file_listener_settings {
	pool_t pool;
	const char *path;
	const char *type;
	unsigned int mode;
	const char *user;
	const char *group;
};
ARRAY_DEFINE_TYPE(file_listener_settings, struct file_listener_settings *);
struct inet_listener_settings {
	pool_t pool;
	const char *name;
	const char *type;
	in_port_t port;
	/* copied from master_settings: */
	ARRAY_TYPE(const_string) listen;
	bool ssl;
	bool reuse_port;
	bool haproxy;
};
ARRAY_DEFINE_TYPE(inet_listener_settings, struct inet_listener_settings *);
struct service_settings {
	pool_t pool;
	const char *name;
	const char *protocol;
	const char *type;
	const char *executable;
	const char *user;
	const char *group;
	const char *privileged_group;
	ARRAY_TYPE(const_string) extra_groups;
	const char *chroot;

	bool drop_priv_before_exec;

	unsigned int process_min_avail;
	unsigned int process_limit;
	unsigned int client_limit;
	unsigned int restart_request_count;
	unsigned int idle_kill_interval;
	uoff_t vsz_limit;

	ARRAY_TYPE(const_string) unix_listeners;
	ARRAY_TYPE(const_string) fifo_listeners;
	ARRAY_TYPE(const_string) inet_listeners;

	/* internal to master: */
	enum service_type parsed_type;
	enum service_user_default user_default;
	bool login_dump_core:1;

	ARRAY_TYPE(file_listener_settings) parsed_unix_listeners;
	ARRAY_TYPE(file_listener_settings) parsed_fifo_listeners;
	ARRAY_TYPE(inet_listener_settings) parsed_inet_listeners;

	/* -- flags that can be set internally -- */

	/* process_limit must not be higher than 1 */
	bool process_limit_1:1;
};
ARRAY_DEFINE_TYPE(service_settings, struct service_settings *);
/* /home/gromy/Документы/Development/dovecot-core/src/lib-program-client/program-client.h */
struct program_client_settings {
	pool_t pool;
	/* Currently only a single execution is allowed */
	ARRAY_TYPE(const_string) execute;
	const char *execute_name;
	const char *execute_driver;
	const char *execute_args;

	/* driver-specific: */
	const char *execute_fork_path;
	const char *execute_unix_socket_path;
	const char *execute_tcp_host;
	in_port_t execute_tcp_port;

	const char *base_dir;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-smtp/smtp-submit-settings.h */
struct smtp_submit_settings {
	pool_t pool;
	const char *hostname;
	bool mail_debug;

	const char *submission_host;
	const char *sendmail_path;
	unsigned int submission_timeout;

	const char *submission_ssl;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-ssl-iostream/ssl-settings.h */
struct ssl_settings {
	pool_t pool;

	const char *ssl_client_ca_file;
	const char *ssl_client_ca_dir;
	const char *ssl_client_cert_file;
	const char *ssl_client_key_file;
	const char *ssl_client_key_password;

	const char *ssl_cipher_list;
	const char *ssl_cipher_suites;
	const char *ssl_curve_list;
	const char *ssl_min_protocol;
	const char *ssl_crypto_device;
	const char *ssl_options;
	const char *ssl_peer_certificate_fingerprint_hash;

	bool ssl_client_require_valid_cert;

	/* These are derived from ssl_options, not set directly */
	struct {
		bool compression;
		bool tickets;
	} parsed_opts;
};
struct ssl_server_settings {
	pool_t pool;

	const char *ssl;
	const char *ssl_server_ca_file;
	const char *ssl_server_cert_file;
	const char *ssl_server_alt_cert_file;
	const char *ssl_server_key_file;
	const char *ssl_server_alt_key_file;
	const char *ssl_server_key_password;
	const char *ssl_server_dh_file;
	const char *ssl_server_cert_username_field;
	const char *ssl_server_prefer_ciphers;
	const char *ssl_server_request_client_cert;

	bool ssl_server_require_crl;

	/* parsed: */
	struct {
		bool request_client_cert;
		bool verify_client_cert;
	} parsed_opts;
};
/* /home/gromy/Документы/Development/dovecot-core/src/auth/auth-settings.h */
struct auth_passdb_post_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) fields;
};
struct auth_passdb_settings {
	pool_t pool;
	const char *name;
	const char *driver;
	bool fields_import_all;
	ARRAY_TYPE(const_string) mechanisms_filter;
	const char *username_filter;

	const char *default_password_scheme;

	const char *skip;
	const char *result_success;
	const char *result_failure;
	const char *result_internalfail;
	bool deny;
	bool master;
	bool use_cache;
	bool use_worker;
};
struct auth_userdb_post_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) fields;
};
struct auth_userdb_settings {
	pool_t pool;
	const char *name;
	const char *driver;
	bool fields_import_all;

	const char *skip;
	const char *result_success;
	const char *result_failure;
	const char *result_internalfail;

	bool use_cache;
	bool use_worker;
};
struct auth_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) mechanisms;
	ARRAY_TYPE(const_string) realms;
	const char *default_domain;
	uoff_t cache_size;
	unsigned int cache_ttl;
	unsigned int cache_negative_ttl;
	bool cache_verify_password_with_worker;
	const char *username_chars;
	const char *username_translation;
	const char *username_format;
	const char *master_user_separator;
	const char *anonymous_username;
	const char *krb5_keytab;
	const char *gssapi_hostname;
	const char *winbind_helper_path;
	const char *proxy_self;
	unsigned int failure_delay;
	unsigned int internal_failure_delay;

	const char *policy_server_url;
	const char *policy_server_api_header;
	const char *policy_hash_mech;
	const char *policy_hash_nonce;
	bool policy_reject_on_fail;
	bool policy_check_before_auth;
	bool policy_check_after_auth;
	bool policy_report_after_auth;
	bool policy_log_only;
	unsigned int policy_hash_truncate;

	bool verbose, debug, debug_passwords;
	bool allow_weak_schemes;
	const char *verbose_passwords;
	bool ssl_require_client_cert;
	bool ssl_username_from_cert;
	bool use_winbind;

	/* settings that don't have auth_ prefix: */
	ARRAY_TYPE(const_string) passdbs;
	ARRAY_TYPE(const_string) userdbs;

	const char *base_dir;

	bool verbose_proctitle;
	unsigned int first_valid_uid;
	unsigned int last_valid_uid;
	unsigned int first_valid_gid;
	unsigned int last_valid_gid;

	/* generated: */
	ARRAY(const struct auth_passdb_settings *) parsed_passdbs;
	ARRAY(const struct auth_userdb_settings *) parsed_userdbs;
	char username_chars_map[256];
	char username_translation_map[256];
	const struct ip_addr *proxy_self_ips;
};
struct auth_policy_request_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) policy_request_attributes;
};
struct auth_static_settings {
	pool_t pool;
	const char *passdb_static_password;
	bool userdb_static_allow_all_users;
};
/* /home/gromy/Документы/Development/dovecot-core/src/auth/db-ldap-settings.h */
struct ldap_settings {
	pool_t pool;

	const char *uris;

	/* This field prevents ldap_conn_find() from reusing the same
	   connection across stanzas that would otherwise do it.

	   Settings with different connection_group will NOT share the
	   connections, allowing parallel async execution if configured.

	   Note that this field is not explicitly used anywhere, but it
	   affects how ldap_conn_find() compares the settings against an
	   existing connection */
	const char *connection_group;

	const char *auth_dn;
	const char *auth_dn_password;

	ARRAY_TYPE(const_string) auth_sasl_mechanisms;
	const char *auth_sasl_realm;
	const char *auth_sasl_authz_id;

	const char *deref;
	const char *scope;

	unsigned int debug_level;
	unsigned int version;

	uid_t uid;
	gid_t gid;

	bool starttls;

	/* parsed */
	int parsed_deref;
	int parsed_scope;
};
struct ldap_pre_settings {
	pool_t pool;

	/* shared: */
	const char *ldap_base;

	/* passdb: */
	bool passdb_ldap_bind;
	const char *passdb_ldap_filter;
	const char *passdb_ldap_bind_userdn;

	/* userdb: */
	const char *userdb_ldap_filter;
	const char *userdb_ldap_iterate_filter;
};
struct ldap_post_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) iterate_fields;
};
/* /home/gromy/Документы/Development/dovecot-core/src/auth/db-lua.h */
struct auth_lua_settings {
	pool_t pool;
};
/* /home/gromy/Документы/Development/dovecot-core/src/auth/db-oauth2.h */
struct auth_oauth2_settings {
	pool_t pool;
	/* tokeninfo endpoint, format https://endpoint/somewhere?token= */
	const char *tokeninfo_url;
	/* password grant endpoint, format https://endpoint/somewhere */
	const char *grant_url;
	/* introspection endpoint, format https://endpoint/somewhere */
	const char *introspection_url;
	/* expected scope(s), optional */
	ARRAY_TYPE(const_string) scope;
	/* mode of introspection, one of auth, get, post, local
	   - auth: send token with header Authorization: Bearer token
	   - get: append token to url
	   - post: send token=<token> as POST request
	   - local: perform local validation
	*/
	const char *introspection_mode;
	/* normalization var-expand template for username, defaults to %Lu */
	const char *username_validation_format;
	/* name of username attribute to lookup, mandatory */
	const char *username_attribute;
	/* name of account is active attribute, optional */
	const char *active_attribute;
	/* expected active value for active attribute, optional */
	const char *active_value;
	/* client identifier for oauth2 server */
	const char *client_id;
	/* not really used, but have to present by oauth2 specs */
	const char *client_secret;
	/* valid token issuers */
	ARRAY_TYPE(const_string) issuers;
	/* The URL for a document following the OpenID Provider Configuration
	   Information schema, see

	   https://datatracker.ietf.org/doc/html/rfc7628#section-3.2.2
	*/
	const char *openid_configuration_url;

	/* How many seconds after token expiration is it still allowed to
	   succeed the authentication. */
	unsigned int token_expire_grace_secs;

	/* Should introspection be done even if not necessary */
	bool force_introspection;
	/* Should we send service and local/remote endpoints as X-Dovecot-Auth headers */
	bool send_auth_headers;
	bool use_worker_with_mech;
};
struct auth_oauth2_post_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) fields;
};
/* /home/gromy/Документы/Development/dovecot-core/src/auth/db-passwd-file.h */
struct passwd_file_settings {
	pool_t pool;
	const char *passwd_file_path;
};
/* /home/gromy/Документы/Development/dovecot-core/src/dict/dict-settings.h */
struct dict_server_settings {
	pool_t pool;
	const char *base_dir;
	bool verbose_proctitle;
};
/* /home/gromy/Документы/Development/dovecot-core/src/doveadm/doveadm-settings.h */

/* <settings checks> */
enum dsync_features {
	DSYNC_FEATURE_EMPTY_HDR_WORKAROUND = 0x1,
	DSYNC_FEATURE_NO_HEADER_HASHES = 0x2,
};

#define DOVEADM_SERVER_FILTER "doveadm_server"
/* </settings checks> */
struct doveadm_settings {
	pool_t pool;
	const char *base_dir;
	const char *libexec_dir;
	ARRAY_TYPE(const_string) mail_plugins;
	const char *mail_plugin_dir;
	const char *mail_temp_dir;
	bool auth_debug;
	const char *auth_socket_path;
	const char *doveadm_socket_path;
	unsigned int doveadm_worker_count;
	in_port_t doveadm_port;
	const char *doveadm_ssl;
	const char *doveadm_username;
	const char *doveadm_password;
	ARRAY_TYPE(const_string) doveadm_allowed_commands;
	const char *dsync_alt_char;
	const char *dsync_remote_cmd;
	const char *doveadm_api_key;
	const char *dsync_features;
	const char *dsync_hashed_headers;
	unsigned int dsync_commit_msgs_interval;
	enum dsync_features parsed_features;
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap-login/imap-login-settings.h */
struct imap_login_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) imap_capability;
	ARRAY_TYPE(const_string) imap_id_send;
	bool imap_literal_minus;
	bool imap_id_retain;
	bool imap4rev2_enable;
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap-urlauth/imap-urlauth-settings.h */
struct imap_urlauth_settings {
	pool_t pool;
	const char *base_dir;

	bool mail_debug;

	bool verbose_proctitle;

	/* imap_urlauth: */
	const char *imap_urlauth_logout_format;

	const char *imap_urlauth_submit_user;
	const char *imap_urlauth_stream_user;
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap-urlauth/imap-urlauth-worker-settings.h */
struct imap_urlauth_worker_settings {
	pool_t pool;
	bool verbose_proctitle;

	/* imap_urlauth: */
	const char *imap_urlauth_host;
	in_port_t imap_urlauth_port;
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap/imap-settings.h */

/* <settings checks> */
enum imap_client_workarounds {
	WORKAROUND_DELAY_NEWMAIL		= 0x01,
	WORKAROUND_TB_EXTRA_MAILBOX_SEP		= 0x08,
	WORKAROUND_TB_LSUB_FLAGS		= 0x10
};

enum imap_client_fetch_failure {
	IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_IMMEDIATELY,
	IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_AFTER,
	IMAP_CLIENT_FETCH_FAILURE_NO_AFTER,
};
/* </settings checks> */
struct imap_settings {
	pool_t pool;
	bool verbose_proctitle;
	bool mailbox_list_index;
	const char *rawlog_dir;

	/* imap: */
	uoff_t imap_max_line_length;
	unsigned int imap_idle_notify_interval;
	ARRAY_TYPE(const_string) imap_capability;
	ARRAY_TYPE(const_string) imap_client_workarounds;
	const char *imap_logout_format;
	const char *imap_fetch_failure;
	bool imap_metadata;
	bool imap_literal_minus;
	bool imap_compress_on_proxy;
	bool imap4rev2_enable;
	bool mail_utf8_extensions;
	unsigned int imap_hibernate_timeout;
	ARRAY_TYPE(const_string) imap_id_send;

	/* imap urlauth: */
	const char *imap_urlauth_host;
	in_port_t imap_urlauth_port;

	enum imap_client_workarounds parsed_workarounds;
	enum imap_client_fetch_failure parsed_fetch_failure;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict-backend/dict-ldap-settings.h */
struct dict_ldap_map_settings {
	pool_t pool;

	const char *pattern;
	const char *base;
	const char *scope;

	/* parsed */

	ARRAY_TYPE(const_string) parsed_attributes;

	/* attributes sorted by the position in parsed_pattern. */
	ARRAY_TYPE(const_string) parsed_pattern_keys;
	int parsed_scope;

	/* the variables are in the same order as parsed_pattern_keys. */
	const char *parsed_pattern;
};
struct dict_ldap_map_pre_settings {
	pool_t pool;
	const char *filter;
};
struct dict_ldap_map_post_settings {
	pool_t pool;
	const char *value;

	/* parsed */

	/* This is preliminary support for supporting multiple values.
	   For now the array contains only the single value coming
	   from 'value' above. */
	ARRAY_TYPE(const_string) values;
};
struct dict_ldap_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) maps;

	/* parsed */
	ARRAY(const struct dict_ldap_map_settings) parsed_maps;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict-backend/dict-sql-settings.h */
struct dict_map_key_field_settings {
	pool_t pool;

	const char *name;
	const char *type;
	const char *value;
};
struct dict_map_value_field_settings {
	pool_t pool;

	const char *name;
	const char *type;
};
struct dict_map_settings {
	pool_t pool;

	const char *pattern;
	const char *sql_table;
	const char *username_field;
	const char *expire_field;
	ARRAY_TYPE(const_string) fields;
	ARRAY_TYPE(const_string) values;

	ARRAY_TYPE(const_string) maps;
};
struct dict_sql_map_settings {
	pool_t pool;
	ARRAY(struct dict_sql_map) maps;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-imap-client/imapc-settings.h */

/* <settings checks> */
enum imapc_features {
	IMAPC_FEATURE_NO_FETCH_SIZE		= 0x01,
	IMAPC_FEATURE_GUID_FORCED		= 0x02,
	IMAPC_FEATURE_NO_FETCH_HEADERS		= 0x04,
	IMAPC_FEATURE_GMAIL_MIGRATION		= 0x08,
	IMAPC_FEATURE_NO_SEARCH			= 0x10,
	IMAPC_FEATURE_ZIMBRA_WORKAROUNDS	= 0x20,
	IMAPC_FEATURE_NO_EXAMINE		= 0x40,
	IMAPC_FEATURE_PROXYAUTH			= 0x80,
	IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS	= 0x100,
	IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS	= 0x200,
	IMAPC_FEATURE_NO_MODSEQ			= 0x400,
	IMAPC_FEATURE_NO_DELAY_LOGIN		= 0x800,
	IMAPC_FEATURE_NO_FETCH_BODYSTRUCTURE	= 0x1000,
	IMAPC_FEATURE_SEND_ID			= 0x2000,
	IMAPC_FEATURE_FETCH_EMPTY_IS_EXPUNGED	= 0x4000,
	IMAPC_FEATURE_NO_MSN_UPDATES		= 0x8000,
	IMAPC_FEATURE_NO_ACL 			= 0x10000,
	IMAPC_FEATURE_NO_METADATA		= 0x20000,
	IMAPC_FEATURE_NO_QRESYNC		= 0x40000,
	IMAPC_FEATURE_NO_IMAP4REV2		= 0x80000,
};
/* </settings checks> */
#define IMAPC_DEFAULT_MAX_IDLE_TIME (60*29)
struct imapc_settings {
	pool_t pool;
	const char *imapc_host;
	in_port_t imapc_port;

	const char *imapc_user;
	const char *imapc_master_user;
	const char *imapc_password;
	ARRAY_TYPE(const_string) imapc_sasl_mechanisms;

	const char *imapc_ssl;

	ARRAY_TYPE(const_string) imapc_features;
	const char *imapc_rawlog_dir;
	const char *imapc_list_prefix;
	unsigned int imapc_cmd_timeout_secs;
	unsigned int imapc_max_idle_time_secs;
	unsigned int imapc_connection_timeout_interval_msecs;
	unsigned int imapc_connection_retry_count;
	unsigned int imapc_connection_retry_interval_msecs;
	uoff_t imapc_max_line_length;

	const char *pop3_deleted_flag;

	enum imapc_features parsed_features;
	unsigned int throttle_init_msecs;
	unsigned int throttle_max_msecs;
	unsigned int throttle_shrink_min_msecs;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-language/lang-settings.h */

/* <settings checks> */
#define LANGUAGE_DATA "data"
/* </settings checks> */
ARRAY_DEFINE_TYPE(lang_settings, struct lang_settings *);
struct lang_settings {
	pool_t pool;
	const char *name;
	const char *filter_normalizer_icu_id;
	const char *filter_stopwords_dir;
	const char *tokenizer_generic_algorithm;
	ARRAY_TYPE(const_string) filters;
	ARRAY_TYPE(const_string) tokenizers;
	unsigned int tokenizer_address_token_maxlen;
	unsigned int tokenizer_generic_token_maxlen;
	bool tokenizer_generic_explicit_prefix;
	bool tokenizer_generic_wb5a;
	bool is_default;
};
struct langs_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) languages;
	const char *textcat_config_path;

	ARRAY_TYPE(lang_settings) parsed_languages;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-lda/lda-settings.h */
struct lda_settings {
	pool_t pool;
	const char *hostname;
	const char *rejection_subject;
	const char *rejection_reason;
	const char *deliver_log_format;
	const char *recipient_delimiter;
	const char *lda_original_recipient_header;

	bool quota_full_tempfail;
	bool lda_mailbox_autocreate;
	bool lda_mailbox_autosubscribe;

	/* generated */
	bool parsed_want_storage_id;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-ldap/ldap-settings.h */
struct ldap_client_settings {
	pool_t pool;

	const char *uris;
	const char *auth_dn;
	const char *auth_dn_password;

	unsigned int timeout_secs;
	unsigned int max_idle_time_secs;
	unsigned int debug_level;
	bool starttls;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-lua/dlua-script.h */
struct dlua_settings {
	pool_t pool;

	const char *file;
	ARRAY_TYPE(const_string) settings;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-sql/sql-api-private.h */

/* <settings checks> */
/* Minimum delay between reconnecting to same server */
#define SQL_CONNECT_MIN_DELAY 1
/* Maximum time to avoiding reconnecting to same server */
#define SQL_CONNECT_MAX_DELAY (60*30)
/* If no servers are connected but a query is requested, try reconnecting to
   next server which has been disconnected longer than this (with a single
   server setup this is really the "max delay" and the SQL_CONNECT_MAX_DELAY
   is never used). */
#define SQL_CONNECT_RESET_DELAY 15
/* Abort connect() if it can't connect within this time. */
#define SQL_CONNECT_TIMEOUT_SECS 5
/* Abort queries after this many seconds */
#define SQL_QUERY_TIMEOUT_SECS 60
/* Default max. number of connections to create per host */
#define SQL_DEFAULT_CONNECTION_LIMIT 5
/* </settings checks> */
/* /home/gromy/Документы/Development/dovecot-core/src/lib-sql/sql-api.h */
#define SQL_DEF_STRUCT(name, struct_name, type, c_type) \
	{ (type) + COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		((struct struct_name *)0)->name, c_type), \
	  #name, offsetof(struct struct_name, name) }
#define SQL_DEF_STRUCT_STR(name, struct_name) \
	SQL_DEF_STRUCT(name, struct_name, SQL_TYPE_STR, const char *)
#define SQL_DEF_STRUCT_UINT(name, struct_name) \
	SQL_DEF_STRUCT(name, struct_name, SQL_TYPE_UINT, unsigned int)
#define SQL_DEF_STRUCT_ULLONG(name, struct_name) \
	SQL_DEF_STRUCT(name, struct_name, SQL_TYPE_ULLONG, unsigned long long)
#define SQL_DEF_STRUCT_BOOL(name, struct_name) \
	SQL_DEF_STRUCT(name, struct_name, SQL_TYPE_BOOL, bool)
struct sql_settings {
	pool_t pool;
	const char *sql_driver;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/dbox-common/dbox-storage.h */

/* <settings checks> */
#define DBOX_MAILBOX_DIR_NAME "mailboxes"
#define DBOX_MAILDIR_NAME "dbox-Mails"
/* </settings checks> */
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/dbox-multi/mdbox-settings.h */
struct mdbox_settings {
	pool_t pool;
	bool mdbox_preallocate_space;
	uoff_t mdbox_rotate_size;
	unsigned int mdbox_rotate_interval;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/dbox-single/sdbox-settings.h */
struct sdbox_settings {
	pool_t pool;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/maildir/maildir-settings.h */
struct maildir_settings {
	pool_t pool;
	bool maildir_copy_with_hardlinks;
	bool maildir_very_dirty_syncs;
	bool maildir_broken_filename_sizes;
	bool maildir_empty_new;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/mbox/mbox-settings.h */
struct mbox_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) mbox_read_locks;
	ARRAY_TYPE(const_string) mbox_write_locks;
	unsigned int mbox_lock_timeout;
	unsigned int mbox_dotlock_change_timeout;
	uoff_t mbox_min_index_size;
	bool mbox_dirty_syncs;
	bool mbox_very_dirty_syncs;
	bool mbox_lazy_writes;
	const char *mbox_md5;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/pop3c/pop3c-settings.h */

/* <settings checks> */
enum pop3c_features {
	POP3C_FEATURE_NO_PIPELINING = 0x1,
};
/* </settings checks> */
struct pop3c_settings {
	pool_t pool;
	const char *pop3c_host;
	in_port_t pop3c_port;

	const char *pop3c_user;
	const char *pop3c_master_user;
	const char *pop3c_password;

	const char *pop3c_ssl;
	bool pop3c_ssl_verify;

	const char *pop3c_rawlog_dir;
	bool pop3c_quick_received_date;

	ARRAY_TYPE(const_string) pop3c_features;
	enum pop3c_features parsed_features;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/mail-storage-settings.h */

/* <settings checks> */
#define MAILBOX_SET_AUTO_NO "no"
#define MAILBOX_SET_AUTO_CREATE "create"
#define MAILBOX_SET_AUTO_SUBSCRIBE "subscribe"
/* </settings checks> */
struct mail_driver_settings {
	pool_t pool;
	const char *mail_driver;
};
struct mailbox_list_layout_settings {
	pool_t pool;
	const char *mailbox_list_layout;
};
struct mail_storage_settings {
	pool_t pool;
	const char *mail_driver;
	const char *mail_ext_attachment_path;
	const char *mail_ext_attachment_hash;
	uoff_t mail_ext_attachment_min_size;
	unsigned int mail_prefetch_count;
	ARRAY_TYPE(const_string) mail_cache_fields;
	ARRAY_TYPE(const_string) mail_always_cache_fields;
	ARRAY_TYPE(const_string) mail_never_cache_fields;
	const char *mail_server_comment;
	const char *mail_server_admin;
	unsigned int mail_cache_min_mail_count;
	unsigned int mail_cache_unaccessed_field_drop;
	uoff_t mail_cache_record_max_size;
	unsigned int mail_cache_max_header_name_length;
	unsigned int mail_cache_max_headers_count;
	uoff_t mail_cache_max_size;
	uoff_t mail_cache_purge_min_size;
	unsigned int mail_cache_purge_delete_percentage;
	unsigned int mail_cache_purge_continued_percentage;
	unsigned int mail_cache_purge_header_continue_count;
	uoff_t mail_index_rewrite_min_log_bytes;
	uoff_t mail_index_rewrite_max_log_bytes;
	uoff_t mail_index_log_rotate_min_size;
	uoff_t mail_index_log_rotate_max_size;
	unsigned int mail_index_log_rotate_min_age;
	unsigned int mail_index_log2_max_age;
	unsigned int mailbox_idle_check_interval;
	unsigned int mail_max_keyword_length;
	unsigned int mail_max_lock_timeout;
	unsigned int mail_temp_scan_interval;
	unsigned int mail_vsize_bg_after_count;
	unsigned int mail_sort_max_read_count;
	bool mail_save_crlf;
	const char *mail_fsync;
	bool mmap_disable;
	bool dotlock_use_excl;
	bool mail_nfs_storage;
	bool mail_nfs_index;
	bool mailbox_list_index;
	bool mailbox_list_index_very_dirty_syncs;
	bool mailbox_list_index_include_inbox;
	const char *mailbox_list_layout;
	const char *mailbox_list_index_prefix;
	bool mailbox_list_iter_from_index_dir;
	bool mailbox_list_drop_noselect;
	bool mailbox_list_validate_fs_names;
	bool mailbox_list_utf8;
	const char *mailbox_list_visible_escape_char;
	const char *mailbox_list_storage_escape_char;
	const char *mailbox_list_lost_mailbox_prefix;
	const char *mailbox_directory_name;
	bool mailbox_directory_name_legacy;
	const char *mailbox_root_directory_name;
	const char *mailbox_subscriptions_filename;
	const char *mail_path;
	const char *mail_inbox_path;
	const char *mail_index_path;
	const char *mail_index_private_path;
	const char *mail_cache_path;
	const char *mail_control_path;
	const char *mail_volatile_path;
	const char *mail_alt_path;
	bool mail_alt_check;
	bool mail_full_filesystem_access;
	bool maildir_stat_dirs;
	bool mail_shared_explicit_inbox;
	const char *lock_method;
	const char *pop3_uidl_format;

	const char *recipient_delimiter;

	ARRAY_TYPE(const_string) mail_attachment_detection_options;

	enum file_lock_method parsed_lock_method;
	enum fsync_mode parsed_fsync_mode;

	const char *const *parsed_mail_attachment_content_type_filter;
	bool parsed_mail_attachment_exclude_inlined;
	bool parsed_mail_attachment_detection_add_flags;
	bool parsed_mail_attachment_detection_no_flags_on_fetch;
	/* Filename part of mailbox_list_index_prefix */
	const char *parsed_list_index_fname;
	/* Directory part of mailbox_list_index_prefix. NULL defaults to index
	   directory. The path may be relative to the index directory. */
	const char *parsed_list_index_dir;
	/* If set, store mailboxes under root_dir/mailbox_dir_name/.
	   This setting contains either "" or "dir/" with trailing "/". */
	const char *parsed_mailbox_root_directory_prefix;

	const char *unexpanded_mailbox_list_path[MAILBOX_LIST_PATH_TYPE_COUNT];
	bool unexpanded_mailbox_list_override[MAILBOX_LIST_PATH_TYPE_COUNT];
};
struct mail_namespace_settings {
	pool_t pool;
	const char *name;
	const char *type;
	const char *separator;
	const char *prefix;
	const char *alias_for;

	bool inbox;
	bool hidden;
	const char *list;
	bool subscriptions;
	bool ignore_on_failure;
	bool disabled;
	unsigned int order;

	/* List of mailbox filter names */
	ARRAY_TYPE(const_string) mailboxes;
	/* mailbox_settings of each configured mailbox in the namespace. */
	ARRAY(const struct mailbox_settings *) parsed_mailboxes;
	bool parsed_have_special_use_mailboxes;
};
struct mailbox_settings {
	pool_t pool;
	const char *name;
	const char *autocreate;
	ARRAY_TYPE(const_string) special_use;
	const char *comment;
	unsigned int autoexpunge;
	unsigned int autoexpunge_max_mails;
};
struct mail_user_settings {
	pool_t pool;
	const char *base_dir;
	const char *auth_socket_path;
	const char *mail_temp_dir;
	bool mail_debug;

	const char *mail_uid;
	const char *mail_gid;
	const char *mail_home;
	const char *mail_chroot;
	ARRAY_TYPE(const_string) mail_access_groups;
	const char *mail_privileged_group;
	ARRAY_TYPE(const_string) valid_chroot_dirs;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	ARRAY_TYPE(const_string) mail_plugins;
	const char *mail_plugin_dir;

	const char *mail_log_prefix;

	ARRAY_TYPE(const_string) namespaces;
	const char *hostname;
	const char *postmaster_address;

	/* May be NULL - use mail_storage_get_postmaster_address() instead of
	   directly accessing this. */
	const struct message_address *_parsed_postmaster_address;
	const struct smtp_address *_parsed_postmaster_address_smtp;
	const char *unexpanded_mail_log_prefix;
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/mail-storage.h */

/* <settings checks> */
/* The "namespace" event field contains the namespace containing mailbox.
   For dynamic namespaces, the name is the one specified in configuration
   for the template namespace. */
#define SETTINGS_EVENT_NAMESPACE_NAME "namespace"
/* </settings checks> */
/* /home/gromy/Документы/Development/dovecot-core/src/lmtp/lmtp-settings.h */

/* <settings checks> */
enum lmtp_hdr_delivery_address {
	LMTP_HDR_DELIVERY_ADDRESS_NONE,
	LMTP_HDR_DELIVERY_ADDRESS_FINAL,
	LMTP_HDR_DELIVERY_ADDRESS_ORIGINAL
};

enum lmtp_client_workarounds {
	LMTP_WORKAROUND_WHITESPACE_BEFORE_PATH	= BIT(0),
	LMTP_WORKAROUND_MAILBOX_FOR_PATH	= BIT(1),
};
/* </settings checks> */
struct lmtp_pre_mail_settings {
	pool_t pool;
	unsigned int mail_max_lock_timeout;
};
struct lmtp_settings {
	pool_t pool;
	bool lmtp_proxy;
	bool lmtp_save_to_detail_mailbox;
	bool lmtp_rcpt_check_quota;
	bool lmtp_add_received_header;
	bool lmtp_verbose_replies;
	bool mail_utf8_extensions;
	unsigned int lmtp_user_concurrency_limit;
	const char *lmtp_hdr_delivery_address;
	const char *lmtp_rawlog_dir;
	const char *lmtp_proxy_rawlog_dir;

	ARRAY_TYPE(const_string) lmtp_client_workarounds;

	const char *login_greeting;
	ARRAY_TYPE(const_string) login_trusted_networks;

	ARRAY_TYPE(const_string) mail_plugins;
	const char *mail_plugin_dir;

	enum lmtp_hdr_delivery_address parsed_lmtp_hdr_delivery_address;

	enum lmtp_client_workarounds parsed_workarounds;
};
/* /home/gromy/Документы/Development/dovecot-core/src/login-common/login-settings.h */
struct login_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) login_trusted_networks;
	ARRAY_TYPE(const_string) login_source_ips;
	const char *login_greeting;
	const char *login_log_format_elements, *login_log_format;
	const char *login_access_sockets;
	const char *login_proxy_notify_path;
	const char *login_plugin_dir;
	ARRAY_TYPE(const_string) login_plugins;
	unsigned int login_proxy_timeout;
	unsigned int login_proxy_max_reconnects;
	unsigned int login_proxy_max_disconnect_delay;
	const char *login_proxy_rawlog_dir;
	const char *login_socket_path;
	const char *ssl; /* for settings check */

	bool auth_ssl_require_client_cert;
	bool auth_ssl_username_from_cert;

	bool auth_allow_cleartext;
	bool auth_verbose;
	bool auth_debug;
	bool auth_debug_passwords;
	bool verbose_proctitle;

	unsigned int mail_max_userip_connections;

	/* generated: */
	char *const *log_format_elements_split;
};
/* /home/gromy/Документы/Development/dovecot-core/src/master/master-settings.h */
struct master_settings {
	pool_t pool;
	const char *base_dir;
	const char *state_dir;
	const char *libexec_dir;
	const char *instance_name;
	ARRAY_TYPE(const_string) protocols;
	ARRAY_TYPE(const_string) listen;
	const char *ssl;
	const char *default_internal_user;
	const char *default_internal_group;
	const char *default_login_user;
	unsigned int default_process_limit;
	unsigned int default_client_limit;
	unsigned int default_idle_kill_interval;
	uoff_t default_vsz_limit;

	bool version_ignore;

	unsigned int first_valid_uid, last_valid_uid;
	unsigned int first_valid_gid, last_valid_gid;

	ARRAY_TYPE(const_string) services;

	ARRAY_TYPE(service_settings) parsed_services;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/acl/acl-rights.h */

/* <settings checks> */

/* Show mailbox in mailbox list. Allow subscribing to it. */
#define MAIL_ACL_LOOKUP		"lookup"
/* Allow opening mailbox for reading */
#define MAIL_ACL_READ		"read"
/* Allow permanent flag changes (except for seen/deleted).
   If not set, doesn't allow save/copy to set any flags either. */
#define MAIL_ACL_WRITE		"write"
/* Allow permanent seen-flag changes */
#define MAIL_ACL_WRITE_SEEN	"write-seen"
/* Allow permanent deleted-flag changes */
#define MAIL_ACL_WRITE_DELETED	"write-deleted"
/* Allow saving and copying mails into the mailbox */
#define MAIL_ACL_INSERT		"insert"
/* Allow posting mails to the mailbox (e.g. Sieve fileinto) */
#define MAIL_ACL_POST		"post"
/* Allow expunging mails */
#define MAIL_ACL_EXPUNGE	"expunge"
/* Allow creating child mailboxes */
#define MAIL_ACL_CREATE		"create"
/* Allow deleting this mailbox */
#define MAIL_ACL_DELETE		"delete"
/* Allow changing ACL state in this mailbox */
#define MAIL_ACL_ADMIN		"admin"

#define ACL_ID_NAME_ANYONE "anyone"
#define ACL_ID_NAME_AUTHENTICATED "authenticated"
#define ACL_ID_NAME_OWNER "owner"
#define ACL_ID_NAME_USER_PREFIX "user="
#define ACL_ID_NAME_GROUP_PREFIX "group="
#define ACL_ID_NAME_GROUP_OVERRIDE_PREFIX "group-override="

struct acl_letter_map {
	const char letter;
	const char *name;
};

extern const struct acl_letter_map acl_letter_map[];
extern const char *const all_mailbox_rights[];

/* ACL identifiers in override order */
enum acl_id_type {
	/* Anyone's rights, including anonymous's.
	   identifier name is ignored. */
	ACL_ID_ANYONE,
	/* Authenticate users' rights. identifier name is ignored. */
	ACL_ID_AUTHENTICATED,
	/* Group's rights */
	ACL_ID_GROUP,
	/* Owner's rights, used when user is the storage's owner.
	   identifier name is ignored. */
	ACL_ID_OWNER,
	/* User's rights */
	ACL_ID_USER,
	/* Same as group's rights, but also overrides user's rights */
	ACL_ID_GROUP_OVERRIDE,

	ACL_ID_TYPE_COUNT
};

enum acl_modify_mode {
	/* Remove rights from existing ACL */
	ACL_MODIFY_MODE_REMOVE = 0,
	/* Add rights to existing ACL (or create a new one) */
	ACL_MODIFY_MODE_ADD,
	/* Replace existing ACL with given rights */
	ACL_MODIFY_MODE_REPLACE,
	/* Clear all the rights from an existing ACL */
	ACL_MODIFY_MODE_CLEAR
};

struct acl_rights {
	/* Type of the identifier, user/group */
	enum acl_id_type id_type;
	/* Identifier, eg. username / group name */
	const char *identifier;

	/* Rights assigned. NULL entry can be ignored, but { NULL } means user
	   has no rights. */
	const char *const *rights;
	/* Negative rights assigned */
	const char *const *neg_rights;

	/* These rights are global for all users */
	bool global:1;
};
ARRAY_DEFINE_TYPE(acl_rights, struct acl_rights);

/* </settings checks> */

/* <settings checks> */
/* Parses identifier from line */
int acl_identifier_parse(const char *line, struct acl_rights *rights);
/* </settings checks> */

/* <settings checks> */
/* Parses line containing identifier and rights */
int acl_rights_parse_line(const char *line, pool_t pool,
			  struct acl_rights *rights_r, const char **error_r);
/* </settings checks> */

/* <settings checks> */
/* Parses acl letter string to names */
const char *const *
acl_right_names_parse(pool_t pool, const char *acl, const char **error_r);
/* </settings checks> */
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/acl/acl-settings.h */
#define ACL_DEFAULT_CACHE_TTL_SECS 30
struct acl_rights_settings {
	pool_t pool;
	const char *id;
	const char *rights;

	struct acl_rights *parsed;
};
ARRAY_DEFINE_TYPE(acl_rights_setting, struct acl_rights_settings);
struct acl_settings {
	pool_t pool;
	const char *acl_user;
	ARRAY_TYPE(const_string) acl_groups;
	ARRAY_TYPE(const_string) acl_rights;
	const char *acl_driver;
	const char *acl_global_path;
	unsigned int acl_cache_ttl;
	bool acl_globals_only;
	bool acl_defaults_from_inbox;
	bool acl_ignore;
	bool acl_dict_index;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/fts-flatcurve/fts-flatcurve-settings.h */

/* <settings checks> */
#define FTS_FLATCURVE_FILTER "fts_flatcurve"
/* </settings checks> */
struct fts_flatcurve_settings {
	pool_t pool;
	unsigned int commit_limit;
	unsigned int min_term_size;
	unsigned int optimize_limit;
	unsigned int rotate_count;
	unsigned int rotate_time;
	bool substring_search;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/fts-solr/fts-solr-settings.h */

/* <settings checks> */
#define FTS_SOLR_FILTER "fts_solr"
/* </settings checks> */
struct fts_solr_settings {
	pool_t pool;
	const char *url;
	unsigned int batch_size;
	bool soft_commit;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/fts/fts-settings.h */

/* <settings checks> */
#define FTS_FILTER		"fts"
#define FTS_FILTER_DECODER_TIKA	"fts_decoder_tika"

enum fts_decoder {
	FTS_DECODER_NO,
	FTS_DECODER_TIKA,
	FTS_DECODER_SCRIPT,
};
/* </settings checks> */
struct fts_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) fts;
	ARRAY_TYPE(const_string) header_excludes;
	ARRAY_TYPE(const_string) header_includes;
	const char *decoder_driver;
	const char *decoder_script_socket_path;
	const char *decoder_tika_url;
	const char *driver;
	bool search;
	const char *search_add_missing;
	bool search_read_fallback;
	unsigned int autoindex_max_recent_msgs;
	unsigned int search_timeout;
	uoff_t message_max_size;
	bool autoindex;

	enum fts_decoder parsed_decoder_driver;
	bool parsed_search_add_missing_body_only;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/lazy-expunge/lazy-expunge-plugin.h */
struct lazy_expunge_settings {
	pool_t pool;

	bool lazy_expunge_only_last_instance;
	const char *lazy_expunge_mailbox;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/mail-compress/mail-compress-plugin.h */
struct mail_compress_settings {
	pool_t pool;
	const char *mail_compress_write_method;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/mail-crypt/crypt-settings.h */
struct crypt_private_key_settings {
	pool_t pool;

	const char *crypt_private_key_name;
	const char *crypt_private_key_file;
	const char *crypt_private_key_password;
};
struct crypt_settings {
	pool_t pool;

	bool fs_crypt_read_plain_fallback;

	const char *crypt_global_public_key_file;
	ARRAY_TYPE(const_string) crypt_global_private_keys;

	const char *crypt_write_algorithm;

	/* for user-specific keys: */
	ARRAY_TYPE(const_string) crypt_user_key_encryption_keys;
	const char *crypt_user_key_password;
	const char *crypt_user_key_curve; /* for generating new user keys */
	bool crypt_user_key_require_encrypted;
};
struct crypt_acl_settings {
	pool_t pool;
	bool crypt_acl_require_secure_key_sharing;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/mail-lua/mail-lua-settings.h */

/* <settings checks> */
#define MAIL_LUA_FILTER "mail_lua"
/* </settings checks> */
struct mail_lua_settings {
	pool_t pool;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/push-notification/push-notification-settings.h */

/* <settings checks> */
#define PUSH_NOTIFICATION_SETTINGS_FILTER_NAME "push_notification"
/* </settings checks> */
struct push_notification_lua_settings {
	pool_t pool;

	const char *path;
};
struct push_notification_ox_settings {
	pool_t pool;

	const char *url;
	unsigned int cache_ttl;
	bool user_from_metadata;

	/* Generated: */
	struct http_url *parsed_url;
};
struct push_notification_settings {
	pool_t pool;
	const char *name;
	const char *driver;

	ARRAY_TYPE(const_string) push_notifications;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/quota-clone/quota-clone-settings.h */
struct quota_clone_settings {
	pool_t      pool;
	bool        unset;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/quota/quota-settings.h */

/* <settings checks> */
#define QUOTA_WARNING_RESOURCE_STORAGE "storage"
#define QUOTA_WARNING_RESOURCE_MESSAGE "message"

#define QUOTA_WARNING_THRESHOLD_OVER "over"
#define QUOTA_WARNING_THRESHOLD_UNDER "under"
/* </settings checks> */
struct quota_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) quota_roots;

	/* Globals: */

	unsigned int quota_mailbox_count;
	uoff_t quota_mail_size;
	unsigned int quota_mailbox_message_count;
	const char *quota_exceeded_message;
};
struct quota_root_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) quota_warnings;

	/* Client-visible name of the quota root */
	const char *quota_name;
	const char *quota_driver;
	/* If TRUE, quota is not tracked at all (for this mailbox). This is
	   typically set only for specific mailboxes or namespaces. Note that
	   this differs from unlimited quota, which still tracks the quota,
	   even if it is not enforced. */
	bool quota_ignore;
	/* IF TRUE, quota is ignored only when quota is unlimited. */
	bool quota_ignore_unlimited;
	/* Whether to actually enforce quota limits. */
	bool quota_enforce;
	/* Quota root is hidden (to e.g. IMAP GETQUOTAROOT) */
	bool quota_hidden;
	/* Quota storage size is counted as:
	   quota_storage_size * quota_storage_percentage / 100 +
	   quota_storage_extra. */
	uoff_t quota_storage_size;
	unsigned int quota_storage_percentage;
	uoff_t quota_storage_extra;
	/* If user is under quota before saving a mail, allow the last mail to
	   bring the user over quota by this many bytes. This is only used for
	   mail delivery sessions (lda, lmtp). */
	uoff_t quota_storage_grace;
	/* Quota messages count is counted as:
	   quota_message_count * quota_message_percentage / 100. */
	unsigned int quota_message_count;
	unsigned int quota_message_percentage;

	/* For quota warnings: */

	/* Name for the warning. This is only for identification in the
	   configuration. */
	const char *quota_warning_name;
	/* Specifies the quota resource the warning tracks
	   (storage / message) */
	const char *quota_warning_resource;
	/* Specifies whether the warning is executed when going over the limit
	   or back under the limit. */
	const char *quota_warning_threshold;

	/* For quota_over_status: */

	bool quota_over_status_lazy_check;
	const char *quota_over_status_current;
	const char *quota_over_status_mask;

	/* Generated: */

	const struct quota_backend *backend;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/quota/quota-status-settings.h */
struct quota_status_settings {
	pool_t pool;
	const char *recipient_delimiter;
	const char *quota_status_nouser;
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/virtual/virtual-settings.h */
struct virtual_settings {
	pool_t pool;

	unsigned int virtual_max_open_mailboxes;
};
/* /home/gromy/Документы/Development/dovecot-core/src/pop3/pop3-settings.h */

/* <settings checks> */
enum pop3_client_workarounds {
	WORKAROUND_OUTLOOK_NO_NULS		= 0x01,
	WORKAROUND_OE_NS_EOH			= 0x02
};
enum pop3_delete_type {
	POP3_DELETE_TYPE_EXPUNGE = 0,
	POP3_DELETE_TYPE_FLAG,
};
/* </settings checks> */
struct pop3_settings {
	pool_t pool;
	bool verbose_proctitle;
	const char *rawlog_dir;

	/* pop3: */
	bool pop3_no_flag_updates;
	bool pop3_enable_last;
	bool pop3_reuse_xuidl;
	bool pop3_save_uidl;
	bool pop3_lock_session;
	bool pop3_fast_size_lookups;
	ARRAY_TYPE(const_string) pop3_client_workarounds;
	const char *pop3_logout_format;
	const char *pop3_uidl_duplicates;
	const char *pop3_deleted_flag;
	const char *pop3_delete_type;

	enum pop3_client_workarounds parsed_workarounds;
	enum pop3_delete_type parsed_delete_type;
	bool parsed_want_uidl_change;
};
/* /home/gromy/Документы/Development/dovecot-core/src/stats/stats-settings.h */

/* <settings checks> */
#define STATS_SERVER_FILTER "stats_server"

/*
 * We allow a selection of a timestamp format.
 *
 * The 'time-unix' format generates a number with the number of seconds
 * since 1970-01-01 00:00 UTC.
 *
 * The 'time-rfc3339' format uses the YYYY-MM-DDTHH:MM:SS.uuuuuuZ format as
 * defined by RFC 3339.
 *
 * The special native format (not explicitly selectable in the config, but
 * default if no time-* token is used) uses the format's native timestamp
 * format.  Note that not all formats have a timestamp data format.
 *
 * The native format and the rules below try to address the question: can a
 * parser that doesn't have any knowledge of fields' values' types losslessly
 * reconstruct the fields?
 *
 * For example, JSON only has strings and numbers, so it cannot represent a
 * timestamp in a "context-free lossless" way.  Therefore, when making a
 * JSON blob, we need to decide which way to serialize timestamps.  No
 * matter how we do it, we incur some loss.  If a decoder sees 1557232304 in
 * a field, it cannot be certain if the field is an integer that just
 * happens to be a reasonable timestamp, or if it actually is a timestamp.
 * Same goes with RFC3339 - it could just be that the user supplied a string
 * that looks like a timestamp, and that string made it into an event field.
 *
 * Other common serialization formats, such as CBOR, have a lossless way of
 * encoding timestamps.
 *
 * Note that there are two concepts at play: native and default.
 *
 * The rules for how the format's timestamp formats are used:
 *
 * 1. The default time format is the native format.
 * 2. The native time format may or may not exist for a given format (e.g.,
 *    in JSON)
 * 3. If the native format doesn't exist and no time format was specified in
 *    the config, it is a config error.
 *
 * We went with these rules because:
 *
 * 1. It prevents type information loss by default.
 * 2. It completely isolates the policy from the algorithm.
 * 3. It defers the decision whether each format without a native timestamp
 *    type should have a default acting as native until after we've had some
 *    operational experience.
 * 4. A future decision to add a default (via 3. point) will be 100% compatible.
 */
enum event_exporter_time_fmt {
	EVENT_EXPORTER_TIME_FMT_NATIVE = 0,
	EVENT_EXPORTER_TIME_FMT_UNIX,
	EVENT_EXPORTER_TIME_FMT_RFC3339,
};
/* </settings checks> */

/* <settings checks> */
enum stats_metric_group_by_func {
	STATS_METRIC_GROUPBY_DISCRETE = 0,
	STATS_METRIC_GROUPBY_QUANTIZED,
};

/*
 * A range covering a stats bucket.  The the interval is half closed - the
 * minimum is excluded and the maximum is included.  In other words: (min, max].
 * Because we don't have a +Inf and -Inf, we use INTMAX_MIN and INTMAX_MAX
 * respectively.
 */
struct stats_metric_settings_bucket_range {
	intmax_t min;
	intmax_t max;
};

struct stats_metric_settings_group_by {
	const char *field;
	enum stats_metric_group_by_func func;
	const char *discrete_modifier;
	unsigned int num_ranges;
	struct stats_metric_settings_bucket_range *ranges;
};
ARRAY_DEFINE_TYPE(stats_metric_settings_group_by,
		  struct stats_metric_settings_group_by);
/* </settings checks> */
#define STATS_METRIC_SETTINGS_DEFAULT_EXPORTER_INCLUDE \
	"name hostname timestamps categories fields"
struct stats_exporter_settings {
	pool_t pool;

	const char *name;
	const char *driver;
	const char *format;
	const char *time_format;

	/* parsed values */
	enum event_exporter_time_fmt parsed_time_format;
};
struct stats_metric_group_by_settings {
	pool_t pool;
	const char *field;
	ARRAY_TYPE(const_string) method;
};
struct stats_metric_group_by_method_settings {
	pool_t pool;

	const char *method;

	const char *discrete_modifier;

	unsigned int exponential_min_magnitude;
	unsigned int exponential_max_magnitude;
	unsigned int exponential_base;

	uintmax_t linear_min;
	uintmax_t linear_max;
	uintmax_t linear_step;
};
struct stats_metric_settings {
	pool_t pool;

	const char *name;
	const char *description;
	ARRAY_TYPE(const_string) fields;
	ARRAY_TYPE(const_string) group_by;
	const char *filter;

	struct event_filter *parsed_filter;

	/* exporter related fields */
	const char *exporter;
	ARRAY_TYPE(const_string) exporter_include;
};
struct stats_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) exporters;
	ARRAY_TYPE(const_string) metrics;
};
/* /home/gromy/Документы/Development/dovecot-core/src/submission-login/submission-login-settings.h */

/* <settings checks> */
enum submission_login_client_workarounds {
	SUBMISSION_LOGIN_WORKAROUND_IMPLICIT_AUTH_EXTERNAL	= BIT(0),
	SUBMISSION_LOGIN_WORKAROUND_EXOTIC_BACKEND		= BIT(1),
};
/* </settings checks> */
struct submission_login_settings {
	pool_t pool;
	const char *hostname;
	bool mail_utf8_extensions;

	/* submission: */
	uoff_t submission_max_mail_size;
	ARRAY_TYPE(const_string) submission_client_workarounds;
	ARRAY_TYPE(const_string) submission_backend_capabilities;

	enum submission_login_client_workarounds parsed_workarounds;
};
/* /home/gromy/Документы/Development/dovecot-core/src/submission/submission-settings.h */

/* <settings checks> */
enum submission_client_workarounds {
	SUBMISSION_WORKAROUND_WHITESPACE_BEFORE_PATH	= BIT(0),
	SUBMISSION_WORKAROUND_MAILBOX_FOR_PATH		= BIT(1),
};
/* </settings checks> */
struct submission_settings {
	pool_t pool;
	bool verbose_proctitle;
	const char *rawlog_dir;

	const char *hostname;

	const char *login_greeting;
	ARRAY_TYPE(const_string) login_trusted_networks;

	const char *recipient_delimiter;

	/* submission: */
	uoff_t submission_max_mail_size;
	unsigned int submission_max_recipients;
	ARRAY_TYPE(const_string) submission_client_workarounds;
	const char *submission_logout_format;
	bool submission_add_received_header;
	bool mail_utf8_extensions;

	/* submission backend: */
	ARRAY_TYPE(const_string) submission_backend_capabilities;

	/* submission relay: */
	const char *submission_relay_host;
	in_port_t submission_relay_port;
	bool submission_relay_trusted;

	const char *submission_relay_user;
	const char *submission_relay_master_user;
	const char *submission_relay_password;

	const char *submission_relay_ssl;
	bool submission_relay_ssl_verify;

	const char *submission_relay_rawlog_dir;
	unsigned int submission_relay_max_idle_time;

	unsigned int submission_relay_connect_timeout;
	unsigned int submission_relay_command_timeout;

	/* imap urlauth: */
	const char *imap_urlauth_host;
	in_port_t imap_urlauth_port;

	enum submission_client_workarounds parsed_workarounds;
};
/* /home/gromy/Документы/Development/dovecot-core/src/anvil/anvil-settings.c */
struct service_settings anvil_service_settings = {
	.name = "anvil",
	.protocol = "",
	.type = "anvil",
	.executable = "anvil",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 1,
	.process_limit = 1,
	.idle_kill_interval = SET_TIME_INFINITE,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
const struct setting_keyvalue anvil_service_settings_defaults[] = {
	{ "unix_listener", "anvil anvil-auth-penalty" },

	{ "unix_listener/anvil/path", "anvil" },
	{ "unix_listener/anvil/mode", "0660" },
	{ "unix_listener/anvil/group", "$SET:default_internal_group" },

	{ "unix_listener/anvil-auth-penalty/path", "anvil-auth-penalty" },
#ifdef DOVECOT_PRO_EDITION
	/* Should use OX Abuse Shield instead */
	{ "unix_listener/anvil-auth-penalty/mode", "0" },
#else
	{ "unix_listener/anvil-auth-penalty/mode", "0600" },
#endif

	{ NULL, NULL }
};
/* /home/gromy/Документы/Development/dovecot-core/src/auth/auth-settings.c */
extern const struct setting_parser_info auth_passdb_setting_parser_info;
extern const struct setting_parser_info auth_passdb_post_setting_parser_info;
extern const struct setting_parser_info auth_userdb_setting_parser_info;
extern const struct setting_parser_info auth_userdb_post_setting_parser_info;
extern const struct setting_parser_info auth_static_setting_parser_info;
extern const struct setting_parser_info auth_setting_parser_info;
extern const struct setting_parser_info auth_policy_request_setting_parser_info;

/* <settings checks> */
static bool
auth_settings_set_self_ips(struct auth_settings *set, pool_t pool,
			   const char **error_r)
{
	const char *const *tmp;
	ARRAY(struct ip_addr) ips_array;
	struct ip_addr *ips;
	unsigned int ips_count;
	int ret;

	if (*set->proxy_self == '\0') {
		set->proxy_self_ips = p_new(pool, struct ip_addr, 1);
		return TRUE;
	}

	p_array_init(&ips_array, pool, 4);
	tmp = t_strsplit_spaces(set->proxy_self, " ");
	for (; *tmp != NULL; tmp++) {
		ret = net_gethostbyname(*tmp, &ips, &ips_count);
		if (ret != 0) {
			*error_r = t_strdup_printf("auth_proxy_self_ips: "
				"gethostbyname(%s) failed: %s",
				*tmp, net_gethosterror(ret));
		}
		array_append(&ips_array, ips, ips_count);
	}
	array_append_zero(&ips_array);
	set->proxy_self_ips = array_front(&ips_array);
	return TRUE;
}

static bool
auth_verify_verbose_password(struct auth_settings *set,
			     const char **error_r)
{
	const char *p, *value = set->verbose_passwords;
	unsigned int num;

	p = strchr(value, ':');
	if (p != NULL) {
		if (str_to_uint(p+1, &num) < 0 || num == 0) {
			*error_r = t_strdup_printf("auth_verbose_passwords: "
				"Invalid truncation number: '%s'", p+1);
			return FALSE;
		}
		value = t_strdup_until(value, p);
	}
	if (strcmp(value, "no") == 0)
		return TRUE;
	else if (strcmp(value, "plain") == 0)
		return TRUE;
	else if (strcmp(value, "sha1") == 0)
		return TRUE;
	else if (strcmp(value, "yes") == 0) {
		/* just use it as alias for "plain" */
		set->verbose_passwords = "plain";
		return TRUE;
	} else {
		*error_r = "auth_verbose_passwords: Invalid value";
		return FALSE;
	}
}

static bool
auth_settings_get_passdbs(struct auth_settings *set, pool_t pool,
			  struct event *event, const char **error_r)
{
	const struct auth_passdb_settings *passdb_set;
	const char *passdb_name, *error;

	if (!array_is_created(&set->passdbs))
		return TRUE;

	p_array_init(&set->parsed_passdbs, pool, array_count(&set->passdbs));
	array_foreach_elem(&set->passdbs, passdb_name) {
		if (settings_get_filter(event, "passdb", passdb_name,
					&auth_passdb_setting_parser_info,
					0, &passdb_set, &error) < 0) {
			*error_r = t_strdup_printf("Failed to get passdb %s: %s",
						   passdb_name, error);
			return FALSE;
		}

		pool_add_external_ref(pool, passdb_set->pool);
		array_push_back(&set->parsed_passdbs, &passdb_set);
		settings_free(passdb_set);
	}
	return TRUE;
}

static bool
auth_settings_get_userdbs(struct auth_settings *set, pool_t pool,
			  struct event *event, const char **error_r)
{
	const struct auth_userdb_settings *userdb_set;
	const char *userdb_name, *error;

	if (!array_is_created(&set->userdbs))
		return TRUE;

	p_array_init(&set->parsed_userdbs, pool, array_count(&set->userdbs));
	array_foreach_elem(&set->userdbs, userdb_name) {
		if (settings_get_filter(event, "userdb", userdb_name,
					&auth_userdb_setting_parser_info,
					0, &userdb_set, &error) < 0) {
			*error_r = t_strdup_printf("Failed to get userdb %s: %s",
						   userdb_name, error);
			return FALSE;
		}

		pool_add_external_ref(pool, userdb_set->pool);
		array_push_back(&set->parsed_userdbs, &userdb_set);
		settings_free(userdb_set);
	}
	return TRUE;
}

static bool auth_settings_ext_check(struct event *event, void *_set,
				    pool_t pool, const char **error_r)
{
	struct auth_settings *set = _set;
	const char *p;

	if (set->debug_passwords)
		set->debug = TRUE;
	if (set->debug)
		set->verbose = TRUE;

	if (set->cache_size > 0 && set->cache_size < 1024) {
		/* probably a configuration error.
		   older versions used megabyte numbers */
		*error_r = t_strdup_printf("auth_cache_size value is too small "
					   "(%"PRIuUOFF_T" bytes)",
					   set->cache_size);
		return FALSE;
	}

	if (!auth_verify_verbose_password(set, error_r))
		return FALSE;

	if (*set->username_chars == '\0') {
		/* all chars are allowed */
		memset(set->username_chars_map, 1,
		       sizeof(set->username_chars_map));
	} else {
		for (p = set->username_chars; *p != '\0'; p++)
			set->username_chars_map[(int)(uint8_t)*p] = 1;
	}

	if (*set->username_translation != '\0') {
		p = set->username_translation;
		for (; *p != '\0' && p[1] != '\0'; p += 2)
			set->username_translation_map[(int)(uint8_t)*p] = p[1];
	}

	if (*set->policy_server_url != '\0') {
		if (*set->policy_hash_nonce == '\0') {

			*error_r = "auth_policy_hash_nonce must be set when policy server is used";
			return FALSE;
		}
		const struct hash_method *digest = hash_method_lookup(set->policy_hash_mech);
		if (digest == NULL) {
			*error_r = "invalid auth_policy_hash_mech given";
			return FALSE;
		}
		if (set->policy_hash_truncate > 0 && set->policy_hash_truncate >= digest->digest_size*8) {
			*error_r = t_strdup_printf("policy_hash_truncate is not smaller than digest size (%u >= %u)",
				set->policy_hash_truncate,
				digest->digest_size*8);
			return FALSE;
		}
	}

	if (!auth_settings_set_self_ips(set, pool, error_r))
		return FALSE;
	if (!auth_settings_get_passdbs(set, pool, event, error_r))
		return FALSE;
	if (!auth_settings_get_userdbs(set, pool, event, error_r))
		return FALSE;
	return TRUE;
}

static bool
auth_passdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r ATTR_UNUSED)
{
	struct auth_passdb_settings *set = _set;

	if (*set->driver == '\0')
		set->driver = set->name;
	return TRUE;
}

static bool
auth_userdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r ATTR_UNUSED)
{
	struct auth_userdb_settings *set = _set;

	if (*set->driver == '\0')
		set->driver = set->name;
	return TRUE;
}
/* </settings checks> */
struct service_settings auth_service_settings = {
	.name = "auth",
	.protocol = "",
	.type = "",
	.executable = "auth",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1,
#ifdef DOVECOT_PRO_EDITION
	.client_limit = 16384,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
const struct setting_keyvalue auth_service_settings_defaults[] = {
	{ "unix_listener", "auth-client auth-login auth-master auth-userdb login\\slogin token-login\\stokenlogin" },

	{ "unix_listener/auth-client/path", "auth-client" },
	{ "unix_listener/auth-client/type", "auth" },
	{ "unix_listener/auth-client/mode", "0600" },
	{ "unix_listener/auth-client/user", "$SET:default_internal_user" },

	{ "unix_listener/auth-login/path", "auth-login" },
	{ "unix_listener/auth-login/type", "login" },
	{ "unix_listener/auth-login/mode", "0600" },
	{ "unix_listener/auth-login/user", "$SET:default_internal_user" },

	{ "unix_listener/auth-master/path", "auth-master" },
	{ "unix_listener/auth-master/type", "master" },
	{ "unix_listener/auth-master/mode", "0600" },

	{ "unix_listener/auth-userdb/path", "auth-userdb" },
	{ "unix_listener/auth-userdb/type", "userdb" },
	{ "unix_listener/auth-userdb/mode", "0666" },
	{ "unix_listener/auth-userdb/user", "$SET:default_internal_user" },
	{ "unix_listener/auth-userdb/group", "$SET:default_internal_group" },

	{ "unix_listener/login\\slogin/path", "login/login" },
	{ "unix_listener/login\\slogin/type", "login" },
	{ "unix_listener/login\\slogin/mode", "0666" },

	{ "unix_listener/token-login\\stokenlogin/path", "token-login/tokenlogin" },
	{ "unix_listener/token-login\\stokenlogin/type", "token-login" },
	{ "unix_listener/token-login\\stokenlogin/mode", "0666" },

	{ NULL, NULL }
};
struct service_settings auth_worker_service_settings = {
	.name = "auth-worker",
	.protocol = "",
	.type = "worker",
	.executable = "auth -w",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 30,
	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue auth_worker_service_settings_defaults[] = {
	{ "unix_listener", "auth-worker" },

	{ "unix_listener/auth-worker/path", "auth-worker" },
	{ "unix_listener/auth-worker/mode", "0600" },
	{ "unix_listener/auth-worker/user", "$SET:default_internal_user" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("passdb_"#name, name, struct auth_passdb_settings)
static const struct setting_define auth_passdb_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	DEF(BOOL, fields_import_all),
	DEF(BOOLLIST, mechanisms_filter),
	DEF(STR, username_filter),

	DEF(STR, default_password_scheme),

	DEF(ENUM, skip),
	DEF(ENUM, result_success),
	DEF(ENUM, result_failure),
	DEF(ENUM, result_internalfail),

	DEF(BOOL, deny),
	DEF(BOOL, master),
	DEF(BOOL, use_cache),
	DEF(BOOL, use_worker),

	SETTING_DEFINE_LIST_END
};
static const struct auth_passdb_settings auth_passdb_default_settings = {
	.name = "",
	.driver = "",
	.fields_import_all = TRUE,
	.mechanisms_filter = ARRAY_INIT,
	.username_filter = "",

	.default_password_scheme = "PLAIN",

	.skip = "never:authenticated:unauthenticated",
	.result_success = "return-ok:return:return-fail:continue:continue-ok:continue-fail",
	.result_failure = "continue:return:return-ok:return-fail:continue-ok:continue-fail",
	.result_internalfail = "continue:return:return-ok:return-fail:continue-ok:continue-fail",

	.deny = FALSE,
	.master = FALSE,
	.use_cache = TRUE,
	.use_worker = FALSE,
};
const struct setting_parser_info auth_passdb_setting_parser_info = {
	.name = "auth_passdb",

	.defines = auth_passdb_setting_defines,
	.defaults = &auth_passdb_default_settings,

	.struct_size = sizeof(struct auth_passdb_settings),
	.pool_offset1 = 1 + offsetof(struct auth_passdb_settings, pool),

	.check_func = auth_passdb_settings_check
};
static const struct setting_define auth_passdb_post_setting_defines[] = {
	{ .type = SET_STRLIST, .key = "passdb_fields",
	  .offset = offsetof(struct auth_passdb_post_settings, fields) },

	SETTING_DEFINE_LIST_END
};
static const struct auth_passdb_post_settings auth_passdb_post_default_settings = {
	.fields = ARRAY_INIT,
};
const struct setting_parser_info auth_passdb_post_setting_parser_info = {
	.name = "auth_passdb_post",

	.defines = auth_passdb_post_setting_defines,
	.defaults = &auth_passdb_post_default_settings,

	.struct_size = sizeof(struct auth_passdb_post_settings),
	.pool_offset1 = 1 + offsetof(struct auth_passdb_post_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("userdb_"#name, name, struct auth_userdb_settings)
static const struct setting_define auth_userdb_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	DEF(BOOL, fields_import_all),

	DEF(ENUM, skip),
	DEF(ENUM, result_success),
	DEF(ENUM, result_failure),
	DEF(ENUM, result_internalfail),

	DEF(BOOL, use_cache),
	DEF(BOOL, use_worker),

	SETTING_DEFINE_LIST_END
};
static const struct auth_userdb_settings auth_userdb_default_settings = {
	/* NOTE: when adding fields, update also auth.c:userdb_dummy_set */
	.name = "",
	.driver = "",
	.fields_import_all = TRUE,

	.skip = "never:found:notfound",
	.result_success = "return-ok:return:return-fail:continue:continue-ok:continue-fail",
	.result_failure = "continue:return:return-ok:return-fail:continue-ok:continue-fail",
	.result_internalfail = "continue:return:return-ok:return-fail:continue-ok:continue-fail",

	.use_cache = TRUE,
	.use_worker = FALSE,
};
const struct setting_parser_info auth_userdb_setting_parser_info = {
	.name = "auth_userdb",

	.defines = auth_userdb_setting_defines,
	.defaults = &auth_userdb_default_settings,

	.struct_size = sizeof(struct auth_userdb_settings),
	.pool_offset1 = 1 + offsetof(struct auth_userdb_settings, pool),

	.check_func = auth_userdb_settings_check,
};
static const struct setting_define auth_userdb_post_setting_defines[] = {
	{ .type = SET_STRLIST, .key = "userdb_fields",
	  .offset = offsetof(struct auth_userdb_post_settings, fields) },

	SETTING_DEFINE_LIST_END
};
static const struct auth_userdb_post_settings auth_userdb_post_default_settings = {
	.fields = ARRAY_INIT,
};
const struct setting_parser_info auth_userdb_post_setting_parser_info = {
	.name = "auth_userdb_post",

	.defines = auth_userdb_post_setting_defines,
	.defaults = &auth_userdb_post_default_settings,

	.struct_size = sizeof(struct auth_userdb_post_settings),
	.pool_offset1 = 1 + offsetof(struct auth_userdb_post_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_static_settings)
static const struct setting_define auth_static_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_static", },
	{ .type = SET_FILTER_NAME, .key = "userdb_static", },
	DEF(STR, passdb_static_password),
	DEF(BOOL, userdb_static_allow_all_users),

	SETTING_DEFINE_LIST_END
};
static const struct auth_static_settings auth_static_default_settings = {
	.passdb_static_password = "",
	.userdb_static_allow_all_users = FALSE,
};
const struct setting_parser_info auth_static_setting_parser_info = {
	.name = "auth_static",

	.defines = auth_static_setting_defines,
	.defaults = &auth_static_default_settings,

	.struct_size = sizeof(struct auth_static_settings),
	.pool_offset1 = 1 + offsetof(struct auth_static_settings, pool),
};
#undef DEF
#undef DEF_NOPREFIX
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("auth_"#name, name, struct auth_settings)
#define DEF_NOPREFIX(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_settings)
static const struct setting_define auth_setting_defines[] = {
	DEF(BOOLLIST, mechanisms),
	DEF(BOOLLIST, realms),
	DEF(STR, default_domain),
	DEF(SIZE, cache_size),
	DEF(TIME, cache_ttl),
	DEF(TIME, cache_negative_ttl),
	DEF(BOOL, cache_verify_password_with_worker),
	DEF(STR, username_chars),
	DEF(STR_HIDDEN, username_translation),
	DEF(STR_NOVARS, username_format),
	DEF(STR, master_user_separator),
	DEF(STR, anonymous_username),
#ifdef DOVECOT_PRO_EDITION
	DEF(STR_HIDDEN, krb5_keytab),
	DEF(STR_HIDDEN, gssapi_hostname),
	DEF(STR_HIDDEN, winbind_helper_path),
#else
	DEF(STR, krb5_keytab),
	DEF(STR, gssapi_hostname),
	DEF(STR, winbind_helper_path),
#endif
	DEF(STR, proxy_self),
	DEF(TIME, failure_delay),
	DEF(TIME_MSECS, internal_failure_delay),

	{ .type = SET_FILTER_NAME, .key = "auth_policy", },
	DEF(STR, policy_server_url),
	DEF(STR, policy_server_api_header),
	DEF(STR, policy_hash_mech),
	DEF(STR, policy_hash_nonce),
	DEF(BOOL, policy_reject_on_fail),
	DEF(BOOL, policy_check_before_auth),
	DEF(BOOL, policy_check_after_auth),
	DEF(BOOL, policy_report_after_auth),
	DEF(BOOL, policy_log_only),
	DEF(UINT_HIDDEN, policy_hash_truncate),

	DEF(BOOL, verbose),
	DEF(BOOL, debug),
	DEF(BOOL, debug_passwords),
	DEF(BOOL, allow_weak_schemes),
	DEF(STR, verbose_passwords),
	DEF(BOOL, ssl_require_client_cert),
	DEF(BOOL, ssl_username_from_cert),
#ifdef DOVECOT_PRO_EDITION
	DEF(BOOL_HIDDEN, use_winbind),
#else
	DEF(BOOL, use_winbind),
#endif

	{ .type = SET_FILTER_ARRAY, .key = "passdb",
	  .offset = offsetof(struct auth_settings, passdbs),
	  .filter_array_field_name = "passdb_name", },
	{ .type = SET_FILTER_ARRAY, .key = "userdb",
	  .offset = offsetof(struct auth_settings, userdbs),
	  .filter_array_field_name = "userdb_name", },

	DEF_NOPREFIX(STR_HIDDEN, base_dir),
	DEF_NOPREFIX(BOOL, verbose_proctitle),
	DEF_NOPREFIX(UINT, first_valid_uid),
	DEF_NOPREFIX(UINT, last_valid_uid),
	DEF_NOPREFIX(UINT, first_valid_gid),
	DEF_NOPREFIX(UINT, last_valid_gid),

	SETTING_DEFINE_LIST_END
};
static const struct auth_settings auth_default_settings = {
	.realms = ARRAY_INIT,
	.default_domain = "",
	.cache_size = 0,
	.cache_ttl = 60*60,
	.cache_negative_ttl = 60*60,
	.cache_verify_password_with_worker = FALSE,
	.username_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@",
	.username_translation = "",
	.username_format = "%{user | lower}",
	.master_user_separator = "",
	.anonymous_username = "anonymous",
	.krb5_keytab = "",
	.gssapi_hostname = "",
	.winbind_helper_path = "/usr/bin/ntlm_auth",
	.proxy_self = "",
	.failure_delay = 2,
	.internal_failure_delay = 2000,

	.policy_server_url = "",
	.policy_server_api_header = "",
	.policy_hash_mech = "sha256",
	.policy_hash_nonce = "",
	.policy_reject_on_fail = FALSE,
	.policy_check_before_auth = TRUE,
	.policy_check_after_auth = TRUE,
	.policy_report_after_auth = TRUE,
	.policy_log_only = FALSE,
	.policy_hash_truncate = 12,

	.verbose = FALSE,
	.debug = FALSE,
	.debug_passwords = FALSE,
	.allow_weak_schemes = FALSE,
	.verbose_passwords = "no",
	.ssl_require_client_cert = FALSE,
	.ssl_username_from_cert = FALSE,

	.use_winbind = FALSE,

	.passdbs = ARRAY_INIT,
	.userdbs = ARRAY_INIT,

	.base_dir = PKG_RUNDIR,
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,
	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,
};
static const struct setting_keyvalue auth_default_settings_keyvalue[] = {
	{ "auth_mechanisms", "plain" },
	{ "auth_policy/http_client_request_absolute_timeout", "2s" },
	{ "auth_policy/http_client_max_idle_time", "10s" },
	{ "auth_policy/http_client_max_parallel_connections", "100" },
	{ "auth_policy/http_client_user_agent", "dovecot/auth-policy-client" },
	{ NULL, NULL }
};
const struct setting_parser_info auth_setting_parser_info = {
	.name = "auth",

	.defines = auth_setting_defines,
	.defaults = &auth_default_settings,
	.default_settings = auth_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_settings),
	.pool_offset1 = 1 + offsetof(struct auth_settings, pool),
	.ext_check_func = auth_settings_ext_check,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("auth_"#name, name, struct auth_policy_request_settings)
static const struct setting_define auth_policy_request_setting_defines[] = {
	DEF(STRLIST, policy_request_attributes),

	SETTING_DEFINE_LIST_END
};
static const struct auth_policy_request_settings auth_policy_request_default_settings = {
	.policy_request_attributes = ARRAY_INIT,
};
static const struct setting_keyvalue auth_policy_request_default_settings_keyvalue[] = {
	{ "auth_policy_request_attributes/login", "%{requested_username}" },
	{ "auth_policy_request_attributes/pwhash", "%{hashed_password}" },
	{ "auth_policy_request_attributes/remote", "%{remote_ip}" },
	{ "auth_policy_request_attributes/device_id", "%{client_id}" },
	{ "auth_policy_request_attributes/protocol", "%{protocol}" },
	{ "auth_policy_request_attributes/session_id", "%{session}" },
	{ "auth_policy_request_attributes/fail_type", "%{fail_type}" },
	{ NULL, NULL }
};
const struct setting_parser_info auth_policy_request_setting_parser_info = {
	.name = "auth_policy_request",

	.defines = auth_policy_request_setting_defines,
	.defaults = &auth_policy_request_default_settings,
	.default_settings = auth_policy_request_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_policy_request_settings),
	.pool_offset1 = 1 + offsetof(struct auth_policy_request_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/auth/db-ldap-settings.c */
extern const struct setting_parser_info ldap_setting_parser_info;
extern const struct setting_parser_info ldap_pre_setting_parser_info;
extern const struct setting_parser_info ldap_post_setting_parser_info;
#ifdef HAVE_LDAP
/* <settings checks> */
#include "ldap-sasl.h"
#include "ldap-settings-parse.h"

static bool ldap_setting_check(void *_set, pool_t pool, const char **error_r);
/* </settings checks> */
#endif
#ifdef HAVE_LDAP
/* <settings checks> */

static int ldap_parse_deref(const char *str, int *ref_r)
{
	if (strcasecmp(str, "never") == 0)
		*ref_r = LDAP_DEREF_NEVER;
	else if (strcasecmp(str, "searching") == 0)
		*ref_r = LDAP_DEREF_SEARCHING;
	else if (strcasecmp(str, "finding") == 0)
		*ref_r = LDAP_DEREF_FINDING;
	else if (strcasecmp(str, "always") == 0)
		*ref_r = LDAP_DEREF_ALWAYS;
	else
		return -1;
	return 0;
}

static bool ldap_setting_check(void *_set, pool_t pool ATTR_UNUSED,
			       const char **error_r)
{
	struct ldap_settings *set = _set;

        if (ldap_parse_deref(set->deref, &set->parsed_deref) < 0) {
		*error_r = t_strdup_printf("Unknown ldap_deref option '%s'",
					   set->deref);
		return FALSE;
	}

	if (ldap_parse_scope(set->scope, &set->parsed_scope) < 0) {
		*error_r = t_strdup_printf("Unknown ldap_scope option '%s'",
					   set->scope);
		return FALSE;
	}

#ifndef HAVE_LDAP_SASL
	if (!array_is_empty(&set->auth_sasl_mechanisms)) {
		*error_r = "ldap_auth_sasl_mechanism set, but no SASL support compiled in";
		return FALSE;
	}
#endif

	return TRUE;
}

/* </settings checks> */
#endif
#ifdef HAVE_LDAP
#undef DEF
#endif
#ifdef HAVE_LDAP
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("ldap_"#name, name, struct ldap_settings)
#endif
#ifdef HAVE_LDAP
static const struct setting_define ldap_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_ldap", },
	{ .type = SET_FILTER_NAME, .key = "userdb_ldap", },
	DEF(STR, uris),
	DEF(STR, connection_group),
	DEF(STR, auth_dn),
	DEF(STR, auth_dn_password),
	DEF(BOOLLIST, auth_sasl_mechanisms),
	DEF(STR, auth_sasl_realm),
	DEF(STR, auth_sasl_authz_id),
	DEF(BOOL, starttls),
	DEF(ENUM, deref),
	DEF(ENUM, scope),
	DEF(UINT, version),
	DEF(UINT, debug_level),
	SETTING_DEFINE_LIST_END
};
#endif
#ifdef HAVE_LDAP
static const struct ldap_settings ldap_default_settings = {
	.uris = "",
	.connection_group = "",
	.auth_dn = "",
	.auth_dn_password = "",
	.auth_sasl_mechanisms = ARRAY_INIT,
	.auth_sasl_realm = "",
	.auth_sasl_authz_id = "",
	.starttls = FALSE,
	.deref = "never:searching:finding:always",
	.scope = "subtree:onelevel:base",
	.version = 3,
	.debug_level = 0,
};
#endif
#ifdef HAVE_LDAP
static const struct setting_keyvalue ldap_default_settings_keyvalue[] = {
	{ "passdb_ldap/passdb_default_password_scheme", "crypt" },
	{ "passdb_ldap/passdb_fields_import_all", "no" },
	{ "userdb_ldap/userdb_fields_import_all", "no" },
	{ NULL, NULL }
};
#endif
#ifdef HAVE_LDAP
const struct setting_parser_info ldap_setting_parser_info = {
	.name = "auth_ldap",
#ifndef BUILTIN_LDAP
	.plugin_dependency = "auth/libauthdb_ldap",
#endif

	.check_func = ldap_setting_check,
	.defines = ldap_setting_defines,
	.defaults = &ldap_default_settings,
	.default_settings = ldap_default_settings_keyvalue,

	.struct_size = sizeof(struct ldap_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_settings, pool),
};
#endif
#ifdef HAVE_LDAP
#undef DEF
#endif
#ifdef HAVE_LDAP
#undef DEFN
#endif
#ifdef HAVE_LDAP
#define DEF(type, field) \
	SETTING_DEFINE_STRUCT_##type(#field, field, struct ldap_pre_settings)
#endif
#ifdef HAVE_LDAP
static const struct setting_define ldap_pre_setting_defines[] = {
	DEF(STR, ldap_base),
	DEF(BOOL, passdb_ldap_bind),
	DEF(STR, passdb_ldap_filter),
	DEF(STR, passdb_ldap_bind_userdn),
	DEF(STR, userdb_ldap_filter),
	DEF(STR, userdb_ldap_iterate_filter),
	SETTING_DEFINE_LIST_END
};
#endif
#ifdef HAVE_LDAP
static const struct ldap_pre_settings ldap_pre_default_settings = {
	.ldap_base = "",
	.passdb_ldap_bind = FALSE,
	.passdb_ldap_filter = "",
	.passdb_ldap_bind_userdn = "",
	.userdb_ldap_filter = "",
	.userdb_ldap_iterate_filter = "",
};
#endif
#ifdef HAVE_LDAP
const struct setting_parser_info ldap_pre_setting_parser_info = {
	.name = "auth_ldap_pre",
#ifndef BUILTIN_LDAP
	.plugin_dependency = "auth/libauthdb_ldap",
#endif

	.defines = ldap_pre_setting_defines,
	.defaults = &ldap_pre_default_settings,

	.struct_size = sizeof(struct ldap_pre_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_pre_settings, pool),
};
#endif
#ifdef HAVE_LDAP
#undef DEF
#endif
#ifdef HAVE_LDAP
#define DEF(type, field) \
	SETTING_DEFINE_STRUCT_##type("userdb_ldap_"#field, field, struct ldap_post_settings)
#endif
#ifdef HAVE_LDAP
static const struct setting_define ldap_post_setting_defines[] = {
	DEF(STRLIST, iterate_fields),
	SETTING_DEFINE_LIST_END
};
#endif
#ifdef HAVE_LDAP
static const struct ldap_post_settings ldap_post_default_settings = {
	.iterate_fields = ARRAY_INIT,
};
#endif
#ifdef HAVE_LDAP
const struct setting_parser_info ldap_post_setting_parser_info = {
	.name = "auth_ldap_post",
#ifndef BUILTIN_LDAP
	.plugin_dependency = "auth/libauthdb_ldap",
#endif

	.defines = ldap_post_setting_defines,
	.defaults = &ldap_post_default_settings,

	.struct_size = sizeof(struct ldap_post_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_post_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/auth/db-lua.c */
extern const struct setting_parser_info auth_lua_setting_parser_info;
#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)
#undef DEF
#endif
#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_lua_settings)
#endif
#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)
static const struct setting_define auth_lua_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_lua", },
	{ .type = SET_FILTER_NAME, .key = "userdb_lua", },

	SETTING_DEFINE_LIST_END
};
#endif
#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)
static const struct setting_keyvalue auth_lua_default_settings_keyvalue[] = {
	{ "passdb_lua/passdb_use_worker", "yes"},
	{ "userdb_lua/userdb_use_worker", "yes"},
	{ NULL, NULL }
};
#endif
#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)
const struct setting_parser_info auth_lua_setting_parser_info = {
	.name = "auth_lua",
#ifndef BUILTIN_LUA
	.plugin_dependency = "auth/libauthdb_lua",
#endif

	.defines = auth_lua_setting_defines,
	.default_settings = auth_lua_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_lua_settings),
	.pool_offset1 = 1 + offsetof(struct auth_lua_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/auth/db-oauth2.c */
extern const struct setting_parser_info auth_oauth2_setting_parser_info;
extern const struct setting_parser_info auth_oauth2_post_setting_parser_info;

/* <settings checks> */

static bool auth_oauth2_settings_check(struct event *event ATTR_UNUSED, void *_set,
				       pool_t pool ATTR_UNUSED, const char **error_r)
{
	const struct auth_oauth2_settings *set = _set;

	if (*set->introspection_mode == '\0') {
		if (*set->grant_url != '\0' ||
		    *set->tokeninfo_url != '\0' ||
		    *set->introspection_url != '\0') {
			*error_r = "Missing oauth2_introspection_mode";
			return FALSE;
		}
	} else if (strcmp(set->introspection_mode, "auth") == 0 ||
		 strcmp(set->introspection_mode, "get") == 0 ||
		 strcmp(set->introspection_mode, "post") == 0) {
		if (*set->tokeninfo_url == '\0' &&
		    *set->introspection_url == '\0') {
			*error_r = "Need at least one of oauth2_tokeninfo_url or oauth2_introspection_url";
			return FALSE;
		}
	}

	if (*set->grant_url != '\0' && *set->client_id == '\0') {
		*error_r = "oauth2_client_id is required with oauth2_grant_url";
		return FALSE;
	}

	if ((*set->client_id != '\0' && *set->client_secret == '\0') ||
	    (*set->client_id == '\0' && *set->client_secret != '\0')) {
		*error_r = "oauth2_client_id and oauth2_client_secret must be provided together";
		return FALSE;
	}

	if (*set->active_attribute == '\0' &&
	    *set->active_value != '\0') {
		*error_r = "Cannot have empty active_attribute if active_value is set";
		return FALSE;
	}

	return TRUE;
}

/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("oauth2_"#name, name, struct auth_oauth2_settings)
#define DEF_SECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("oauth2_"#name, name##_secs, struct auth_oauth2_settings)
static const struct setting_define auth_oauth2_setting_defines[] = {
	DEF(STR, tokeninfo_url),
	DEF(STR, grant_url),
	DEF(STR, introspection_url),
	DEF(BOOLLIST, scope),
	DEF(ENUM, introspection_mode),
	DEF(STR_NOVARS, username_validation_format),
	DEF(STR, username_attribute),
	DEF(STR, active_attribute),
	DEF(STR, active_value),
	DEF(STR, client_id),
	DEF(STR, client_secret),
	DEF(BOOLLIST, issuers),
	DEF(STR, openid_configuration_url),
	DEF_SECS(TIME, token_expire_grace),
	DEF(BOOL, force_introspection),
	DEF(BOOL, send_auth_headers),
	DEF(BOOL, use_worker_with_mech),
	{ .type = SET_FILTER_NAME, .key = "oauth2_local_validation",
		.required_setting = "dict", },
	{ .type = SET_FILTER_NAME, .key = "oauth2", },
	SETTING_DEFINE_LIST_END
};
static const struct auth_oauth2_settings auth_oauth2_default_settings = {
	.tokeninfo_url = "",
	.grant_url = "",
	.introspection_url = "",
	.scope = ARRAY_INIT,
	.force_introspection = FALSE,
	.introspection_mode = ":auth:get:post:local",
	.username_validation_format = "%{user}",
	.username_attribute = "email",
	.active_attribute = "",
	.active_value = "",
	.client_id = "",
	.client_secret = "",
	.issuers = ARRAY_INIT,
	.openid_configuration_url = "",
	.token_expire_grace_secs = 60,
	.send_auth_headers = FALSE,
	.use_worker_with_mech = FALSE,
};
static const struct setting_keyvalue auth_oauth2_default_settings_keyvalue[] = {
	{ "oauth2/http_client_user_agent", "dovecot-oauth2-passdb/"DOVECOT_VERSION },
	{ "oauth2/http_client_max_idle_time", "60s" },
	{ "oauth2/http_client_max_parallel_connections", "10" },
	{ "oauth2/http_client_max_pipelined_requests", "1" },
	{ "oauth2/http_client_request_max_attempts", "1" },
	{ NULL, NULL }
};
const struct setting_parser_info auth_oauth2_setting_parser_info = {
	.name = "auth_oauth2",

	.defines = auth_oauth2_setting_defines,
	.defaults = &auth_oauth2_default_settings,
	.default_settings = auth_oauth2_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_oauth2_settings),
	.pool_offset1 = 1 + offsetof(struct auth_oauth2_settings, pool),
	.ext_check_func = auth_oauth2_settings_check,
};
static const struct setting_define auth_oauth2_post_setting_defines[] = {
	{ .type = SET_STRLIST, .key = "oauth2_fields",
	  .offset = offsetof(struct auth_oauth2_post_settings, fields) },

	SETTING_DEFINE_LIST_END
};
static const struct auth_oauth2_post_settings auth_oauth2_post_default_settings = {
	.fields = ARRAY_INIT,
};
const struct setting_parser_info auth_oauth2_post_setting_parser_info = {
	.name = "auth_oauth2_fields",

	.defines = auth_oauth2_post_setting_defines,
	.defaults = &auth_oauth2_post_default_settings,

	.struct_size = sizeof(struct auth_oauth2_post_settings),
	.pool_offset1 = 1 + offsetof(struct auth_oauth2_post_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/auth/db-passwd-file.c */
extern const struct setting_parser_info passwd_file_setting_parser_info;
#if defined (USERDB_PASSWD_FILE) || defined(PASSDB_PASSWD_FILE)
#undef DEF
#endif
#if defined (USERDB_PASSWD_FILE) || defined(PASSDB_PASSWD_FILE)
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct passwd_file_settings)
#endif
#if defined (USERDB_PASSWD_FILE) || defined(PASSDB_PASSWD_FILE)
static const struct setting_define passwd_file_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_passwd_file", },
	{ .type = SET_FILTER_NAME, .key = "userdb_passwd_file", },
	DEF(STR_NOVARS, passwd_file_path),

	SETTING_DEFINE_LIST_END
};
#endif
#if defined (USERDB_PASSWD_FILE) || defined(PASSDB_PASSWD_FILE)
static const struct passwd_file_settings passwd_file_default_settings = {
	.passwd_file_path = "",
};
#endif
#if defined (USERDB_PASSWD_FILE) || defined(PASSDB_PASSWD_FILE)
static const struct setting_keyvalue passwd_file_default_settings_keyvalue[] = {
	{ "passdb_passwd_file/passdb_default_password_scheme", "CRYPT" },
	{ NULL, NULL }
};
#endif
#if defined (USERDB_PASSWD_FILE) || defined(PASSDB_PASSWD_FILE)
const struct setting_parser_info passwd_file_setting_parser_info = {
	.name = "passwd_file",

	.defines = passwd_file_setting_defines,
	.defaults = &passwd_file_default_settings,
	.default_settings = passwd_file_default_settings_keyvalue,

	.struct_size = sizeof(struct passwd_file_settings),
	.pool_offset1 = 1 + offsetof(struct passwd_file_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/auth/passdb-bsdauth.c */
extern const struct setting_parser_info passdb_bsdauth_setting_parser_info;
#ifdef PASSDB_BSDAUTH
struct passdb_bsdauth_settings {
	pool_t pool;
};
#endif
#ifdef PASSDB_BSDAUTH
static const struct setting_define passdb_bsdauth_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_bsdauth" },

	SETTING_DEFINE_LIST_END,
};
#endif
#ifdef PASSDB_BSDAUTH
const struct setting_parser_info passdb_bsdauth_setting_parser_info = {
	.name = "auth_bsdauth",

	.defines = passdb_bsdauth_setting_defines,
	.default_settings = passdb_bsdauth_settings_keyvalue,

	.struct_size = sizeof(struct passdb_bsdauth_settings),
	.pool_offset1 = 1 + offsetof(struct passdb_bsdauth_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/auth/passdb-imap.c */
extern const struct setting_parser_info passdb_imap_setting_parser_info;
struct passdb_imap_settings {
	pool_t pool;
};
static const struct setting_define passdb_imap_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_imapc" },

	SETTING_DEFINE_LIST_END,
};
const struct setting_parser_info passdb_imap_setting_parser_info = {
	.name = "auth_imapc",

	.defines = passdb_imap_setting_defines,

	.struct_size = sizeof(struct passdb_imap_settings),
	.pool_offset1 = 1 + offsetof(struct passdb_imap_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/auth/passdb-pam.c */
extern const struct setting_parser_info auth_pam_setting_parser_info;
#ifdef PASSDB_PAM
struct auth_pam_settings {
	pool_t pool;

	bool session;
	bool setcred;
	const char *service_name;
	unsigned int max_requests;
	bool failure_show_msg;
};
#endif
#ifdef PASSDB_PAM
#undef DEF
#endif
#ifdef PASSDB_PAM
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("passdb_pam_"#name, name, struct auth_pam_settings)
#endif
#ifdef PASSDB_PAM
static const struct setting_define auth_pam_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_pam", },
	DEF(BOOL, session),
	DEF(BOOL, setcred),
	DEF(STR, service_name),
	DEF(UINT, max_requests),
	DEF(BOOL, failure_show_msg),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef PASSDB_PAM
static const struct auth_pam_settings auth_pam_default_settings = {
	.session = FALSE,
	.setcred = FALSE,
	.service_name = "dovecot",
	.max_requests = 100,
	.failure_show_msg = FALSE,
};
#endif
#ifdef PASSDB_PAM
static const struct setting_keyvalue auth_pam_default_settings_keyvalue[] = {
	{ "passdb_pam/passdb_use_worker", "yes"},
	{ NULL, NULL }
};
#endif
#ifdef PASSDB_PAM
const struct setting_parser_info auth_pam_setting_parser_info = {
	.name = "auth_pam",

	.defines = auth_pam_setting_defines,
	.defaults = &auth_pam_default_settings,
	.default_settings = auth_pam_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_pam_settings),
	.pool_offset1 = 1 + offsetof(struct auth_pam_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/auth/passdb-passwd.c */
extern const struct setting_parser_info auth_passwd_info;
#ifdef PASSDB_PASSWD
#undef DEF
#endif
#ifdef PASSDB_PASSWD
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_passwd_settings)
#endif
#ifdef PASSDB_PASSWD
struct auth_passwd_settings {
	pool_t pool;
};
#endif
#ifdef PASSDB_PASSWD
static const struct setting_define auth_passwd_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_passwd", },
	{ .type = SET_FILTER_NAME, .key = "userdb_passwd", },

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef PASSDB_PASSWD
static const struct setting_keyvalue auth_passwd_default_settings_keyvalue[] = {
	{ "passdb_passwd/passdb_use_worker", "yes" },
	{ "passdb_passwd/passdb_default_password_scheme", "crypt" },
	{ "userdb_passwd/userdb_use_worker", "yes" },
	{ NULL, NULL }
};
#endif
#ifdef PASSDB_PASSWD
const struct setting_parser_info auth_passwd_info = {
	.name = "passwd",

	.defines = auth_passwd_setting_defines,
	.default_settings = auth_passwd_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_passwd_settings),
	.pool_offset1 = 1 + offsetof(struct auth_passwd_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/auth/passdb-sql.c */
extern const struct setting_parser_info passdb_sql_setting_parser_info;
#ifdef PASSDB_SQL
struct passdb_sql_settings {
	pool_t pool;
	const char *query;
	const char *update_query;
};
#endif
#ifdef PASSDB_SQL
#undef DEF
#endif
#ifdef PASSDB_SQL
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("passdb_sql_"#name, name, struct passdb_sql_settings)
#endif
#ifdef PASSDB_SQL
static const struct setting_define passdb_sql_setting_defines[] = {
	DEF(STR, query),
	DEF(STR, update_query),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef PASSDB_SQL
static const struct passdb_sql_settings passdb_sql_default_settings = {
	.query = "",
	.update_query = "",
};
#endif
#ifdef PASSDB_SQL
const struct setting_parser_info passdb_sql_setting_parser_info = {
	.name = "passdb_sql",

	.defines = passdb_sql_setting_defines,
	.defaults = &passdb_sql_default_settings,

	.struct_size = sizeof(struct passdb_sql_settings),
	.pool_offset1 = 1 + offsetof(struct passdb_sql_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/auth/userdb-sql.c */
extern const struct setting_parser_info userdb_sql_setting_parser_info;
#ifdef USERDB_SQL
struct userdb_sql_settings {
	pool_t pool;
	const char *query;
	const char *iterate_query;
};
#endif
#ifdef USERDB_SQL
#undef DEF
#endif
#ifdef USERDB_SQL
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("userdb_sql_"#name, name, struct userdb_sql_settings)
#endif
#ifdef USERDB_SQL
static const struct setting_define userdb_sql_setting_defines[] = {
	DEF(STR, query),
	DEF(STR, iterate_query),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef USERDB_SQL
static const struct userdb_sql_settings userdb_sql_default_settings = {
	.query = "",
	.iterate_query = "",
};
#endif
#ifdef USERDB_SQL
const struct setting_parser_info userdb_sql_setting_parser_info = {
	.name = "userdb_sql",

	.defines = userdb_sql_setting_defines,
	.defaults = &userdb_sql_default_settings,

	.struct_size = sizeof(struct userdb_sql_settings),
	.pool_offset1 = 1 + offsetof(struct userdb_sql_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/config/config-settings.c */
struct service_settings config_service_settings = {
	.name = "config",
	.protocol = "",
	.type = "config",
	.executable = "config",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.idle_kill_interval = SET_TIME_INFINITE,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue config_service_settings_defaults[] = {
	{ "unix_listener", "config" },

	{ "unix_listener/config/path", "config" },
	{ "unix_listener/config/mode", "0600" },

	{ NULL, NULL }
};
/* /home/gromy/Документы/Development/dovecot-core/src/dict/dict-settings.c */
extern const struct setting_parser_info dict_server_setting_parser_info;
struct service_settings dict_service_settings = {
	.name = "dict",
	.protocol = "",
	.type = "",
	.executable = "dict",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue dict_service_settings_defaults[] = {
	{ "unix_listener", "dict" },

	{ "unix_listener/dict/path", "dict" },
	{ "unix_listener/dict/mode", "0660" },
	{ "unix_listener/dict/group", "$SET:default_internal_group" },

	{ NULL, NULL }
};
struct service_settings dict_async_service_settings = {
	.name = "dict-async",
	.protocol = "",
	.type = "",
	.executable = "dict",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

#ifdef DOVECOT_PRO_EDITION
	/* Cassandra driver can use up a lot of VSZ */
	.vsz_limit = 2048ULL * 1024 * 1024,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue dict_async_service_settings_defaults[] = {
	{ "unix_listener", "dict-async" },

	{ "unix_listener/dict-async/path", "dict-async" },
	{ "unix_listener/dict-async/mode", "0660" },
	{ "unix_listener/dict-async/group", "$SET:default_internal_group" },

	{ NULL, NULL }
};
struct service_settings dict_expire_service_settings = {
	.name = "dict-expire",
	.protocol = "",
	.type = "",
	.executable = "dict-expire",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1,
	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct dict_server_settings)
static const struct setting_define dict_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "dict_server" },

	DEF(STR_HIDDEN, base_dir),
	DEF(BOOL, verbose_proctitle),

	SETTING_DEFINE_LIST_END
};
const struct dict_server_settings dict_default_settings = {
	.base_dir = PKG_RUNDIR,
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,
};
const struct setting_parser_info dict_server_setting_parser_info = {
	.name = "dict_server",

	.defines = dict_setting_defines,
	.defaults = &dict_default_settings,

	.struct_size = sizeof(struct dict_server_settings),
	.pool_offset1 = 1 + offsetof(struct dict_server_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/dns/dns-client-settings.c */
struct service_settings dns_client_service_settings = {
	.name = "dns-client",
	.protocol = "",
	.type = "",
	.executable = "dns-client",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue dns_client_service_settings_defaults[] = {
	{ "unix_listener", "dns-client login\\sdns-client" },

	{ "unix_listener/dns-client/path", "dns-client" },
	{ "unix_listener/dns-client/mode", "0666" },

	{ "unix_listener/login\\sdns-client/path", "login/dns-client" },
	{ "unix_listener/login\\sdns-client/mode", "0666" },

	{ NULL, NULL }
};
/* /home/gromy/Документы/Development/dovecot-core/src/doveadm/doveadm-settings.c */
extern const struct setting_parser_info doveadm_setting_parser_info;

/* <settings checks> */
struct dsync_feature_list {
	const char *name;
	enum dsync_features num;
};

static const struct dsync_feature_list dsync_feature_list[] = {
	{ "empty-header-workaround", DSYNC_FEATURE_EMPTY_HDR_WORKAROUND },
	{ "no-header-hashes", DSYNC_FEATURE_NO_HEADER_HASHES },
	{ NULL, 0 }
};

static int
dsync_settings_parse_features(struct doveadm_settings *set,
			      const char **error_r)
{
	enum dsync_features features = 0;
	const struct dsync_feature_list *list;
	const char *const *str;

	str = t_strsplit_spaces(set->dsync_features, " ,");
	for (; *str != NULL; str++) {
		list = dsync_feature_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("dsync_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool doveadm_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				   const char **error_r)
{
	struct doveadm_settings *set = _set;

#ifndef CONFIG_BINARY
	fix_base_path(set, pool, &set->auth_socket_path);
	fix_base_path(set, pool, &set->doveadm_socket_path);
#endif
	if (*set->dsync_hashed_headers == '\0') {
		*error_r = "dsync_hashed_headers must not be empty";
		return FALSE;
	}
	if (*set->dsync_alt_char == '\0') {
		*error_r = "dsync_alt_char must not be empty";
		return FALSE;
	}
	if (dsync_settings_parse_features(set, error_r) != 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */
struct service_settings doveadm_service_settings = {
	.name = "doveadm",
	.protocol = "",
	.type = "",
	.executable = "doveadm-server",
	.user = "",
	.group = "",
	.privileged_group = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.client_limit = 1,
#ifdef DOVECOT_PRO_EDITION
	.restart_request_count = 1000,
#else
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue doveadm_service_settings_defaults[] = {
	{ "unix_listener", "doveadm-server" },

	{ "unix_listener/doveadm-server/path", "doveadm-server" },
	{ "unix_listener/doveadm-server/type", "tcp" },
	{ "unix_listener/doveadm-server/mode", "0600" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct doveadm_settings)
static const struct setting_define doveadm_setting_defines[] = {
	DEF(STR_HIDDEN, base_dir),
	DEF(STR_HIDDEN, libexec_dir),
	DEF(BOOLLIST, mail_plugins),
	DEF(STR, mail_plugin_dir),
	DEF(STR, mail_temp_dir),
	DEF(BOOL, auth_debug),
	DEF(STR_HIDDEN, auth_socket_path),
	DEF(STR, doveadm_socket_path),
	DEF(UINT, doveadm_worker_count),
	DEF(IN_PORT, doveadm_port),
	{ .type = SET_ALIAS, .key = "doveadm_proxy_port" },
	DEF(ENUM, doveadm_ssl),
	DEF(STR, doveadm_username),
	DEF(STR, doveadm_password),
	DEF(BOOLLIST, doveadm_allowed_commands),
	DEF(STR, dsync_alt_char),
	DEF(STR_NOVARS, dsync_remote_cmd),
	DEF(STR, doveadm_api_key),
	DEF(STR, dsync_features),
	DEF(UINT, dsync_commit_msgs_interval),
	DEF(STR_HIDDEN, dsync_hashed_headers),

	{ .type = SET_FILTER_NAME, .key = DOVEADM_SERVER_FILTER },

	SETTING_DEFINE_LIST_END
};
const struct doveadm_settings doveadm_default_settings = {
	.base_dir = PKG_RUNDIR,
	.libexec_dir = PKG_LIBEXECDIR,
	.mail_plugins = ARRAY_INIT,
	.mail_plugin_dir = MODULEDIR,
#ifdef DOVECOT_PRO_EDITION
	.mail_temp_dir = "/dev/shm/dovecot",
#else
	.mail_temp_dir = "/tmp",
#endif
	.auth_debug = FALSE,
	.auth_socket_path = "auth-userdb",
	.doveadm_socket_path = "doveadm-server",
	.doveadm_worker_count = 0,
	.doveadm_port = 0,
	.doveadm_ssl = "no:ssl:starttls",
	.doveadm_username = "doveadm",
	.doveadm_password = "",
	.doveadm_allowed_commands = ARRAY_INIT,
	.dsync_alt_char = "_",
	.dsync_remote_cmd = "ssh -l%{login} %{host} doveadm dsync-server -u%{user} -U",
	.dsync_features = "",
	.dsync_hashed_headers = "Date Message-ID",
	.dsync_commit_msgs_interval = 100,
	.doveadm_api_key = "",
};
const struct setting_parser_info doveadm_setting_parser_info = {
	.name = "doveadm",

	.defines = doveadm_setting_defines,
	.defaults = &doveadm_default_settings,

	.struct_size = sizeof(struct doveadm_settings),
	.pool_offset1 = 1 + offsetof(struct doveadm_settings, pool),
	.check_func = doveadm_settings_check,
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap-hibernate/imap-hibernate-settings.c */
struct service_settings imap_hibernate_service_settings = {
	.name = "imap-hibernate",
	.protocol = "imap",
	.type = "",
	.executable = "imap-hibernate",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue imap_hibernate_service_settings_defaults[] = {
	{ "unix_listener", "imap-hibernate srv.imap-hibernate\\s%{pid}" },

	{ "unix_listener/imap-hibernate/path", "imap-hibernate" },
	{ "unix_listener/imap-hibernate/mode", "0660" },
	{ "unix_listener/imap-hibernate/group", "$SET:default_internal_group" },

	{ "unix_listener/srv.imap-hibernate\\s%{pid}/path", "srv.imap-hibernate/%{pid}" },
	{ "unix_listener/srv.imap-hibernate\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.imap-hibernate\\s%{pid}/mode", "0600" },

	{ NULL, NULL }
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap-login/imap-login-settings.c */
extern const struct setting_parser_info imap_login_setting_parser_info;
struct service_settings imap_login_service_settings = {
	.name = "imap-login",
	.protocol = "imap",
	.type = "login",
	.executable = "imap-login",
	.user = "$SET:default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

#ifndef DOVECOT_PRO_EDITION
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,
};
const struct setting_keyvalue imap_login_service_settings_defaults[] = {
	{ "unix_listener", "srv.imap-login\\s%{pid}" },

	{ "unix_listener/srv.imap-login\\s%{pid}/path", "srv.imap-login/%{pid}" },
	{ "unix_listener/srv.imap-login\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.imap-login\\s%{pid}/mode", "0600" },

	{ "inet_listener", "imap imaps" },

	{ "inet_listener/imap/name", "imap" },
	{ "inet_listener/imap/port", "143" },

	{ "inet_listener/imaps/name", "imaps" },
	{ "inet_listener/imaps/port", "993" },
	{ "inet_listener/imaps/ssl", "yes" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_login_settings)
static const struct setting_define imap_login_setting_defines[] = {
	DEF(BOOLLIST, imap_capability),
	DEF(BOOL, imap_literal_minus),
	DEF(BOOL, imap_id_retain),
	DEF(BOOL, imap4rev2_enable),

	{ .type = SET_STRLIST, .key = "imap_id_send",
	  .offset = offsetof(struct imap_login_settings, imap_id_send) },

	SETTING_DEFINE_LIST_END
};
static const struct imap_login_settings imap_login_default_settings = {
	.imap_capability = ARRAY_INIT,
	.imap_id_send = ARRAY_INIT,
	.imap_literal_minus = FALSE,
	.imap_id_retain = FALSE,
	.imap4rev2_enable = FALSE,
};
static const struct setting_keyvalue imap_login_default_settings_keyvalue[] = {
	{"service/imap-login/imap_capability/IMAP4rev1", "yes"},
	{"service/imap-login/imap_capability/IMAP4rev2", "yes"},
	{"service/imap-login/imap_capability/LOGIN-REFERRALS", "yes"},
	{"service/imap-login/imap_capability/ID", "yes"},
	{"service/imap-login/imap_capability/ENABLE", "yes"},
	/* IDLE doesn't really belong to banner. It's there just to make
	   Blackberries happy, because otherwise BIS server disables push email. */
	{ "service/imap-login/imap_capability/IDLE", "yes" },
	{ "service/imap-login/imap_capability/SASL-IR", "yes" },
	{ "service/imap-login/imap_capability/LITERAL+", "yes" },
	{ "service/imap-login/imap_capability/LITERAL-", "yes" },
	{ "imap_id_send/name", DOVECOT_NAME },
#ifdef DOVECOT_PRO_EDITION
	{ "service/imap-login/service_process_limit", "%{system:cpu_count}" },
	{ "service/imap-login/service_process_min_avail", "%{system:cpu_count}" },
#endif
	{ NULL, NULL },
};
const struct setting_parser_info imap_login_setting_parser_info = {
	.name = "imap_login",

	.defines = imap_login_setting_defines,
	.defaults = &imap_login_default_settings,
	.default_settings = imap_login_default_settings_keyvalue,

	.struct_size = sizeof(struct imap_login_settings),
	.pool_offset1 = 1 + offsetof(struct imap_login_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap-urlauth-login/imap-urlauth-login-settings.c */
extern const struct setting_parser_info imap_urlauth_login_setting_parser_info;
struct service_settings imap_urlauth_login_service_settings = {
	.name = "imap-urlauth-login",
	.protocol = "imap",
	.type = "login",
	.executable = "imap-urlauth-login",
	.user = "$SET:default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "token-login",

	.drop_priv_before_exec = FALSE,

	.restart_request_count = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue imap_urlauth_login_service_settings_defaults[] = {
	{ "unix_listener", "imap-urlauth" },

	{ "unix_listener/imap-urlauth/path", "imap-urlauth" },
	{ "unix_listener/imap-urlauth/mode", "0666" },

	{ NULL, NULL }
};
static const struct setting_define imap_urlauth_login_setting_defines[] = {
	SETTING_DEFINE_LIST_END
};
const struct setting_parser_info imap_urlauth_login_setting_parser_info = {
	.name = "imap_urlauth_login",

	.defines = imap_urlauth_login_setting_defines,
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap-urlauth/imap-urlauth-settings.c */
extern const struct setting_parser_info imap_urlauth_setting_parser_info;
struct service_settings imap_urlauth_service_settings = {
	.name = "imap-urlauth",
	.protocol = "imap",
	.type = "",
	.executable = "imap-urlauth",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1024,
	.client_limit = 1,
	.restart_request_count = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue imap_urlauth_service_settings_defaults[] = {
	{ "unix_listener", "token-login\\simap-urlauth" },

	{ "unix_listener/token-login\\simap-urlauth/path", "token-login/imap-urlauth" },
	{ "unix_listener/token-login\\simap-urlauth/mode", "0666" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_urlauth_settings)
static const struct setting_define imap_urlauth_setting_defines[] = {
	DEF(STR_HIDDEN, base_dir),

	DEF(BOOL, mail_debug),

	DEF(BOOL, verbose_proctitle),

	DEF(STR_NOVARS, imap_urlauth_logout_format),
	DEF(STR, imap_urlauth_submit_user),
	DEF(STR, imap_urlauth_stream_user),

	SETTING_DEFINE_LIST_END
};
const struct imap_urlauth_settings imap_urlauth_default_settings = {
	.base_dir = PKG_RUNDIR,
  .mail_debug = FALSE,

	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,

	.imap_urlauth_logout_format = "in=%{input} out=%{output}",
	.imap_urlauth_submit_user = "",
	.imap_urlauth_stream_user = "",
};
const struct setting_parser_info imap_urlauth_setting_parser_info = {
	.name = "imap_urlauth",

	.defines = imap_urlauth_setting_defines,
	.defaults = &imap_urlauth_default_settings,

	.struct_size = sizeof(struct imap_urlauth_settings),
	.pool_offset1 = 1 + offsetof(struct imap_urlauth_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap-urlauth/imap-urlauth-worker-settings.c */
extern const struct setting_parser_info imap_urlauth_worker_setting_parser_info;
struct service_settings imap_urlauth_worker_service_settings = {
	.name = "imap-urlauth-worker",
	.protocol = "imap",
	.type = "",
	.executable = "imap-urlauth-worker",
	.user = "",
	.group = "",
	.privileged_group = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1024,
	.client_limit = 1,
	.restart_request_count = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue imap_urlauth_worker_service_settings_defaults[] = {
	{ "unix_listener", IMAP_URLAUTH_WORKER_SOCKET },

	{ "unix_listener/"IMAP_URLAUTH_WORKER_SOCKET"/path", IMAP_URLAUTH_WORKER_SOCKET },
	{ "unix_listener/"IMAP_URLAUTH_WORKER_SOCKET"/mode", "0600" },
	{ "unix_listener/"IMAP_URLAUTH_WORKER_SOCKET"/user", "$SET:default_internal_user" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_urlauth_worker_settings)
static const struct setting_define imap_urlauth_worker_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	SETTING_DEFINE_LIST_END
};
const struct imap_urlauth_worker_settings imap_urlauth_worker_default_settings = {
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143
};
const struct setting_parser_info imap_urlauth_worker_setting_parser_info = {
	.name = "imap_urlauth_worker",

	.defines = imap_urlauth_worker_setting_defines,
	.defaults = &imap_urlauth_worker_default_settings,

	.struct_size = sizeof(struct imap_urlauth_worker_settings),
	.pool_offset1 = 1 + offsetof(struct imap_urlauth_worker_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/imap/imap-settings.c */
extern const struct setting_parser_info imap_setting_parser_info;

/* <settings checks> */
struct imap_client_workaround_list {
	const char *name;
	enum imap_client_workarounds num;
};

static const struct imap_client_workaround_list imap_client_workaround_list[] = {
	{ "delay-newmail", WORKAROUND_DELAY_NEWMAIL },
	{ "tb-extra-mailbox-sep", WORKAROUND_TB_EXTRA_MAILBOX_SEP },
	{ "tb-lsub-flags", WORKAROUND_TB_LSUB_FLAGS },
	{ NULL, 0 }
};

static int
imap_settings_parse_workarounds(struct imap_settings *set,
				const char **error_r)
{
	enum imap_client_workarounds client_workarounds = 0;
	const struct imap_client_workaround_list *list;
	const char *const *str;

	str = settings_boollist_get(&set->imap_client_workarounds);
	for (; *str != NULL; str++) {
		list = imap_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("imap_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}


static bool
imap_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct imap_settings *set = _set;

#ifndef EXPERIMENTAL_MAIL_UTF8
	if (set->mail_utf8_extensions) {
		*error_r = "Dovecot not built with --enable-experimental-mail-utf8";
		return FALSE;
	}
#endif
#ifndef EXPERIMENTAL_IMAP4REV2
	if (set->imap4rev2_enable) {
		*error_r = "Dovecot not built with --enable-experimental-imap4rev2.";
		return FALSE;
	}
#endif

	if (imap_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

	if (strcmp(set->imap_fetch_failure, "disconnect-immediately") == 0)
		set->parsed_fetch_failure = IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_IMMEDIATELY;
	else if (strcmp(set->imap_fetch_failure, "disconnect-after") == 0)
		set->parsed_fetch_failure = IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_AFTER;
	else if (strcmp(set->imap_fetch_failure, "no-after") == 0)
		set->parsed_fetch_failure = IMAP_CLIENT_FETCH_FAILURE_NO_AFTER;
	else {
		*error_r = t_strdup_printf("Unknown imap_fetch_failure: %s",
					   set->imap_fetch_failure);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
struct service_settings imap_service_settings = {
	.name = "imap",
	.protocol = "imap",
	.type = "",
	.executable = "imap",
	.user = "",
	.group = "",
	.privileged_group = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

#ifdef DOVECOT_PRO_EDITION
	.process_limit = 10240,
#else
	.process_limit = 1024,
#endif
	.client_limit = 1,
#ifdef DOVECOT_PRO_EDITION
	.restart_request_count = 1000,
#else
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue imap_service_settings_defaults[] = {
	{ "unix_listener", "imap-master login\\simap srv.imap\\s%{pid}" },

	{ "unix_listener/imap-master/path", "imap-master" },
	{ "unix_listener/imap-master/type", "master" },
	{ "unix_listener/imap-master/mode", "0600" },
#ifdef DOVECOT_PRO_EDITION
	/* Potentially not safe in some setups, so keep it Pro-only */
	{ "unix_listener/imap-master/user", "$SET:default_internal_user" },
#endif

	{ "unix_listener/login\\simap/path", "login/imap" },
	{ "unix_listener/login\\simap/type", "login" },
	{ "unix_listener/login\\simap/mode", "0666" },

	{ "unix_listener/srv.imap\\s%{pid}/path", "srv.imap/%{pid}" },
	{ "unix_listener/srv.imap\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.imap\\s%{pid}/mode", "0600" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_settings)
static const struct setting_define imap_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(BOOL, mailbox_list_index),
	DEF(STR, rawlog_dir),

	DEF(SIZE_HIDDEN, imap_max_line_length),
	DEF(TIME_HIDDEN, imap_idle_notify_interval),
	DEF(BOOLLIST, imap_capability),
	DEF(BOOLLIST, imap_client_workarounds),
	DEF(STR_NOVARS, imap_logout_format),
	DEF(ENUM, imap_fetch_failure),
	DEF(BOOL, imap_metadata),
	DEF(BOOL, imap_literal_minus),
	DEF(BOOL_HIDDEN, imap_compress_on_proxy),
	DEF(BOOL, mail_utf8_extensions),
	DEF(BOOL, imap4rev2_enable),
#ifdef BUILD_IMAP_HIBERNATE
	DEF(TIME, imap_hibernate_timeout),
#endif

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	{ .type = SET_STRLIST, .key = "imap_id_send",
	  .offset = offsetof(struct imap_settings, imap_id_send) },

	SETTING_DEFINE_LIST_END
};
static const struct imap_settings imap_default_settings = {
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,
	.mailbox_list_index = TRUE,
	.rawlog_dir = "",

	/* RFC-2683 recommends at least 8000 bytes. Some clients however don't
	   break large message sets to multiple commands, so we're pretty
	   liberal by default. */
	.imap_max_line_length = 64*1024,
	.imap_idle_notify_interval = 2*60,
	.imap_capability = ARRAY_INIT,
	.imap_client_workarounds = ARRAY_INIT,
	.imap_logout_format = "in=%{input} out=%{output} deleted=%{deleted} "
		"expunged=%{expunged} trashed=%{trashed} "
		"hdr_count=%{fetch_hdr_count} hdr_bytes=%{fetch_hdr_bytes} "
		"body_count=%{fetch_body_count} body_bytes=%{fetch_body_bytes}",
	.imap_id_send = ARRAY_INIT,
	.imap_fetch_failure = "disconnect-immediately:disconnect-after:no-after",
	.imap_metadata = FALSE,
	.imap_literal_minus = FALSE,
	.imap_compress_on_proxy = FALSE,
	.mail_utf8_extensions = FALSE,
	.imap4rev2_enable = FALSE,
#ifdef DOVECOT_PRO_EDITION
	.imap_hibernate_timeout = 30,
#else
	.imap_hibernate_timeout = 0,
#endif

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143
};
static const struct setting_keyvalue imap_default_settings_keyvalue[] = {
	{ "service/imap/imap_capability/IMAP4rev1", "yes" },
	{ "service/imap/imap_capability/IMAP4rev2", "yes" },
	{ "service/imap/imap_capability/SASL-IR", "yes" },
	{ "service/imap/imap_capability/LOGIN-REFERRALS", "yes" },
	{ "service/imap/imap_capability/ID", "yes" },
	{ "service/imap/imap_capability/ENABLE", "yes" },
	{ "service/imap/imap_capability/IDLE", "yes" },
	{ "service/imap/imap_capability/SORT", "yes" },
	{ "service/imap/imap_capability/SORT=DISPLAY", "yes" },
	{ "service/imap/imap_capability/THREAD=REFERENCES", "yes" },
	{ "service/imap/imap_capability/THREAD=REFS", "yes" },
	{ "service/imap/imap_capability/THREAD=ORDEREDSUBJECT", "yes" },
	{ "service/imap/imap_capability/MULTIAPPEND", "yes" },
	{ "service/imap/imap_capability/URL-PARTIAL", "yes" },
	{ "service/imap/imap_capability/CATENATE", "yes" },
	{ "service/imap/imap_capability/UNSELECT", "yes" },
	{ "service/imap/imap_capability/CHILDREN", "yes" },
	{ "service/imap/imap_capability/NAMESPACE", "yes" },
	{ "service/imap/imap_capability/UIDPLUS", "yes" },
	{ "service/imap/imap_capability/LIST-EXTENDED", "yes" },
	{ "service/imap/imap_capability/I18NLEVEL=1", "yes" },
	{ "service/imap/imap_capability/CONDSTORE", "yes" },
	{ "service/imap/imap_capability/QRESYNC", "yes" },
	{ "service/imap/imap_capability/ESEARCH", "yes" },
	{ "service/imap/imap_capability/ESORT", "yes" },
	{ "service/imap/imap_capability/SEARCHRES", "yes" },
	{ "service/imap/imap_capability/WITHIN", "yes" },
	{ "service/imap/imap_capability/CONTEXT=SEARCH", "yes" },
	{ "service/imap/imap_capability/LIST-STATUS", "yes" },
	{ "service/imap/imap_capability/BINARY", "yes" },
	{ "service/imap/imap_capability/MOVE", "yes" },
	{ "service/imap/imap_capability/REPLACE", "yes" },
	{ "service/imap/imap_capability/SNIPPET=FUZZY", "yes" },
	{ "service/imap/imap_capability/PREVIEW=FUZZY", "yes" },
	{ "service/imap/imap_capability/PREVIEW", "yes" },
	{ "service/imap/imap_capability/SPECIAL-USE", "yes" },
	{ "service/imap/imap_capability/STATUS=SIZE", "yes" },
	{ "service/imap/imap_capability/SAVEDATE", "yes" },
	{ "service/imap/imap_capability/COMPRESS=DEFLATE", "yes" },
	{ "service/imap/imap_capability/INPROGRESS", "yes" },
	{ "service/imap/imap_capability/NOTIFY", "yes" },
	{ "service/imap/imap_capability/METADATA", "yes" },
	{ "service/imap/imap_capability/SPECIAL-USE", "yes" },
	{ "service/imap/imap_capability/LITERAL+", "yes" },
	{ "service/imap/imap_capability/LITERAL-", "yes" },
	{ "service/imap/imap_capability/UTF8=ACCEPT", "yes" },
#ifdef DOVECOT_PRO_EDITION
	{ "service/imap/process_shutdown_filter", "event=mail_user_session_finished AND rss > 20MB" },
#endif
	{ "imap_id_send/name", DOVECOT_NAME },
	{ NULL, NULL },
};
const struct setting_parser_info imap_setting_parser_info = {
	.name = "imap",

	.defines = imap_setting_defines,
	.defaults = &imap_default_settings,
	.default_settings = imap_default_settings_keyvalue,

	.struct_size = sizeof(struct imap_settings),
	.pool_offset1 = 1 + offsetof(struct imap_settings, pool),
	.check_func = imap_settings_verify,
};
/* /home/gromy/Документы/Development/dovecot-core/src/indexer/indexer-settings.c */
struct service_settings indexer_service_settings = {
	.name = "indexer",
	.protocol = "",
	.type = "",
	.executable = "indexer",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
const struct setting_keyvalue indexer_service_settings_defaults[] = {
	{ "unix_listener", "indexer" },

	{ "unix_listener/indexer/path", "indexer" },
	{ "unix_listener/indexer/mode", "0666" },

	{ NULL, NULL }
};
/* /home/gromy/Документы/Development/dovecot-core/src/indexer/indexer-worker-settings.c */
struct service_settings indexer_worker_service_settings = {
	.name = "indexer-worker",
	.protocol = "",
	.type = "worker",
	.executable = "indexer-worker",
	.user = "",
	.group = "",
	.privileged_group = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 10,
	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue indexer_worker_service_settings_defaults[] = {
	{ "unix_listener", "indexer-worker srv.indexer-worker\\s%{pid}" },

	{ "unix_listener/indexer-worker/path", "indexer-worker" },
	{ "unix_listener/indexer-worker/mode", "0600" },
	{ "unix_listener/indexer-worker/user", "$SET:default_internal_user" },

	{ "unix_listener/srv.indexer-worker\\s%{pid}/path", "srv.indexer-worker/%{pid}" },
	{ "unix_listener/srv.indexer-worker\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.indexer-worker\\s%{pid}/mode", "0600" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-compression/ostream-bzlib.c */
extern const struct setting_parser_info bzlib_setting_parser_info;
#ifdef HAVE_BZLIB
struct bzlib_settings {
	pool_t pool;
	unsigned int compress_bz2_block_size_100k;
};
#endif
#ifdef HAVE_BZLIB
#undef DEF
#endif
#ifdef HAVE_BZLIB
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct bzlib_settings)
#endif
#ifdef HAVE_BZLIB
static const struct setting_define bzlib_setting_defines[] = {
	DEF(UINT, compress_bz2_block_size_100k),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef HAVE_BZLIB
static const struct bzlib_settings bzlib_default_settings = {
	.compress_bz2_block_size_100k = 9,
};
#endif
#ifdef HAVE_BZLIB
const struct setting_parser_info bzlib_setting_parser_info = {
	.name = "bzlib",

	.defines = bzlib_setting_defines,
	.defaults = &bzlib_default_settings,

	.struct_size = sizeof(struct bzlib_settings),
	.pool_offset1 = 1 + offsetof(struct bzlib_settings, pool),
#ifndef CONFIG_BINARY
	.check_func = bzlib_settings_check,
#endif
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/lib-compression/ostream-zlib.c */
extern const struct setting_parser_info zlib_setting_parser_info;
struct zlib_settings {
	pool_t pool;
	unsigned int compress_gz_level;
	unsigned int compress_deflate_level;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct zlib_settings)
static const struct setting_define zlib_setting_defines[] = {
	DEF(UINT, compress_gz_level),
	DEF(UINT, compress_deflate_level),

	SETTING_DEFINE_LIST_END
};
static const struct zlib_settings zlib_default_settings = {
	.compress_gz_level = 6,
	.compress_deflate_level = 6,
};
const struct setting_parser_info zlib_setting_parser_info = {
	.name = "zlib",

	.defines = zlib_setting_defines,
	.defaults = &zlib_default_settings,

	.struct_size = sizeof(struct zlib_settings),
	.pool_offset1 = 1 + offsetof(struct zlib_settings, pool),
#ifndef CONFIG_BINARY
	.check_func = zlib_settings_check,
#endif
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-compression/ostream-zstd.c */
extern const struct setting_parser_info zstd_setting_parser_info;
#ifdef HAVE_ZSTD
struct zstd_settings {
	pool_t pool;
	unsigned int compress_zstd_level;
};
#endif
#ifdef HAVE_ZSTD
#undef DEF
#endif
#ifdef HAVE_ZSTD
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct zstd_settings)
#endif
#ifdef HAVE_ZSTD
static const struct setting_define zstd_setting_defines[] = {
	DEF(UINT, compress_zstd_level),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef HAVE_ZSTD
static const struct zstd_settings zstd_default_settings = {
	.compress_zstd_level = 3,
};
#endif
#ifdef HAVE_ZSTD
const struct setting_parser_info zstd_setting_parser_info = {
	.name = "zstd",

	.defines = zstd_setting_defines,
	.defaults = &zstd_default_settings,

	.struct_size = sizeof(struct zstd_settings),
	.pool_offset1 = 1 + offsetof(struct zstd_settings, pool),
#ifndef CONFIG_BINARY
	.check_func = zstd_settings_check,
#endif
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict-backend/dict-cdb.c */
extern const struct setting_parser_info cdb_setting_parser_info;
#ifdef BUILD_CDB
struct dict_cdb_settings {
	pool_t pool;

	const char *cdb_path;
};
#endif
#ifdef BUILD_CDB
#undef DEF
#endif
#ifdef BUILD_CDB
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct dict_cdb_settings)
#endif
#ifdef BUILD_CDB
static const struct setting_define cdb_setting_defines[] = {
	DEF(STR, cdb_path),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef BUILD_CDB
static const struct dict_cdb_settings cdb_default_settings = {
	.cdb_path = "",
};
#endif
#ifdef BUILD_CDB
const struct setting_parser_info cdb_setting_parser_info = {
	.name = "dict_cdb",

	.defines = cdb_setting_defines,
	.defaults = &cdb_default_settings,

	.struct_size = sizeof(struct dict_cdb_settings),
	.pool_offset1 = 1 + offsetof(struct dict_cdb_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict-backend/dict-ldap-settings.c */
extern const struct setting_parser_info dict_ldap_map_setting_parser_info;
extern const struct setting_parser_info dict_ldap_map_pre_setting_parser_info;
extern const struct setting_parser_info dict_ldap_map_post_setting_parser_info;
extern const struct setting_parser_info dict_ldap_setting_parser_info;
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
/* <settings checks> */
#include "ldap-settings-parse.h"

static bool
dict_ldap_map_settings_post_check(void *set, pool_t pool, const char **error_r);

/* </settings checks> */
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
/* <settings checks> */

static bool
dict_ldap_map_settings_post_check(void *_set, pool_t pool,
				  const char **error_r ATTR_UNUSED)
{
	struct dict_ldap_map_post_settings *set = _set;
	p_array_init(&set->values, pool, 1);
	if (*set->value != '\0')
		array_push_back(&set->values, &set->value);
	return TRUE;
}

/* </settings checks> */
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#undef DEF
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#undef DEFN
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_"#name, name, struct dict_ldap_map_settings)
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#define DEFN(type, field, name) \
	SETTING_DEFINE_STRUCT_##type(#name, field, struct dict_ldap_map_settings)
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
static const struct setting_define dict_ldap_map_setting_defines[] = {
	DEF(STR, pattern),
	DEFN(STR, base, ldap_base),
	DEFN(ENUM, scope, ldap_scope),
	SETTING_DEFINE_LIST_END
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
static const struct dict_ldap_map_settings dict_ldap_map_default_settings = {
	.pattern = "",
	.base = "",
	.scope = "subtree:onelevel:base",
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
const struct setting_parser_info dict_ldap_map_setting_parser_info = {
	.name = "dict_ldap_map",

	.defines = dict_ldap_map_setting_defines,
	.defaults = &dict_ldap_map_default_settings,

	.struct_size = sizeof(struct dict_ldap_map_settings),
	.pool_offset1 = 1 + offsetof(struct dict_ldap_map_settings, pool),
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#undef DEFN
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#define DEFN(type, field, name) \
	SETTING_DEFINE_STRUCT_##type(#name, field, struct dict_ldap_map_pre_settings)
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
static const struct setting_define dict_ldap_map_pre_setting_defines[] = {
	DEFN(STR, filter, dict_map_ldap_filter),
	SETTING_DEFINE_LIST_END
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
static const struct dict_ldap_map_pre_settings dict_ldap_map_pre_default_settings = {
	.filter = "",
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
const struct setting_parser_info dict_ldap_map_pre_setting_parser_info = {
	.name = "dict_ldap_map_pre",

	.defines = dict_ldap_map_pre_setting_defines,
	.defaults = &dict_ldap_map_pre_default_settings,

	.struct_size = sizeof(struct dict_ldap_map_pre_settings),
	.pool_offset1 = 1 + offsetof(struct dict_ldap_map_pre_settings, pool),
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#undef DEF
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_"#name, name, struct dict_ldap_map_post_settings)
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
static const struct setting_define dict_ldap_map_post_setting_defines[] = {
	DEF(STR, value),
	SETTING_DEFINE_LIST_END
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
static const struct dict_ldap_map_post_settings dict_ldap_map_post_default_settings = {
	.value = "",
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
const struct setting_parser_info dict_ldap_map_post_setting_parser_info = {
	.name = "dict_ldap_map_post",

	.defines = dict_ldap_map_post_setting_defines,
	.defaults = &dict_ldap_map_post_default_settings,
	.check_func = dict_ldap_map_settings_post_check,

	.struct_size = sizeof(struct dict_ldap_map_post_settings),
	.pool_offset1 = 1 + offsetof(struct dict_ldap_map_post_settings, pool),
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#undef DEF
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("ldap_"#name, name, struct dict_ldap_settings)
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
static const struct setting_define dict_ldap_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = "dict_map",
	  .offset = offsetof(struct dict_ldap_settings, maps),
	  .filter_array_field_name = "dict_map_pattern", },
	SETTING_DEFINE_LIST_END
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
static const struct dict_ldap_settings dict_ldap_default_settings = {
	.maps = ARRAY_INIT,
};
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
const struct setting_parser_info dict_ldap_setting_parser_info = {
	.name = "dict_ldap",

	.defines = dict_ldap_setting_defines,
	.defaults = &dict_ldap_default_settings,

	.struct_size = sizeof(struct dict_ldap_settings),
	.pool_offset1 = 1 + offsetof(struct dict_ldap_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict-backend/dict-sql-settings.c */
extern const struct setting_parser_info dict_map_key_field_setting_parser_info;
extern const struct setting_parser_info dict_map_value_field_setting_parser_info;
extern const struct setting_parser_info dict_map_setting_parser_info;

/* <settings checks> */
#define DICT_MAP_FIELD_TYPES_ENUM \
	"string:int:uint:double:hexblob:uuid"
/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_key_field_"#name, name, struct dict_map_key_field_settings)
static const struct setting_define dict_map_key_field_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, value),
	DEF(ENUM, type),

	SETTING_DEFINE_LIST_END
};
static const struct dict_map_key_field_settings dict_map_key_field_default_settings = {
	.name = "",
	.type = DICT_MAP_FIELD_TYPES_ENUM,
	.value = "",
};
const struct setting_parser_info dict_map_key_field_setting_parser_info = {
	.name = "dict_map_key_field",

	.defines = dict_map_key_field_setting_defines,
	.defaults = &dict_map_key_field_default_settings,

	.struct_size = sizeof(struct dict_map_key_field_settings),
	.pool_offset1 = 1 + offsetof(struct dict_map_key_field_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_value_field_"#name, name, struct dict_map_value_field_settings)
static const struct setting_define dict_map_value_field_setting_defines[] = {
	DEF(STR, name),
	DEF(ENUM, type),

	SETTING_DEFINE_LIST_END
};
static const struct dict_map_value_field_settings dict_map_value_field_default_settings = {
	.name = "",
	.type = DICT_MAP_FIELD_TYPES_ENUM,
};
const struct setting_parser_info dict_map_value_field_setting_parser_info = {
	.name = "dict_map_value_field",

	.defines = dict_map_value_field_setting_defines,
	.defaults = &dict_map_value_field_default_settings,

	.struct_size = sizeof(struct dict_map_value_field_settings),
	.pool_offset1 = 1 + offsetof(struct dict_map_value_field_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("dict_map_"#name, name, struct dict_map_settings)
static const struct setting_define dict_map_setting_defines[] = {
	DEF(STR, pattern),
	DEF(STR, sql_table),
	DEF(STR, username_field),
	DEF(STR, expire_field),
	{ .type = SET_FILTER_ARRAY, .key = "dict_map_key_field",
	  .offset = offsetof(struct dict_map_settings, fields),
	  .filter_array_field_name = "dict_map_key_field_name", },
	{ .type = SET_FILTER_ARRAY, .key = "dict_map_value_field",
	  .offset = offsetof(struct dict_map_settings, values),
	  .filter_array_field_name = "dict_map_value_field_name", },

	{ .type = SET_FILTER_ARRAY, .key = "dict_map",
	  .offset = offsetof(struct dict_map_settings, maps),
	  .filter_array_field_name = "dict_map_pattern", },

	SETTING_DEFINE_LIST_END
};
static const struct dict_map_settings dict_map_default_settings = {
	.pattern = "",
	.sql_table = "",
	.username_field = "",
	.expire_field = "",
};
const struct setting_parser_info dict_map_setting_parser_info = {
	.name = "dict_map",

	.defines = dict_map_setting_defines,
	.defaults = &dict_map_default_settings,

	.struct_size = sizeof(struct dict_map_settings),
	.pool_offset1 = 1 + offsetof(struct dict_map_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-imap-client/imapc-settings.c */
extern const struct setting_parser_info imapc_setting_parser_info;

/* <settings checks> */
struct imapc_feature_list {
	const char *name;
	enum imapc_features num;
};

static const struct imapc_feature_list imapc_feature_list[] = {
	{ "no-fetch-size", IMAPC_FEATURE_NO_FETCH_SIZE },
	{ "guid-forced", IMAPC_FEATURE_GUID_FORCED },
	{ "no-fetch-headers", IMAPC_FEATURE_NO_FETCH_HEADERS },
	{ "gmail-migration", IMAPC_FEATURE_GMAIL_MIGRATION },
	{ "no-search", IMAPC_FEATURE_NO_SEARCH },
	{ "zimbra-workarounds", IMAPC_FEATURE_ZIMBRA_WORKAROUNDS },
	{ "no-examine", IMAPC_FEATURE_NO_EXAMINE },
	{ "proxyauth", IMAPC_FEATURE_PROXYAUTH },
	{ "fetch-msn-workarounds", IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS },
	{ "fetch-fix-broken-mails", IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS },
	{ "no-modseq", IMAPC_FEATURE_NO_MODSEQ },
	{ "no-delay-login", IMAPC_FEATURE_NO_DELAY_LOGIN },
	{ "no-fetch-bodystructure", IMAPC_FEATURE_NO_FETCH_BODYSTRUCTURE },
	{ "send-id", IMAPC_FEATURE_SEND_ID },
	{ "fetch-empty-is-expunged", IMAPC_FEATURE_FETCH_EMPTY_IS_EXPUNGED },
	{ "no-msn-updates", IMAPC_FEATURE_NO_MSN_UPDATES },
	{ "no-acl", IMAPC_FEATURE_NO_ACL },
	{ "no-metadata", IMAPC_FEATURE_NO_METADATA },
	{ "no-qresync", IMAPC_FEATURE_NO_QRESYNC },
	{ "no-imap4rev2", IMAPC_FEATURE_NO_IMAP4REV2 },
	{ NULL, 0 }
};

static int
imapc_settings_parse_throttle(struct imapc_settings *set,
			      const char *throttle_str, const char **error_r)
{
	const char *const *tmp;

	tmp = t_strsplit(throttle_str, ":");
	if (str_array_length(tmp) != 3 ||
	    str_to_uint(tmp[0], &set->throttle_init_msecs) < 0 ||
	    str_to_uint(tmp[1], &set->throttle_max_msecs) < 0 ||
	    str_to_uint(tmp[2], &set->throttle_shrink_min_msecs) < 0) {
		*error_r = "imapc_features: Invalid throttle settings";
		return -1;
	}
	return 0;
}

static int
imapc_settings_parse_features(struct imapc_settings *set,
			      const char **error_r)
{
	enum imapc_features features = 0;
	const struct imapc_feature_list *list;
	const char *const *str, *value;

	str = settings_boollist_get(&set->imapc_features);
	for (; *str != NULL; str++) {
		list = imapc_feature_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (str_begins_icase(*str, "throttle:", &value)) {
			if (imapc_settings_parse_throttle(set, value, error_r) < 0)
				return -1;
			continue;
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("imapc_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool imapc_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct imapc_settings *set = _set;

	if (set->imapc_max_idle_time_secs == 0) {
		*error_r = "imapc_max_idle_time must not be 0";
		return FALSE;
	}
	if (set->imapc_max_line_length == 0) {
		*error_r = "imapc_max_line_length must not be 0";
		return FALSE;
	}
	if (imapc_settings_parse_features(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imapc_settings)
#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name##_msecs, struct imapc_settings)
#undef DEF_SECS
#define DEF_SECS(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name##_secs, struct imapc_settings)
static const struct setting_define imapc_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "imapc" },
	{ .type = SET_FILTER_NAME, .key = "layout_imapc" },
	DEF(STR, imapc_host),
	DEF(IN_PORT, imapc_port),

	DEF(STR, imapc_user),
	DEF(STR, imapc_master_user),
	DEF(STR, imapc_password),
	DEF(BOOLLIST, imapc_sasl_mechanisms),

	DEF(ENUM, imapc_ssl),

	DEF(BOOLLIST, imapc_features),
	DEF(STR, imapc_rawlog_dir),
	DEF(STR, imapc_list_prefix),
	DEF_SECS(TIME, imapc_cmd_timeout),
	DEF_SECS(TIME, imapc_max_idle_time),
	DEF_MSECS(TIME_MSECS, imapc_connection_timeout_interval),
	DEF(UINT, imapc_connection_retry_count),
	DEF_MSECS(TIME_MSECS, imapc_connection_retry_interval),
	DEF(SIZE, imapc_max_line_length),

	DEF(STR, pop3_deleted_flag),

	SETTING_DEFINE_LIST_END
};
static const struct imapc_settings imapc_default_settings = {
	.imapc_host = "",
	.imapc_port = 143,

	.imapc_user = "%{owner_user}",
	.imapc_master_user = "",
	.imapc_password = "",
	.imapc_sasl_mechanisms = ARRAY_INIT,

	.imapc_ssl = "no:imaps:starttls",

	.imapc_features = ARRAY_INIT,
	.imapc_rawlog_dir = "",
	.imapc_list_prefix = "",
	.imapc_cmd_timeout_secs = 5*60,
	.imapc_max_idle_time_secs = IMAPC_DEFAULT_MAX_IDLE_TIME,
	.imapc_connection_timeout_interval_msecs = 1000*30,
	.imapc_connection_retry_count = 1,
	.imapc_connection_retry_interval_msecs = 1000,
	.imapc_max_line_length = SET_SIZE_UNLIMITED,

	.pop3_deleted_flag = "",
};
static const struct setting_keyvalue imapc_default_settings_keyvalue[] = {
	{ "imapc/mailbox_list_layout", "imapc" },
	/* We want to have all imapc mailboxes accessible, so escape them if
	   necessary. */
	{ "layout_imapc/mailbox_list_visible_escape_char", "~" },
	{ "layout_imapc/mailbox_list_storage_escape_char", "%" },
	{ NULL, NULL }
};
const struct setting_parser_info imapc_setting_parser_info = {
	.name = "imapc",

	.defines = imapc_setting_defines,
	.defaults = &imapc_default_settings,
	.default_settings = imapc_default_settings_keyvalue,

	.struct_size = sizeof(struct imapc_settings),
	.pool_offset1 = 1 + offsetof(struct imapc_settings, pool),

	.check_func = imapc_settings_check
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-language/lang-settings.c */
extern const struct setting_parser_info lang_setting_parser_info;
extern const struct setting_parser_info langs_setting_parser_info;

/* <settings checks> */
static bool langs_settings_ext_check(struct event *event, void *_set,
				     pool_t pool, const char **error_r);
/* </settings checks> */

/* <settings checks> */

static bool langs_settings_ext_check(struct event *event, void *_set,
				     pool_t pool, const char **error_r)
{
	struct langs_settings *set = _set;
	if (array_is_empty(&set->languages)) {
#ifdef CONFIG_BINARY
		return TRUE;
#else
		*error_r = "No language { .. } defined";
		return FALSE;
#endif
	}

	const char *lang_default = NULL;
	const char *filter_name;
	unsigned int nondata_languages = 0;
	p_array_init(&set->parsed_languages, pool, array_count(&set->languages));
	array_foreach_elem(&set->languages, filter_name) {
		const struct lang_settings *lang_set;
		const char *error;

		if (settings_get_filter(event, "language", filter_name,
					&lang_setting_parser_info, 0,
					&lang_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get language %s: %s",
				filter_name, error);
			return FALSE;
		}

		bool is_data = strcmp(lang_set->name, LANGUAGE_DATA) == 0;

		if (lang_set->is_default) {
			if (is_data) {
				*error_r = "language "LANGUAGE_DATA" cannot have { default = yes }";
				settings_free(lang_set);
				return FALSE;
			}

			if (lang_default != NULL) {
				*error_r = t_strdup_printf(
					"Only one language with with { default = yes } is allowed"
					" (default is '%s', cannot set '%s' too)",
					lang_default, lang_set->name);
				settings_free(lang_set);
				return FALSE;
			}
			lang_default = t_strdup(lang_set->name);
		}

		if (!is_data)
			nondata_languages++;

		struct lang_settings *lang_set_dup =
			p_memdup(pool, lang_set, sizeof(*lang_set));
		pool_add_external_ref(pool, lang_set->pool);
		if (lang_set->is_default)
			array_push_front(&set->parsed_languages, &lang_set_dup);
		else
			array_push_back(&set->parsed_languages, &lang_set_dup);
		settings_free(lang_set);
	}

	if (nondata_languages == 0) {
		*error_r = "No valid languages";
		return FALSE;
	}

	if (lang_default == NULL) {
		*error_r = "No language with { default = yes } found";
		return FALSE;
	}

	return TRUE;
}

/* </settings checks> */
#undef DEF
#define DEF(_type, name) SETTING_DEFINE_STRUCT_##_type( \
	"language_"#name, name, struct lang_settings)
static const struct setting_define lang_setting_defines[] = {
	DEF(STR, name),
	SETTING_DEFINE_STRUCT_BOOL("language_default", is_default, struct lang_settings),
	DEF(BOOLLIST, filters),
	DEF(STR,  filter_normalizer_icu_id),
	DEF(STR,  filter_stopwords_dir),
	DEF(BOOLLIST, tokenizers),
	DEF(UINT, tokenizer_address_token_maxlen),
	DEF(STR,  tokenizer_generic_algorithm),
	DEF(BOOL, tokenizer_generic_explicit_prefix),
	DEF(UINT, tokenizer_generic_token_maxlen),
	DEF(BOOL, tokenizer_generic_wb5a),
	SETTING_DEFINE_LIST_END
};
const struct lang_settings lang_default_settings = {
	.name = "",
	.is_default = FALSE,
	.filters = ARRAY_INIT,
	.filter_normalizer_icu_id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC; [\\x20] Remove",
	.filter_stopwords_dir = DATADIR"/stopwords",
	.tokenizers = ARRAY_INIT,
	.tokenizer_address_token_maxlen = 250,
	.tokenizer_generic_algorithm = "simple",
	.tokenizer_generic_explicit_prefix = FALSE,
	.tokenizer_generic_token_maxlen = 30,
	.tokenizer_generic_wb5a = FALSE,
};
const struct setting_parser_info lang_setting_parser_info = {
	.name = "language",

	.defines = lang_setting_defines,
	.defaults = &lang_default_settings,

	.struct_size = sizeof(struct lang_settings),
	.pool_offset1 = 1 + offsetof(struct lang_settings, pool),
};
#undef DEF
#define DEF(_type, name) SETTING_DEFINE_STRUCT_##_type( \
	#name, name, struct langs_settings)
static const struct setting_define langs_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = "language",
	  .offset = offsetof(struct langs_settings, languages),
	  .filter_array_field_name = "language_name", },
	DEF(STR, textcat_config_path),
	SETTING_DEFINE_LIST_END
};
static const struct langs_settings langs_default_settings = {
	.textcat_config_path = "",
};
const struct setting_parser_info langs_setting_parser_info = {
	.name = "languages",

	.defines = langs_setting_defines,
	.defaults = &langs_default_settings,
	.ext_check_func = langs_settings_ext_check,

	.struct_size = sizeof(struct langs_settings),
	.pool_offset1 = 1 + offsetof(struct langs_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-lda/lda-settings.c */
extern const struct setting_parser_info lda_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct lda_settings)
static const struct setting_define lda_setting_defines[] = {
	DEF(STR, hostname),
	DEF(STR_NOVARS, rejection_subject),
	DEF(STR_NOVARS, rejection_reason),
	DEF(STR_NOVARS, deliver_log_format),
	DEF(STR, recipient_delimiter),
	DEF(STR, lda_original_recipient_header),
	DEF(BOOL, quota_full_tempfail),
	DEF(BOOL, lda_mailbox_autocreate),
	DEF(BOOL, lda_mailbox_autosubscribe),

	SETTING_DEFINE_LIST_END
};
static const struct lda_settings lda_default_settings = {
	.hostname = "",
	.rejection_subject = "Rejected: %{subject}",
	.rejection_reason =
		"Your message to <%{to}> was automatically rejected:%{literal('\\r\\n')}%{reason}",
	.deliver_log_format = "msgid=%{msgid}: %{message}",
	.recipient_delimiter = "+",
	.lda_original_recipient_header = "",
	.quota_full_tempfail = FALSE,
	.lda_mailbox_autocreate = FALSE,
	.lda_mailbox_autosubscribe = FALSE
};
const struct setting_parser_info lda_setting_parser_info = {
	.name = "lda",

	.defines = lda_setting_defines,
	.defaults = &lda_default_settings,

	.struct_size = sizeof(struct lda_settings),
	.pool_offset1 = 1 + offsetof(struct lda_settings, pool),
#ifndef CONFIG_BINARY
	.check_func = lda_settings_check,
#endif
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-ldap/ldap-settings.c */
extern const struct setting_parser_info ldap_client_setting_parser_info;
#undef DEF
#undef DEFN
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("ldap_"#name, name, struct ldap_client_settings)
#define DEFN(type, field, name) \
	SETTING_DEFINE_STRUCT_##type(#name, field, struct ldap_client_settings)
static const struct setting_define ldap_client_setting_defines[] = {
	DEF(STR, uris),
	DEF(STR, auth_dn),
	DEF(STR, auth_dn_password),
	DEFN(TIME, timeout_secs, ldap_timeout),
	DEFN(TIME, max_idle_time_secs, ldap_max_idle_time),
	DEF(UINT, debug_level),
	DEF(BOOL, starttls),
	SETTING_DEFINE_LIST_END
};
static const struct ldap_client_settings ldap_client_default_settings = {
	.uris = "",
	.auth_dn = "",
	.auth_dn_password = "",
	.timeout_secs = 30,
	.max_idle_time_secs = 0,
	.debug_level = 0,
	.starttls = FALSE,
};
const struct setting_parser_info ldap_client_setting_parser_info = {
	.name = "ldap",

	.defines = ldap_client_setting_defines,
	.defaults = &ldap_client_default_settings,

	.struct_size = sizeof(struct ldap_client_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_client_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-lua/dlua-script.c */
extern const struct setting_parser_info dlua_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("lua_"#name, name, struct dlua_settings)
static const struct setting_define dlua_setting_defines[] = {
	DEF(FILE, file),
	DEF(STRLIST, settings),

	SETTING_DEFINE_LIST_END
};
static const struct dlua_settings dlua_default_settings = {
	.file = "",
	.settings = ARRAY_INIT,
};
const struct setting_parser_info dlua_setting_parser_info = {
	.name = "dlua",

	.defines = dlua_setting_defines,
	.defaults = &dlua_default_settings,

	.struct_size = sizeof(struct dlua_settings),
	.pool_offset1 = 1 + offsetof(struct dlua_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-sql/driver-cassandra.c */
extern const struct setting_parser_info cassandra_setting_parser_info;
#ifdef BUILD_CASSANDRA
/* <settings checks> */
#include <cassandra.h>
/* </settings checks> */
#endif
#ifdef BUILD_CASSANDRA
/* <settings checks> */
static bool
cassandra_settings_check(void *_set, pool_t pool, const char **error_r);

struct cassandra_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) hosts;
	in_port_t port;
	const char *keyspace;
	const char *user;
	const char *password;

	const char *metrics_path;
	const char *log_level;
	bool debug_queries;
	bool log_retries;
	bool latency_aware_routing;

	const char *read_consistency;
	const char *write_consistency;
	const char *delete_consistency;
	const char *read_fallback_consistency;
	const char *write_fallback_consistency;
	const char *delete_fallback_consistency;

	unsigned int connect_timeout_msecs;
	unsigned int request_timeout_msecs;
	unsigned int warn_timeout_msecs;

	unsigned int protocol_version;
	unsigned int io_thread_count;
	unsigned int heartbeat_interval_secs;
	unsigned int idle_timeout_secs;
	unsigned int execution_retry_interval_msecs;
	unsigned int execution_retry_times;
	unsigned int page_size;

	const char *ssl;

	/* generated: */
	CassLogLevel parsed_log_level;
	CassConsistency parsed_read_consistency;
	CassConsistency parsed_write_consistency;
	CassConsistency parsed_delete_consistency;
	CassConsistency parsed_read_fallback_consistency;
	CassConsistency parsed_write_fallback_consistency;
	CassConsistency parsed_delete_fallback_consistency;
	bool parsed_use_ssl;
	CassSslVerifyFlags parsed_ssl_verify_flags;
};
/* </settings checks> */
#endif
#ifdef BUILD_CASSANDRA
/* <settings checks> */
static struct {
	CassConsistency consistency;
	const char *name;
} cass_consistency_names[] = {
	{ CASS_CONSISTENCY_ANY, "any" },
	{ CASS_CONSISTENCY_ONE, "one" },
	{ CASS_CONSISTENCY_TWO, "two" },
	{ CASS_CONSISTENCY_THREE, "three" },
	{ CASS_CONSISTENCY_QUORUM, "quorum" },
	{ CASS_CONSISTENCY_ALL, "all" },
	{ CASS_CONSISTENCY_LOCAL_QUORUM, "local-quorum" },
	{ CASS_CONSISTENCY_EACH_QUORUM, "each-quorum" },
	{ CASS_CONSISTENCY_SERIAL, "serial" },
	{ CASS_CONSISTENCY_LOCAL_SERIAL, "local-serial" },
	{ CASS_CONSISTENCY_LOCAL_ONE, "local-one" }
};

static struct {
	CassLogLevel log_level;
	const char *name;
} cass_log_level_names[] = {
	{ CASS_LOG_CRITICAL, "critical" },
	{ CASS_LOG_ERROR, "error" },
	{ CASS_LOG_WARN, "warn" },
	{ CASS_LOG_INFO, "info" },
	{ CASS_LOG_DEBUG, "debug" },
	{ CASS_LOG_TRACE, "trace" }
};
/* </settings checks> */
#endif
#ifdef BUILD_CASSANDRA
/* <settings checks> */
static int consistency_parse(const char *str, CassConsistency *consistency_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(cass_consistency_names); i++) {
		if (strcmp(cass_consistency_names[i].name, str) == 0) {
			*consistency_r = cass_consistency_names[i].consistency;
			return 0;
		}
	}
	return -1;
}

static int log_level_parse(const char *str, CassLogLevel *log_level_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(cass_log_level_names); i++) {
		if (strcmp(cass_log_level_names[i].name, str) == 0) {
			*log_level_r = cass_log_level_names[i].log_level;
			return 0;
		}
	}
	return -1;
}

static bool
cassandra_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			 const char **error_r)
{
	struct cassandra_settings *set = _set;
	const struct {
		const char *set_name;
		const char *set_value;
		const CassConsistency *empty_default;
		CassConsistency *output;
	} consistencies[] = {
		{ "read_consistency", set->read_consistency, NULL,
		  &set->parsed_read_consistency },
		{ "write_consistency", set->write_consistency, NULL,
		  &set->parsed_write_consistency },
		{ "delete_consistency", set->delete_consistency, NULL,
		  &set->parsed_delete_consistency },
		/* Parse fallback consistencies after the ones above, so
		   empty_default can access already checked consistency
		   values. */
		{ "read_fallback_consistency", set->read_fallback_consistency,
		  &set->parsed_read_consistency,
		  &set->parsed_read_fallback_consistency },
		{ "write_fallback_consistency", set->write_fallback_consistency,
		  &set->parsed_write_consistency,
		  &set->parsed_write_fallback_consistency },
		{ "delete_fallback_consistency", set->delete_fallback_consistency,
		  &set->parsed_delete_consistency,
		  &set->parsed_delete_fallback_consistency },
	};

	for (unsigned int i = 0; i < N_ELEMENTS(consistencies); i++) {
		if (consistencies[i].set_value[0] == '\0' &&
		    consistencies[i].empty_default != NULL) {
			*consistencies[i].output =
				*consistencies[i].empty_default;
		} else if (consistency_parse(consistencies[i].set_value,
					     consistencies[i].output) < 0) {
			*error_r = t_strdup_printf(
				"Unknown cassandra_%s: %s",
				consistencies[i].set_name,
				consistencies[i].set_value);
			return FALSE;
		}
	}
	if (log_level_parse(set->log_level, &set->parsed_log_level) < 0) {
		*error_r = t_strdup_printf(
			"Unknown cassandra_log_level: %s", set->log_level);
		return FALSE;
	}

	if (strcmp(set->ssl, "no") != 0) {
		set->parsed_use_ssl = TRUE;
		if (strcmp(set->ssl, "cert-only") == 0) {
			set->parsed_ssl_verify_flags =
				CASS_SSL_VERIFY_PEER_CERT;
		} else if (strcmp(set->ssl, "cert-ip") == 0) {
			set->parsed_ssl_verify_flags =
				CASS_SSL_VERIFY_PEER_CERT |
				CASS_SSL_VERIFY_PEER_IDENTITY;
		} else {
			*error_r = t_strdup_printf(
				"Unsupported cassandra_ssl: '%s'", set->ssl);
			return FALSE;
		}
	}
	return TRUE;
}
/* </settings checks> */
#endif
#ifdef BUILD_CASSANDRA
#define CASS_QUERY_DEFAULT_WARN_TIMEOUT_MSECS (5*1000)
#endif
#ifdef BUILD_CASSANDRA
#undef DEF
#endif
#ifdef BUILD_CASSANDRA
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("cassandra_"#name, name, struct cassandra_settings)
#endif
#ifdef BUILD_CASSANDRA
#undef DEF_SECS
#endif
#ifdef BUILD_CASSANDRA
#define DEF_SECS(name) \
	SETTING_DEFINE_STRUCT_TIME("cassandra_"#name, name##_secs, struct cassandra_settings)
#endif
#ifdef BUILD_CASSANDRA
#undef DEF_MSECS
#endif
#ifdef BUILD_CASSANDRA
#define DEF_MSECS(name) \
	SETTING_DEFINE_STRUCT_TIME_MSECS("cassandra_"#name, name##_msecs, struct cassandra_settings)
#endif
#ifdef BUILD_CASSANDRA
static const struct setting_define cassandra_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "cassandra", },

	DEF(BOOLLIST, hosts),
	DEF(IN_PORT, port),
	DEF(STR, keyspace),
	DEF(STR, user),
	DEF(STR, password),

	DEF(STR, metrics_path),
	DEF(ENUM, log_level),
	DEF(BOOL, debug_queries),
	DEF(BOOL, log_retries),
	DEF(BOOL, latency_aware_routing),

	DEF(STR, read_consistency),
	DEF(STR, write_consistency),
	DEF(STR, delete_consistency),
	DEF(STR, read_fallback_consistency),
	DEF(STR, write_fallback_consistency),
	DEF(STR, delete_fallback_consistency),

	DEF_MSECS(connect_timeout),
	DEF_MSECS(request_timeout),
	DEF_MSECS(warn_timeout),

	DEF(UINT, protocol_version),
	DEF(UINT, io_thread_count),
	DEF_SECS(heartbeat_interval),
	DEF_SECS(idle_timeout),
	DEF_MSECS(execution_retry_interval),
	DEF(UINT, execution_retry_times),
	DEF(UINT, page_size),

	DEF(ENUM, ssl),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef BUILD_CASSANDRA
static struct cassandra_settings cassandra_default_settings = {
	.hosts = ARRAY_INIT,
	.port = 9042,
	.keyspace = "",
	.user = "",
	.password = "",

	.metrics_path = "",
	.log_level = "warn:critical:error:info:debug:trace",
	.debug_queries = FALSE,
	.log_retries = FALSE,
	.latency_aware_routing = FALSE,

	.read_consistency = "local-quorum",
	.write_consistency = "local-quorum",
	.delete_consistency = "local-quorum",
	.read_fallback_consistency = "",
	.write_fallback_consistency = "",
	.delete_fallback_consistency = "",

	.connect_timeout_msecs = SQL_CONNECT_TIMEOUT_SECS * 1000,
	.request_timeout_msecs = SQL_QUERY_TIMEOUT_SECS * 1000,
	.warn_timeout_msecs = CASS_QUERY_DEFAULT_WARN_TIMEOUT_MSECS,

	.protocol_version = 0,
	.io_thread_count = 1,
	.heartbeat_interval_secs = 30,
	.idle_timeout_secs = 60,
	.execution_retry_interval_msecs = 0,
	.execution_retry_times = 0,
	.page_size = 0,

	.ssl = "no:cert-only:cert-ip",
};
#endif
#ifdef BUILD_CASSANDRA
const struct setting_parser_info cassandra_setting_parser_info = {
	.name = "cassandra",
#ifdef SQL_DRIVER_PLUGINS
	.plugin_dependency = "libdriver_cassandra",
#endif

	.defines = cassandra_setting_defines,
	.defaults = &cassandra_default_settings,

	.struct_size = sizeof(struct cassandra_settings),
	.pool_offset1 = 1 + offsetof(struct cassandra_settings, pool),
	.check_func = cassandra_settings_check,
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/lib-sql/driver-mysql.c */
extern const struct setting_parser_info mysql_setting_parser_info;
#ifdef BUILD_MYSQL
/* <settings checks> */
#define MYSQL_SQLPOOL_SET_NAME "mysql"
/* </settings checks> */
#endif
#ifdef BUILD_MYSQL
#define MYSQL_DEFAULT_READ_TIMEOUT_SECS 30
#endif
#ifdef BUILD_MYSQL
#define MYSQL_DEFAULT_WRITE_TIMEOUT_SECS 30
#endif
#ifdef BUILD_MYSQL
struct mysql_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) sqlpool_hosts;
	unsigned int connection_limit;

	const char *host;
	in_port_t port;
	const char *user;
	const char *password;
	const char *dbname;

	bool ssl;
	const char *option_file;
	const char *option_group;
	unsigned int client_flags;

	unsigned int connect_timeout_secs;
	unsigned int read_timeout_secs;
	unsigned int write_timeout_secs;
};
#endif
#ifdef BUILD_MYSQL
#undef DEF
#endif
#ifdef BUILD_MYSQL
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("mysql_"#name, name, struct mysql_settings)
#endif
#ifdef BUILD_MYSQL
#undef DEF_SECS
#endif
#ifdef BUILD_MYSQL
#define DEF_SECS(type, name) \
	SETTING_DEFINE_STRUCT_##type("mysql_"#name, name##_secs, struct mysql_settings)
#endif
#ifdef BUILD_MYSQL
static const struct setting_define mysql_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = MYSQL_SQLPOOL_SET_NAME,
	  .offset = offsetof(struct mysql_settings, sqlpool_hosts),
	  .filter_array_field_name = "mysql_host", },
	DEF(UINT, connection_limit),

	DEF(STR, host),
	DEF(IN_PORT, port),
	DEF(STR, user),
	DEF(STR, password),
	DEF(STR, dbname),

	DEF(BOOL, ssl),
	DEF(STR, option_file),
	DEF(STR, option_group),
	DEF(UINT, client_flags),

	DEF_SECS(TIME, connect_timeout),
	DEF_SECS(TIME, read_timeout),
	DEF_SECS(TIME, write_timeout),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef BUILD_MYSQL
static struct mysql_settings mysql_default_settings = {
	.sqlpool_hosts = ARRAY_INIT,
	.connection_limit = SQL_DEFAULT_CONNECTION_LIMIT,

	.host = "",
	.port = 0,
	.user = "",
	.password = "",
	.dbname = "",

	.ssl = FALSE,
	.option_file = "",
	.option_group = "client",
	.client_flags = 0,

	.connect_timeout_secs = SQL_CONNECT_TIMEOUT_SECS,
	.read_timeout_secs = MYSQL_DEFAULT_READ_TIMEOUT_SECS,
	.write_timeout_secs = MYSQL_DEFAULT_WRITE_TIMEOUT_SECS,
};
#endif
#ifdef BUILD_MYSQL
const struct setting_parser_info mysql_setting_parser_info = {
	.name = "mysql",
#ifdef SQL_DRIVER_PLUGINS
	.plugin_dependency = "libdriver_mysql",
#endif

	.defines = mysql_setting_defines,
	.defaults = &mysql_default_settings,

	.struct_size = sizeof(struct mysql_settings),
	.pool_offset1 = 1 + offsetof(struct mysql_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/lib-sql/driver-pgsql.c */
extern const struct setting_parser_info pgsql_setting_parser_info;
#ifdef BUILD_PGSQL
/* <settings checks> */
#define PGSQL_SQLPOOL_SET_NAME "pgsql"
/* </settings checks> */
#endif
#ifdef BUILD_PGSQL
struct pgsql_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) sqlpool_hosts;
	unsigned int connection_limit;

	const char *host;
	ARRAY_TYPE(const_string) parameters;
};
#endif
#ifdef BUILD_PGSQL
#undef DEF
#endif
#ifdef BUILD_PGSQL
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("pgsql_"#name, name, struct pgsql_settings)
#endif
#ifdef BUILD_PGSQL
static const struct setting_define pgsql_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = PGSQL_SQLPOOL_SET_NAME,
	  .offset = offsetof(struct pgsql_settings, sqlpool_hosts),
	  .filter_array_field_name = "pgsql_host", },
	DEF(UINT, connection_limit),

	DEF(STR, host),
	DEF(STRLIST, parameters),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef BUILD_PGSQL
static const struct pgsql_settings pgsql_default_settings = {
	.sqlpool_hosts = ARRAY_INIT,
	.connection_limit = SQL_DEFAULT_CONNECTION_LIMIT,

	.host = "",
	.parameters = ARRAY_INIT,
};
#endif
#ifdef BUILD_PGSQL
const struct setting_parser_info pgsql_setting_parser_info = {
	.name = "pgsql",
#ifdef SQL_DRIVER_PLUGINS
	.plugin_dependency = "libdriver_pgsql",
#endif

	.defines = pgsql_setting_defines,
	.defaults = &pgsql_default_settings,

	.struct_size = sizeof(struct pgsql_settings),
	.pool_offset1 = 1 + offsetof(struct pgsql_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/lib-sql/driver-sqlite.c */
extern const struct setting_parser_info sqlite_setting_parser_info;
#ifdef BUILD_SQLITE
struct sqlite_settings {
	pool_t pool;

	const char *path;
	const char *journal_mode;
	bool readonly;

	/* generated: */
	bool parsed_journal_use_wal;
};
#endif
#ifdef BUILD_SQLITE
#undef DEF
#endif
#ifdef BUILD_SQLITE
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("sqlite_"#name, name, struct sqlite_settings)
#endif
#ifdef BUILD_SQLITE
static const struct setting_define sqlite_setting_defines[] = {
	DEF(STR, path),
	DEF(ENUM, journal_mode),
	DEF(BOOL, readonly),

	SETTING_DEFINE_LIST_END
};
#endif
#ifdef BUILD_SQLITE
static const struct sqlite_settings sqlite_default_settings = {
	.path = "",
	.journal_mode = "wal:delete",
	.readonly = FALSE,
};
#endif
#ifdef BUILD_SQLITE
const struct setting_parser_info sqlite_setting_parser_info = {
	.name = "sqlite",
#ifdef SQL_DRIVER_PLUGINS
	.plugin_dependency = "libdriver_sqlite",
#endif

	.defines = sqlite_setting_defines,
	.defaults = &sqlite_default_settings,

	.struct_size = sizeof(struct sqlite_settings),
	.pool_offset1 = 1 + offsetof(struct sqlite_settings, pool),
};
#endif
/* /home/gromy/Документы/Development/dovecot-core/src/lib-sql/sql-api.c */
extern const struct setting_parser_info sql_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct sql_settings)
static const struct setting_define sql_setting_defines[] = {
	DEF(STR, sql_driver),

	SETTING_DEFINE_LIST_END
};
static const struct sql_settings sql_default_settings = {
	.sql_driver = "",
};
const struct setting_parser_info sql_setting_parser_info = {
	.name = "sql",

	.defines = sql_setting_defines,
	.defaults = &sql_default_settings,

	.struct_size = sizeof(struct sql_settings),
	.pool_offset1 = 1 + offsetof(struct sql_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/dbox-multi/mdbox-settings.c */
extern const struct setting_parser_info mdbox_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mdbox_settings)
static const struct setting_define mdbox_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "mdbox" },
	DEF(BOOL, mdbox_preallocate_space),
	DEF(SIZE, mdbox_rotate_size),
	DEF(TIME, mdbox_rotate_interval),

	SETTING_DEFINE_LIST_END
};
static const struct mdbox_settings mdbox_default_settings = {
	.mdbox_preallocate_space = FALSE,
	.mdbox_rotate_size = 10*1024*1024,
	.mdbox_rotate_interval = 0
};
static const struct setting_keyvalue mdbox_default_settings_keyvalue[] = {
	{ "mdbox/mailbox_root_directory_name", DBOX_MAILBOX_DIR_NAME },
	{ "mdbox/mailbox_directory_name", DBOX_MAILDIR_NAME },
	{ "mdbox/mail_path", "%{home}/mdbox" },
	{ NULL, NULL }
};
const struct setting_parser_info mdbox_setting_parser_info = {
	.name = "mdbox",

	.defines = mdbox_setting_defines,
	.defaults = &mdbox_default_settings,
	.default_settings = mdbox_default_settings_keyvalue,

	.struct_size = sizeof(struct mdbox_settings),
	.pool_offset1 = 1 + offsetof(struct mdbox_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/dbox-single/sdbox-settings.c */
extern const struct setting_parser_info sdbox_setting_parser_info;
static const struct setting_define sdbox_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "sdbox" },
	SETTING_DEFINE_LIST_END
};
static const struct sdbox_settings sdbox_default_settings = {
};
static const struct setting_keyvalue sdbox_default_settings_keyvalue[] = {
	{ "sdbox/mailbox_root_directory_name", DBOX_MAILBOX_DIR_NAME },
	{ "sdbox/mailbox_directory_name", DBOX_MAILDIR_NAME },
	{ "sdbox/mail_path", "%{home}/sdbox" },
	{ NULL, NULL }
};
const struct setting_parser_info sdbox_setting_parser_info = {
	.name = "sdbox",

	.defines = sdbox_setting_defines,
	.defaults = &sdbox_default_settings,
	.default_settings = sdbox_default_settings_keyvalue,

	.struct_size = sizeof(struct sdbox_settings),
	.pool_offset1 = 1 + offsetof(struct sdbox_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/maildir/maildir-settings.c */
extern const struct setting_parser_info maildir_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct maildir_settings)
static const struct setting_define maildir_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "maildir" },
	DEF(BOOL, maildir_copy_with_hardlinks),
	DEF(BOOL, maildir_very_dirty_syncs),
	DEF(BOOL, maildir_broken_filename_sizes),
	DEF(BOOL, maildir_empty_new),

	SETTING_DEFINE_LIST_END
};
static const struct maildir_settings maildir_default_settings = {
	.maildir_copy_with_hardlinks = TRUE,
	.maildir_very_dirty_syncs = FALSE,
	.maildir_broken_filename_sizes = FALSE,
	.maildir_empty_new = FALSE
};
static const struct setting_keyvalue maildir_default_settings_keyvalue[] = {
	{ "maildir/mailbox_list_layout", "maildir++" },
	{ "maildir/mail_path", "%{home}/Maildir" },
	/* Use Maildir/ root as the INBOX, not Maildir/.INBOX/ */
	{ "maildir/layout_maildir++/mail_inbox_path", "." },
	{ "maildir/layout_fs/mail_inbox_path", "." },
	{ NULL, NULL }
};
const struct setting_parser_info maildir_setting_parser_info = {
	.name = "maildir",

	.defines = maildir_setting_defines,
	.defaults = &maildir_default_settings,
	.default_settings = maildir_default_settings_keyvalue,

	.struct_size = sizeof(struct maildir_settings),
	.pool_offset1 = 1 + offsetof(struct maildir_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/mbox/mbox-settings.c */
extern const struct setting_parser_info mbox_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mbox_settings)
static const struct setting_define mbox_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "mbox" },
	DEF(BOOLLIST, mbox_read_locks),
	DEF(BOOLLIST, mbox_write_locks),
	DEF(TIME, mbox_lock_timeout),
	DEF(TIME, mbox_dotlock_change_timeout),
	DEF(SIZE_HIDDEN, mbox_min_index_size),
	DEF(BOOL, mbox_dirty_syncs),
	DEF(BOOL, mbox_very_dirty_syncs),
	DEF(BOOL, mbox_lazy_writes),
	DEF(ENUM_HIDDEN, mbox_md5),

	SETTING_DEFINE_LIST_END
};
static const struct mbox_settings mbox_default_settings = {
	.mbox_read_locks = ARRAY_INIT,
	.mbox_write_locks = ARRAY_INIT,
	.mbox_lock_timeout = 5*60,
	.mbox_dotlock_change_timeout = 2*60,
	.mbox_min_index_size = 0,
	.mbox_dirty_syncs = TRUE,
	.mbox_very_dirty_syncs = FALSE,
	.mbox_lazy_writes = TRUE,
	.mbox_md5 = "apop3d:all"
};
static const struct setting_keyvalue mbox_default_settings_keyvalue[] = {
	{ "mbox/mailbox_subscriptions_filename", ".subscriptions" },
	{ "mbox/mail_path", "%{home}/mail" },
	/* Use $mail_path/inbox as the INBOX, not $mail_path/INBOX */
	{ "mbox/layout_fs/mail_inbox_path", "inbox" },
	{ "mbox_read_locks", "fcntl" },
	{ "mbox_write_locks", "dotlock fcntl" },
	{ NULL, NULL }
};
const struct setting_parser_info mbox_setting_parser_info = {
	.name = "mbox",

	.defines = mbox_setting_defines,
	.defaults = &mbox_default_settings,
	.default_settings = mbox_default_settings_keyvalue,

	.struct_size = sizeof(struct mbox_settings),
	.pool_offset1 = 1 + offsetof(struct mbox_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/index/pop3c/pop3c-settings.c */
extern const struct setting_parser_info pop3c_setting_parser_info;

/* <settings checks> */
struct pop3c_feature_list {
	const char *name;
	enum pop3c_features num;
};

static const struct pop3c_feature_list pop3c_feature_list[] = {
	{ "no-pipelining", POP3C_FEATURE_NO_PIPELINING },
	{ NULL, 0 }
};

static int
pop3c_settings_parse_features(struct pop3c_settings *set,
			      const char **error_r)
{
	enum pop3c_features features = 0;
	const struct pop3c_feature_list *list;
	const char *const *str;

	str = settings_boollist_get(&set->pop3c_features);
	for (; *str != NULL; str++) {
		list = pop3c_feature_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("pop3c_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool pop3c_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct pop3c_settings *set = _set;

	if (pop3c_settings_parse_features(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct pop3c_settings)
static const struct setting_define pop3c_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "pop3c" },
	DEF(STR, pop3c_host),
	DEF(IN_PORT, pop3c_port),

	DEF(STR, pop3c_user),
	DEF(STR, pop3c_master_user),
	DEF(STR, pop3c_password),

	DEF(ENUM, pop3c_ssl),
	DEF(BOOL, pop3c_ssl_verify),

	DEF(STR, pop3c_rawlog_dir),
	DEF(BOOL, pop3c_quick_received_date),

	DEF(BOOLLIST, pop3c_features),

	SETTING_DEFINE_LIST_END
};
static const struct pop3c_settings pop3c_default_settings = {
	.pop3c_host = "",
	.pop3c_port = 110,

	.pop3c_user = "%{user}",
	.pop3c_master_user = "",
	.pop3c_password = "",

	.pop3c_ssl = "no:pop3s:starttls",
	.pop3c_ssl_verify = TRUE,

	.pop3c_rawlog_dir = "",
	.pop3c_quick_received_date = FALSE,

	.pop3c_features = ARRAY_INIT
};
const struct setting_parser_info pop3c_setting_parser_info = {
	.name = "pop3c",

	.defines = pop3c_setting_defines,
	.defaults = &pop3c_default_settings,

	.struct_size = sizeof(struct pop3c_settings),
	.pool_offset1 = 1 + offsetof(struct pop3c_settings, pool),

	.check_func = pop3c_settings_check
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-storage/mail-storage-settings.c */
extern const struct setting_parser_info mail_storage_setting_parser_info;
extern const struct setting_parser_info mail_driver_setting_parser_info;
extern const struct setting_parser_info mailbox_list_layout_setting_parser_info;
extern const struct setting_parser_info mailbox_setting_parser_info;
extern const struct setting_parser_info mail_namespace_setting_parser_info;
extern const struct setting_parser_info mail_user_setting_parser_info;

/* <settings checks> */
static bool mail_cache_fields_parse(const char *key,
				    const ARRAY_TYPE(const_string) *value,
				    const char **error_r)
{
	const char *const *arr;
	bool has_asterisk = FALSE;
	size_t fields_count = 0;

	for (arr = settings_boollist_get(value); *arr != NULL; arr++) {
		const char *name = *arr;

		if (str_begins_icase(name, "hdr.", &name) &&
		    !message_header_name_is_valid(name)) {
			*error_r = t_strdup_printf(
				"Invalid %s: %s is not a valid header name",
				key, name);
			return FALSE;
		} else if (strcmp(name, "*") == 0) {
			has_asterisk = TRUE;
		}
		fields_count++;
	}
	if (has_asterisk && fields_count > 1) {
		*error_r = t_strdup_printf(
			"Invalid %s: has multiple values while having \"*\" set", key);
		return FALSE;
	}
	return TRUE;
}

static bool
mailbox_list_get_path_setting(const char *key, const char **value,
			      pool_t pool, enum mailbox_list_path_type *type_r)
{
	const char *fname;

	if (strcmp(key, "mailbox_list_index_prefix") == 0) {
		if ((fname = strrchr(*value, '/')) == NULL)
			*value = NULL;
		else
			*value = p_strdup_until(pool, *value, fname);
		*type_r = MAILBOX_LIST_PATH_TYPE_LIST_INDEX;
		return TRUE;
	}
	struct {
		const char *set_name;
		enum mailbox_list_path_type type;
	} set_types[] = {
		{ "mail_path", MAILBOX_LIST_PATH_TYPE_DIR },
		{ "mail_index_path", MAILBOX_LIST_PATH_TYPE_INDEX },
		{ "mail_index_private_path", MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE },
		{ "mail_cache_path", MAILBOX_LIST_PATH_TYPE_INDEX_CACHE },
		{ "mail_control_path", MAILBOX_LIST_PATH_TYPE_CONTROL },
		{ "mail_alt_path", MAILBOX_LIST_PATH_TYPE_ALT_DIR },
	};
	for (unsigned int i = 0; i < N_ELEMENTS(set_types); i++) {
		if (strcmp(set_types[i].set_name, key) == 0) {
			*type_r = set_types[i].type;
			return TRUE;
		}
	}
	return FALSE;
}

static bool
mail_storage_settings_apply(struct event *event ATTR_UNUSED, void *_set,
			    const char *key, const char **value,
			    enum setting_apply_flags flags,
			    const char **error_r)
{
	struct mail_storage_settings *set = _set;
	enum mailbox_list_path_type type;
	const char *unexpanded_value = *value;

	unsigned int key_len = strlen(key);
	if (key_len > 5 && strcmp(key + key_len - 5, "_path") == 0) {
		unsigned int value_len = strlen(*value);
		bool truncate = FALSE;

		/* drop trailing '/' and convert ~/ to %{home}/ */
		if (value_len > 0 && (*value)[value_len-1] == '/')
			truncate = TRUE;
		if ((str_begins_with(*value, "~/") ||
		     strcmp(*value, "~") == 0) &&
		    (flags & SETTING_APPLY_FLAG_NO_EXPAND) == 0) {
#ifndef CONFIG_BINARY
			struct mail_user *user =
				mail_storage_event_get_user(event);
			const char *home;
			if (mail_user_get_home(user, &home) > 0)
				;
			else if (user->nonexistent) {
				/* Nonexistent shared user. Don't fail the user
				   creation due to this. */
				home = "";
			} else {
				*error_r = t_strdup_printf(
					"%s setting used home directory (~/) but there is no "
					"mail_home and userdb didn't return it", key);
				return FALSE;
			}
			if (!truncate)
				*value = p_strconcat(set->pool, home, *value + 1, NULL);
			else T_BEGIN {
				*value = p_strconcat(set->pool, home,
					t_strndup(*value + 1, value_len - 2), NULL);
			} T_END;
#else
			*error_r = "~/ expansion not supported in config binary";
			return FALSE;
#endif
		} else if (truncate) {
			*value = p_strndup(set->pool, *value, value_len - 1);
		}
	}

	if (mailbox_list_get_path_setting(key, &unexpanded_value,
					  set->pool, &type)) {
		set->unexpanded_mailbox_list_path[type] = unexpanded_value;
		set->unexpanded_mailbox_list_override[type] =
			(flags & SETTING_APPLY_FLAG_OVERRIDE) != 0;
	}
	return TRUE;
}

static bool
mail_storage_settings_ext_check(struct event *event, void *_set, pool_t pool,
				const char **error_r)
{
	struct mail_storage_settings *set = _set;
	struct hash_format *format;
	const char *value, *fname, *error;
	bool uidl_format_ok;

	if (set->mailbox_idle_check_interval == 0) {
		*error_r = "mailbox_idle_check_interval must not be 0";
		return FALSE;
	}

	if (strcmp(set->mail_fsync, "optimized") == 0)
		set->parsed_fsync_mode = FSYNC_MODE_OPTIMIZED;
	else if (strcmp(set->mail_fsync, "never") == 0)
		set->parsed_fsync_mode = FSYNC_MODE_NEVER;
	else if (strcmp(set->mail_fsync, "always") == 0)
		set->parsed_fsync_mode = FSYNC_MODE_ALWAYS;
	else {
		*error_r = t_strdup_printf("Unknown mail_fsync: %s",
					   set->mail_fsync);
		return FALSE;
	}

	if (set->mail_nfs_index && !set->mmap_disable) {
		*error_r = "mail_nfs_index=yes requires mmap_disable=yes";
		return FALSE;
	}
	if (set->mail_nfs_index &&
	    set->parsed_fsync_mode != FSYNC_MODE_ALWAYS) {
		*error_r = "mail_nfs_index=yes requires mail_fsync=always";
		return FALSE;
	}

	if (!file_lock_method_parse(set->lock_method,
				    &set->parsed_lock_method)) {
		*error_r = t_strdup_printf("Unknown lock_method: %s",
					   set->lock_method);
		return FALSE;
	}

	if (set->mail_cache_max_size > 1024 * 1024 * 1024) {
		*error_r = "mail_cache_max_size can't be over 1 GB";
		return FALSE;
	}
	if (set->mail_cache_purge_delete_percentage > 100) {
		*error_r = "mail_cache_purge_delete_percentage can't be over 100";
		return FALSE;
	}

	uidl_format_ok = FALSE;
	struct var_expand_program *prog;
	if (var_expand_program_create(set->pop3_uidl_format, &prog, &error) < 0) {
		*error_r = t_strdup_printf("Invalid pop3_uidl_format: %s", error);
		return FALSE;
	}

	const char *const *pop3_uidl_vars = var_expand_program_variables(prog);
	const char *const pop3_uidl_allowed_vars[] = {
		"uidvalidity",
		"uid",
		"md5",
		"filename",
		"guid",
		NULL
	};
	*error_r = NULL;
	for (; *pop3_uidl_vars != NULL; pop3_uidl_vars++) {
		if (!str_array_find(pop3_uidl_allowed_vars, *pop3_uidl_vars)) {
			*error_r = t_strdup_printf(
					"Unknown pop3_uidl_format variable: %%{%s}",
					*pop3_uidl_vars);
			break;
		}
		uidl_format_ok = TRUE;
	}
	var_expand_program_free(&prog);

	if (!uidl_format_ok) {
		if (*error_r == NULL)
			*error_r = "pop3_uidl_format setting doesn't contain any "
				   "%{variables}.";
		return FALSE;
	}

	if (strchr(set->mail_ext_attachment_hash, '/') != NULL) {
		*error_r = "mail_attachment_hash setting "
			"must not contain '/' characters";
		return FALSE;
	}
	if (hash_format_init(set->mail_ext_attachment_hash,
			     &format, &error) < 0) {
		*error_r = t_strconcat("Invalid mail_attachment_hash setting: ",
				       error, NULL);
		return FALSE;
	}
	if (strchr(set->mail_ext_attachment_hash, '-') != NULL) {
		*error_r = "mail_attachment_hash setting "
			"must not contain '-' characters";
		return FALSE;
	}
	hash_format_deinit_free(&format);

	/* check mail_server_admin syntax (RFC 5464, Section 6.2.2) */
	if (*set->mail_server_admin != '\0' &&
	    uri_check(set->mail_server_admin, 0, &error) < 0) {
		*error_r = t_strdup_printf("mail_server_admin: "
					   "'%s' is not a valid URI: %s",
					   set->mail_server_admin, error);
		return FALSE;
	}

	/* parse mail_attachment_indicator_options */
	if (array_not_empty(&set->mail_attachment_detection_options)) {
		ARRAY_TYPE(const_string) content_types;
		p_array_init(&content_types, pool, 2);

		const char *const *options =
			settings_boollist_get(&set->mail_attachment_detection_options);

		while(*options != NULL) {
			const char *opt = *options;

			if (strcmp(opt, "add-flags") == 0 ||
			    strcmp(opt, "add-flags-on-save") == 0) {
				set->parsed_mail_attachment_detection_add_flags = TRUE;
			} else if (strcmp(opt, "no-flags-on-fetch") == 0) {
				set->parsed_mail_attachment_detection_no_flags_on_fetch = TRUE;
			} else if (strcmp(opt, "exclude-inlined") == 0) {
				set->parsed_mail_attachment_exclude_inlined = TRUE;
			} else if (str_begins(opt, "content-type=", &value)) {
				value = p_strdup(pool, value);
				array_push_back(&content_types, &value);
			} else {
				*error_r = t_strdup_printf("mail_attachment_detection_options: "
					"Unknown option: %s", opt);
				return FALSE;
			}
			options++;
		}

		array_append_zero(&content_types);
		set->parsed_mail_attachment_content_type_filter = array_front(&content_types);
	}

	if (!mail_cache_fields_parse("mail_cache_fields",
				     &set->mail_cache_fields, error_r))
		return FALSE;
	if (!mail_cache_fields_parse("mail_always_cache_fields",
				     &set->mail_always_cache_fields, error_r))
		return FALSE;
	if (!mail_cache_fields_parse("mail_never_cache_fields",
				     &set->mail_never_cache_fields, error_r))
		return FALSE;

	if ((fname = strrchr(set->mailbox_list_index_prefix, '/')) == NULL)
		set->parsed_list_index_fname = set->mailbox_list_index_prefix;
	else {
		/* non-default list index directory */
		set->parsed_list_index_dir =
			p_strdup_until(pool, set->mailbox_list_index_prefix, fname);
		set->parsed_list_index_fname = fname+1;
		if (set->parsed_list_index_dir[0] != '/' &&
		    set->mail_index_path[0] == '\0') {
			*error_r = "mailbox_list_index_prefix directory is relative, but mail_index_path is empty";
			return FALSE;
		}
	}
	if (set->mailbox_root_directory_name[0] == '\0')
		set->parsed_mailbox_root_directory_prefix = "";
	else if (strchr(set->mailbox_root_directory_name, '/') != NULL) {
		*error_r = "mailbox_root_directory_name must not contain '/'";
		return FALSE;
	} else {
		set->parsed_mailbox_root_directory_prefix = p_strconcat(pool,
			set->mailbox_root_directory_name, "/", NULL);
	}

	if (set->mailbox_list_visible_escape_char != set_value_unknown &&
	    strlen(set->mailbox_list_visible_escape_char) > 1) {
		*error_r = "mailbox_list_visible_escape_char value must be a single character";
		return FALSE;
	}
	if (set->mailbox_list_storage_escape_char != set_value_unknown &&
	    strlen(set->mailbox_list_storage_escape_char) > 1) {
		*error_r = "mailbox_list_storage_escape_char value must be a single character";
		return FALSE;
	}

	if (set->mail_inbox_path[0] != '\0' && set->mail_inbox_path[0] != '/') {
		/* Convert to absolute path */
		if (strcmp(set->mail_inbox_path, ".") == 0)
			set->mail_inbox_path = set->mail_path;
		else {
			set->mail_inbox_path = p_strdup_printf(pool, "%s/%s",
				set->mail_path, set->mail_inbox_path);
		}
	}

	if (getenv(MASTER_IS_PARENT_ENV) != NULL &&
	    set->mailbox_directory_name_legacy) {
		e_warning(event,
			  "mailbox_directory_name_legacy=yes has been deprecated and will eventually be removed. See "
			  DOC_LINK("core/config/mailbox_formats/dbox.html#migrating-away-from-mailbox-directory-name-legacy")
			  " for an upgrade guide.");
	}
	return TRUE;
}

static int
namespace_parse_mailboxes(struct event *event, pool_t pool,
			  struct mail_namespace_settings *ns,
			  const char **error_r)
{
	const struct mailbox_settings *box_set;
	const char *box_name, *error;
	int ret = 0;

	if (array_is_empty(&ns->mailboxes))
		return 0;

	p_array_init(&ns->parsed_mailboxes, pool,
		     array_count(&ns->mailboxes));
	event = event_create(event);
	event_add_str(event, SETTINGS_EVENT_NAMESPACE_NAME, ns->name);
	settings_event_add_list_filter_name(event,
		SETTINGS_EVENT_NAMESPACE_NAME, ns->name);
	array_foreach_elem(&ns->mailboxes, box_name) {
		if (settings_get_filter(event,
					"mailbox", box_name,
					&mailbox_setting_parser_info, 0,
					&box_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get mailbox %s: %s",
				box_name, error);
			ret = -1;
			break;
		}
		array_push_back(&ns->parsed_mailboxes, &box_set);
		pool_add_external_ref(pool, box_set->pool);
		bool have_special_use = array_not_empty(&box_set->special_use);
		settings_free(box_set);
		if (have_special_use)
			ns->parsed_have_special_use_mailboxes = TRUE;
	}
	event_unref(&event);
	return ret;
}

static bool namespace_settings_ext_check(struct event *event,
					 void *_set, pool_t pool,
					 const char **error_r)
{
	struct mail_namespace_settings *ns = _set;

	if (ns->separator[0] != '\0' && ns->separator[1] != '\0') {
		*error_r = t_strdup_printf("Namespace %s: "
			"Hierarchy separator must be only one character long",
			ns->name);
		return FALSE;
	}
	if (!uni_utf8_str_is_valid(ns->prefix)) {
		*error_r = t_strdup_printf("Namespace %s: prefix not valid UTF8: %s",
					   ns->name, ns->prefix);
		return FALSE;
	}

	return namespace_parse_mailboxes(event, pool, ns, error_r) == 0;
}

static bool mailbox_special_use_exists(const char *name)
{
	if (name[0] != '\\')
		return FALSE;
	name++;

	if (strcasecmp(name, "All") == 0)
		return TRUE;
	if (strcasecmp(name, "Archive") == 0)
		return TRUE;
	if (strcasecmp(name, "Drafts") == 0)
		return TRUE;
	if (strcasecmp(name, "Flagged") == 0)
		return TRUE;
	if (strcasecmp(name, "Important") == 0)
		return TRUE;
	if (strcasecmp(name, "Junk") == 0)
		return TRUE;
	if (strcasecmp(name, "Sent") == 0)
		return TRUE;
	if (strcasecmp(name, "Trash") == 0)
		return TRUE;
	return FALSE;
}

static void
mailbox_special_use_check(struct mailbox_settings *set)
{
	const char *const *uses;
	unsigned int i;

	uses = settings_boollist_get(&set->special_use);
	for (i = 0; uses[i] != NULL; i++) {
		if (!mailbox_special_use_exists(uses[i])) {
			i_warning("mailbox %s: special_use label %s is not an "
				  "RFC-defined label - allowing anyway",
				  set->name, uses[i]);
		}
	}
}

static bool mailbox_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				   const char **error_r)
{
	struct mailbox_settings *set = _set;

	if (!uni_utf8_str_is_valid(set->name)) {
		*error_r = t_strdup_printf("mailbox %s: name isn't valid UTF-8",
					   set->name);
		return FALSE;
	}
	mailbox_special_use_check(set);
	return TRUE;
}

#ifndef CONFIG_BINARY
static bool parse_postmaster_address(const char *address, pool_t pool,
				     struct mail_user_settings *set,
				     const char **error_r) ATTR_NULL(3)
{
	struct message_address *addr;
	struct smtp_address *smtp_addr;

	addr = message_address_parse(pool,
		(const unsigned char *)address,
		strlen(address), 2, 0);
	if (addr == NULL || addr->domain == NULL || addr->invalid_syntax ||
	    smtp_address_create_from_msg(pool, addr, &smtp_addr) < 0) {
		*error_r = t_strdup_printf(
			"invalid address `%s' specified for the "
			"postmaster_address setting", address);
		return FALSE;
	}
	if (addr->next != NULL) {
		*error_r = "more than one address specified for the "
			"postmaster_address setting";
		return FALSE;
	}
	if (addr->name == NULL || *addr->name == '\0')
		addr->name = "Postmaster";
	if (set != NULL) {
		set->_parsed_postmaster_address = addr;
		set->_parsed_postmaster_address_smtp = smtp_addr;
	}
	return TRUE;
}
#endif

static bool
mail_user_settings_apply(struct event *event ATTR_UNUSED, void *_set,
			 const char *key, const char **value,
			 enum setting_apply_flags flags ATTR_UNUSED,
			 const char **error_r ATTR_UNUSED)
{
	struct mail_user_settings *set = _set;

	if (strcmp(key, "mail_log_prefix") == 0)
		set->unexpanded_mail_log_prefix = *value;
	return TRUE;
}

static bool mail_user_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				     const char **error_r ATTR_UNUSED)
{
	struct mail_user_settings *set = _set;

#ifndef CONFIG_BINARY
	i_assert(set->unexpanded_mail_log_prefix != NULL);
	fix_base_path(set, pool, &set->auth_socket_path);

	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
	/* Parse if possible. Perform error handling later. */
	const char *error ATTR_UNUSED;
	(void)parse_postmaster_address(set->postmaster_address, pool,
				       set, &error);
#else
	if (array_is_created(&set->mail_plugins) &&
	    array_not_empty(&set->mail_plugins) &&
	    faccessat(AT_FDCWD, set->mail_plugin_dir, R_OK | X_OK, AT_EACCESS) < 0) {
		*error_r = t_strdup_printf(
			"mail_plugin_dir: access(%s) failed: %m",
			set->mail_plugin_dir);
		return FALSE;
	}
#endif
	return TRUE;
}

/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_storage_settings)
static const struct setting_define mail_storage_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "layout_index" },
	{ .type = SET_FILTER_NAME, .key = "layout_maildir++" },
	{ .type = SET_FILTER_NAME, .key = "layout_imapdir" },
	{ .type = SET_FILTER_NAME, .key = "layout_fs" },
	{ .type = SET_FILTER_NAME, .key = "mail_ext_attachment",
	  .required_setting = "fs", },
	DEF(STR, mail_ext_attachment_path),
	DEF(STR_NOVARS_HIDDEN, mail_ext_attachment_hash),
	DEF(SIZE, mail_ext_attachment_min_size),
	DEF(BOOLLIST, mail_attachment_detection_options),
	{ .type = SET_FILTER_NAME, .key = "mail_attribute",
	  .required_setting = "dict", },
	DEF(UINT, mail_prefetch_count),
	DEF(BOOLLIST, mail_cache_fields),
	DEF(BOOLLIST, mail_always_cache_fields),
	DEF(BOOLLIST, mail_never_cache_fields),
	DEF(STR, mail_server_comment),
	DEF(STR, mail_server_admin),
	DEF(TIME_HIDDEN, mail_cache_unaccessed_field_drop),
	DEF(SIZE_HIDDEN, mail_cache_record_max_size),
	DEF(UINT_HIDDEN, mail_cache_max_header_name_length),
	DEF(UINT_HIDDEN, mail_cache_max_headers_count),
	DEF(SIZE_HIDDEN, mail_cache_max_size),
	DEF(UINT_HIDDEN, mail_cache_min_mail_count),
	DEF(SIZE_HIDDEN, mail_cache_purge_min_size),
	DEF(UINT_HIDDEN, mail_cache_purge_delete_percentage),
	DEF(UINT_HIDDEN, mail_cache_purge_continued_percentage),
	DEF(UINT_HIDDEN, mail_cache_purge_header_continue_count),
	DEF(SIZE_HIDDEN, mail_index_rewrite_min_log_bytes),
	DEF(SIZE_HIDDEN, mail_index_rewrite_max_log_bytes),
	DEF(SIZE_HIDDEN, mail_index_log_rotate_min_size),
	DEF(SIZE_HIDDEN, mail_index_log_rotate_max_size),
	DEF(TIME_HIDDEN, mail_index_log_rotate_min_age),
	DEF(TIME_HIDDEN, mail_index_log2_max_age),
	DEF(TIME_HIDDEN, mailbox_idle_check_interval),
	DEF(UINT_HIDDEN, mail_max_keyword_length),
	DEF(TIME, mail_max_lock_timeout),
	DEF(TIME, mail_temp_scan_interval),
	DEF(UINT, mail_vsize_bg_after_count),
	DEF(UINT, mail_sort_max_read_count),
	DEF(BOOL_HIDDEN, mail_save_crlf),
	DEF(ENUM, mail_fsync),
	DEF(BOOL, mmap_disable),
	DEF(BOOL, dotlock_use_excl),
	DEF(BOOL, mail_nfs_storage),
	DEF(BOOL, mail_nfs_index),
	DEF(BOOL, mailbox_list_index),
	DEF(BOOL, mailbox_list_index_very_dirty_syncs),
	DEF(BOOL, mailbox_list_index_include_inbox),
	DEF(STR, mailbox_list_layout),
	DEF(STR, mailbox_list_index_prefix),
	DEF(BOOL_HIDDEN, mailbox_list_iter_from_index_dir),
	DEF(BOOL_HIDDEN, mailbox_list_drop_noselect),
	DEF(BOOL_HIDDEN, mailbox_list_validate_fs_names),
	DEF(BOOL_HIDDEN, mailbox_list_utf8),
	DEF(STR, mailbox_list_visible_escape_char),
	DEF(STR, mailbox_list_storage_escape_char),
	DEF(STR_HIDDEN, mailbox_list_lost_mailbox_prefix),
	DEF(STR_HIDDEN, mailbox_directory_name),
	DEF(BOOL, mailbox_directory_name_legacy),
	DEF(STR_HIDDEN, mailbox_root_directory_name),
	DEF(STR_HIDDEN, mailbox_subscriptions_filename),
	DEF(STR, mail_driver),
	DEF(STR, mail_path),
	DEF(STR, mail_inbox_path),
	DEF(STR, mail_index_path),
	DEF(STR, mail_index_private_path),
	DEF(STR_HIDDEN, mail_cache_path),
	DEF(STR, mail_control_path),
	DEF(STR, mail_volatile_path),
	DEF(STR, mail_alt_path),
	DEF(BOOL_HIDDEN, mail_alt_check),
	DEF(BOOL_HIDDEN, mail_full_filesystem_access),
	DEF(BOOL, maildir_stat_dirs),
	DEF(BOOL, mail_shared_explicit_inbox),
	DEF(ENUM, lock_method),
	DEF(STR_NOVARS, pop3_uidl_format),

	DEF(STR, recipient_delimiter),

	SETTING_DEFINE_LIST_END
};
const struct mail_storage_settings mail_storage_default_settings = {
	.mail_ext_attachment_path = "",
	.mail_ext_attachment_hash = "%{sha1}",
	.mail_ext_attachment_min_size = 1024*128,
	.mail_attachment_detection_options = ARRAY_INIT,
	.mail_prefetch_count = 0,
	.mail_always_cache_fields = ARRAY_INIT,
	.mail_server_comment = "",
	.mail_server_admin = "",
	.mail_cache_min_mail_count = 0,
	.mail_cache_unaccessed_field_drop = 60*60*24*30,
	.mail_cache_record_max_size = 64 * 1024,
	.mail_cache_max_header_name_length = 100,
	.mail_cache_max_headers_count = 100,
	.mail_cache_max_size = 1024 * 1024 * 1024,
	.mail_cache_purge_min_size = 32 * 1024,
	.mail_cache_purge_delete_percentage = 20,
	.mail_cache_purge_continued_percentage = 200,
	.mail_cache_purge_header_continue_count = 4,
	.mail_index_rewrite_min_log_bytes = 8 * 1024,
	.mail_index_rewrite_max_log_bytes = 128 * 1024,
	.mail_index_log_rotate_min_size = 32 * 1024,
	.mail_index_log_rotate_max_size = 1024 * 1024,
	.mail_index_log_rotate_min_age = 5 * 60,
	.mail_index_log2_max_age = 3600 * 24 * 2,
	.mailbox_idle_check_interval = 30,
	.mail_max_keyword_length = 50,
	.mail_max_lock_timeout = 0,
	.mail_temp_scan_interval = 7*24*60*60,
	.mail_vsize_bg_after_count = 0,
	.mail_sort_max_read_count = 0,
	.mail_save_crlf = FALSE,
	.mail_fsync = "optimized:never:always",
	.mmap_disable = FALSE,
	.dotlock_use_excl = TRUE,
	.mail_nfs_storage = FALSE,
	.mail_nfs_index = FALSE,
	.mailbox_list_index = TRUE,
	.mailbox_list_index_very_dirty_syncs = FALSE,
	.mailbox_list_index_include_inbox = FALSE,
	.mailbox_list_layout = "fs",
	.mailbox_list_index_prefix = "dovecot.list.index",
	.mailbox_list_iter_from_index_dir = FALSE,
	.mailbox_list_drop_noselect = TRUE,
	.mailbox_list_validate_fs_names = TRUE,
	.mailbox_list_utf8 = FALSE,
	.mailbox_list_visible_escape_char = "",
	.mailbox_list_storage_escape_char = "",
	.mailbox_list_lost_mailbox_prefix = "recovered-lost-folder-",
	.mailbox_directory_name = "",
	.mailbox_directory_name_legacy = FALSE,
	.mailbox_root_directory_name = "",
	.mailbox_subscriptions_filename = "subscriptions",
	.mail_driver = "",
	.mail_path = "",
	.mail_inbox_path = "",
	.mail_index_path = "",
	.mail_index_private_path = "",
	.mail_cache_path = "",
	.mail_control_path = "",
	.mail_volatile_path = "",
	.mail_alt_path = "",
	.mail_alt_check = TRUE,
	.mail_full_filesystem_access = FALSE,
	.maildir_stat_dirs = FALSE,
	.mail_shared_explicit_inbox = FALSE,
	.lock_method = "fcntl:flock:dotlock",
	.pop3_uidl_format = "%{uid | hex(8)}%{uidvalidity | hex(8)}",

	.recipient_delimiter = "+",
};
static const struct setting_keyvalue mail_storage_default_settings_keyvalue[] = {
	{ "layout_index/mailbox_list_storage_escape_char", "^" },
#define MAIL_CACHE_FIELDS_DEFAULT \
	"flags " \
	/* IMAP ENVELOPE: */ \
	"hdr.date hdr.subject hdr.from hdr.sender hdr.reply-to hdr.to hdr.cc hdr.bcc hdr.in-reply-to hdr.message-id " \
	/* Commonly used by clients: */ \
	"date.received size.virtual imap.bodystructure mime.parts hdr.references " \
	/* AppSuite, at least: */ \
	"hdr.importance hdr.x-priority " \
	"hdr.x-open-xchange-share-url " \
	/* POP3: */ \
	"pop3.uidl pop3.order"
	{ "mail_cache_fields", MAIL_CACHE_FIELDS_DEFAULT },
#ifdef DOVECOT_PRO_EDITION
	{ "mail_always_cache_fields", MAIL_CACHE_FIELDS_DEFAULT },
#endif
	{ "mail_never_cache_fields", "imap.envelope" },
	{ "mail_attachment_detection_options", "add-flags content-type=!application/signature" },
	/* This breaks mbox format in various ways */
	{ "mbox/mail_attachment_detection_options", "" },
	/* It may be confusing to enable with imapc, and it's unlikely to be
	   useful. Even when using imapc with shared folders, the missing
	   attachment flags would normally be added by the remote server. */
	{ "imapc/mail_attachment_detection_options", "" },
	{ NULL, NULL }
};
const struct setting_parser_info mail_storage_setting_parser_info = {
	.name = "mail_storage",

	.defines = mail_storage_setting_defines,
	.defaults = &mail_storage_default_settings,
	.default_settings = mail_storage_default_settings_keyvalue,

	.struct_size = sizeof(struct mail_storage_settings),
	.pool_offset1 = 1 + offsetof(struct mail_storage_settings, pool),
	.setting_apply = mail_storage_settings_apply,
	.ext_check_func = mail_storage_settings_ext_check,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_driver_settings)
static const struct setting_define mail_driver_setting_defines[] = {
	DEF(STR, mail_driver),
	SETTING_DEFINE_LIST_END
};
const struct mail_driver_settings mail_driver_default_settings = {
	.mail_driver = "",
};
const struct setting_parser_info mail_driver_setting_parser_info = {
	.name = "mail_driver",

	.defines = mail_driver_setting_defines,
	.defaults = &mail_driver_default_settings,

	.struct_size = sizeof(struct mail_driver_settings),
	.pool_offset1 = 1 + offsetof(struct mail_driver_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mailbox_list_layout_settings)
static const struct setting_define mailbox_list_layout_setting_defines[] = {
	DEF(STR, mailbox_list_layout),
	SETTING_DEFINE_LIST_END
};
const struct mailbox_list_layout_settings mailbox_list_layout_default_settings = {
	.mailbox_list_layout = "fs",
};
const struct setting_parser_info mailbox_list_layout_setting_parser_info = {
	.name = "mailbox_list_layout",

	.defines = mailbox_list_layout_setting_defines,
	.defaults = &mailbox_list_layout_default_settings,

	.struct_size = sizeof(struct mailbox_list_layout_settings),
	.pool_offset1 = 1 + offsetof(struct mailbox_list_layout_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("mailbox_"#name, name, struct mailbox_settings)
static const struct setting_define mailbox_setting_defines[] = {
	DEF(STR, name),
	{ .type = SET_ENUM, .key = "mailbox_auto",
	  .offset = offsetof(struct mailbox_settings, autocreate) } ,
	DEF(BOOLLIST, special_use),
	DEF(STR, comment),
	DEF(TIME, autoexpunge),
	DEF(UINT, autoexpunge_max_mails),

	SETTING_DEFINE_LIST_END
};
const struct mailbox_settings mailbox_default_settings = {
	.name = "",
	.autocreate = MAILBOX_SET_AUTO_NO":"
		MAILBOX_SET_AUTO_CREATE":"
		MAILBOX_SET_AUTO_SUBSCRIBE,
	.special_use = ARRAY_INIT,
	.comment = "",
	.autoexpunge = 0,
	.autoexpunge_max_mails = 0
};
const struct setting_parser_info mailbox_setting_parser_info = {
	.name = "mailbox",

	.defines = mailbox_setting_defines,
	.defaults = &mailbox_default_settings,

	.struct_size = sizeof(struct mailbox_settings),
	.pool_offset1 = 1 + offsetof(struct mailbox_settings, pool),

	.check_func = mailbox_settings_check
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("namespace_"#name, name, struct mail_namespace_settings)
static const struct setting_define mail_namespace_setting_defines[] = {
	DEF(STR, name),
	DEF(ENUM, type),
	DEF(STR, separator),
	DEF(STR, prefix),
	DEF(STR, alias_for),

	DEF(BOOL, inbox),
	DEF(BOOL, hidden),
	DEF(ENUM, list),
	DEF(BOOL, subscriptions),
	DEF(BOOL, ignore_on_failure),
	DEF(BOOL, disabled),
	DEF(UINT, order),

	{ .type = SET_FILTER_ARRAY, .key = "mailbox",
	   .offset = offsetof(struct mail_namespace_settings, mailboxes),
	   .filter_array_field_name = "mailbox_name" },

	SETTING_DEFINE_LIST_END
};
const struct mail_namespace_settings mail_namespace_default_settings = {
	.name = "",
	.type = "private:shared:public",
	.separator = "",
	.prefix = "",
	.alias_for = "",

	.inbox = FALSE,
	.hidden = FALSE,
	.list = "yes:no:children",
	.subscriptions = TRUE,
	.ignore_on_failure = FALSE,
	.disabled = FALSE,
	.order = 0,

	.mailboxes = ARRAY_INIT
};
const struct setting_parser_info mail_namespace_setting_parser_info = {
	.name = "mail_namespace",

	.defines = mail_namespace_setting_defines,
	.defaults = &mail_namespace_default_settings,

	.struct_size = sizeof(struct mail_namespace_settings),
	.pool_offset1 = 1 + offsetof(struct mail_namespace_settings, pool),

	.ext_check_func = namespace_settings_ext_check,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_user_settings)
static const struct setting_define mail_user_setting_defines[] = {
	DEF(STR_HIDDEN, base_dir),
	DEF(STR_HIDDEN, auth_socket_path),
	DEF(STR, mail_temp_dir),
	DEF(BOOL, mail_debug),

	DEF(STR, mail_uid),
	DEF(STR, mail_gid),
	DEF(STR, mail_home),
	DEF(STR, mail_chroot),
	DEF(BOOLLIST, mail_access_groups),
	DEF(STR, mail_privileged_group),
	DEF(BOOLLIST, valid_chroot_dirs),

	DEF(UINT, first_valid_uid),
	DEF(UINT, last_valid_uid),
	DEF(UINT, first_valid_gid),
	DEF(UINT, last_valid_gid),

	DEF(BOOLLIST, mail_plugins),
	DEF(STR, mail_plugin_dir),

	DEF(STR, mail_log_prefix),

	{ .type = SET_FILTER_ARRAY, .key = "namespace",
	   .offset = offsetof(struct mail_user_settings, namespaces),
	   .filter_array_field_name = "namespace_name" },
	DEF(STR, hostname),
	DEF(STR, postmaster_address),

	SETTING_DEFINE_LIST_END
};
static const struct mail_user_settings mail_user_default_settings = {
	.base_dir = PKG_RUNDIR,
	.auth_socket_path = "auth-userdb",
#ifdef DOVECOT_PRO_EDITION
	.mail_temp_dir = "/dev/shm/dovecot",
#else
	.mail_temp_dir = "/tmp",
#endif
	.mail_debug = FALSE,

#ifdef DOVECOT_PRO_EDITION
	.mail_uid = "vmail",
	.mail_gid = "vmail",
#else
	.mail_uid = "",
	.mail_gid = "",
#endif
	.mail_home = "",
	.mail_chroot = "",
	.mail_access_groups = ARRAY_INIT,
	.mail_privileged_group = "",
	.valid_chroot_dirs = ARRAY_INIT,

	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,

	.mail_plugins = ARRAY_INIT,
	.mail_plugin_dir = MODULEDIR,

	.mail_log_prefix = "%{service}(%{user})<%{process:pid}><%{session}>: ",

	.namespaces = ARRAY_INIT,
	.hostname = "",
	.postmaster_address = "postmaster@%{user|domain|default(hostname)}",
};
const struct setting_parser_info mail_user_setting_parser_info = {
	.name = "mail_user",

	.defines = mail_user_setting_defines,
	.defaults = &mail_user_default_settings,

	.struct_size = sizeof(struct mail_user_settings),
	.pool_offset1 = 1 + offsetof(struct mail_user_settings, pool),
	.setting_apply = mail_user_settings_apply,
	.check_func = mail_user_settings_check,
};
/* /home/gromy/Документы/Development/dovecot-core/src/lmtp/lmtp-settings.c */
extern const struct setting_parser_info lmtp_pre_mail_setting_parser_info;
extern const struct setting_parser_info lmtp_setting_parser_info;

/* <settings checks> */
struct lmtp_client_workaround_list {
	const char *name;
	enum lmtp_client_workarounds num;
};

static const struct lmtp_client_workaround_list
lmtp_client_workaround_list[] = {
	{ "whitespace-before-path", LMTP_WORKAROUND_WHITESPACE_BEFORE_PATH },
	{ "mailbox-for-path", LMTP_WORKAROUND_MAILBOX_FOR_PATH },
	{ NULL, 0 }
};

static int
lmtp_settings_parse_workarounds(struct lmtp_settings *set,
				const char **error_r)
{
	enum lmtp_client_workarounds client_workarounds = 0;
	const struct lmtp_client_workaround_list *list;
	const char *const *str;

	str = settings_boollist_get(&set->lmtp_client_workarounds);
	for (; *str != NULL; str++) {
		list = lmtp_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf(
				"lmtp_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool lmtp_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				const char **error_r)
{
	struct lmtp_settings *set = _set;

#ifndef EXPERIMENTAL_MAIL_UTF8
	if (set->mail_utf8_extensions) {
		*error_r = "Dovecot not built with --enable-experimental-mail-utf8";
		return FALSE;
	}
#endif

	if (lmtp_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

	if (strcmp(set->lmtp_hdr_delivery_address, "none") == 0) {
		set->parsed_lmtp_hdr_delivery_address =
			LMTP_HDR_DELIVERY_ADDRESS_NONE;
	} else if (strcmp(set->lmtp_hdr_delivery_address, "final") == 0) {
		set->parsed_lmtp_hdr_delivery_address =
			LMTP_HDR_DELIVERY_ADDRESS_FINAL;
	} else if (strcmp(set->lmtp_hdr_delivery_address, "original") == 0) {
		set->parsed_lmtp_hdr_delivery_address =
			LMTP_HDR_DELIVERY_ADDRESS_ORIGINAL;
	} else {
		*error_r = t_strdup_printf("Unknown lmtp_hdr_delivery_address: %s",
					   set->lmtp_hdr_delivery_address);
		return FALSE;
	}

	if (set->lmtp_user_concurrency_limit == 0) {
		*error_r = "lmtp_user_concurrency_limit must not be 0 "
			   "(did you mean \"unlimited\"?)";
		return FALSE;
	}

	return TRUE;
}
/* </settings checks> */
struct service_settings lmtp_service_settings = {
	.name = "lmtp",
	.protocol = "lmtp",
	.type = "",
	.executable = "lmtp",
	.user = "",
	.group = "",
	.privileged_group = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.client_limit = 1,
#ifdef DOVECOT_PRO_EDITION
	.restart_request_count = 1000,
	.process_limit = 512,
#else
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue lmtp_service_settings_defaults[] = {
	{ "unix_listener", "lmtp" },

	{ "unix_listener/lmtp/path", "lmtp" },
	{ "unix_listener/lmtp/mode", "0666" },

#ifdef DOVECOT_PRO_EDITION
	{ "inet_listener", "lmtp" },
	{ "inet_listener/lmtp/name", "lmtp" },
	{ "inet_listener/lmtp/port", "24" },
#endif

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct lmtp_pre_mail_settings)
static const struct setting_define lmtp_pre_mail_setting_defines[] = {
	DEF(TIME, mail_max_lock_timeout),

	SETTING_DEFINE_LIST_END
};
static const struct lmtp_pre_mail_settings lmtp_pre_mail_default_settings = {
	.mail_max_lock_timeout = 0,
};
const struct setting_parser_info lmtp_pre_mail_setting_parser_info = {
	.name = "lmtp_pre_mail",

	.defines = lmtp_pre_mail_setting_defines,
	.defaults = &lmtp_pre_mail_default_settings,

	.struct_size = sizeof(struct lmtp_pre_mail_settings),
	.pool_offset1 = 1 + offsetof(struct lmtp_pre_mail_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct lmtp_settings)
static const struct setting_define lmtp_setting_defines[] = {
	DEF(BOOL, lmtp_proxy),
	DEF(BOOL, lmtp_save_to_detail_mailbox),
	DEF(BOOL, lmtp_rcpt_check_quota),
	DEF(BOOL, lmtp_add_received_header),
	DEF(BOOL_HIDDEN, lmtp_verbose_replies),
	DEF(UINT, lmtp_user_concurrency_limit),
	DEF(ENUM, lmtp_hdr_delivery_address),
	DEF(STR, lmtp_rawlog_dir),
	DEF(STR, lmtp_proxy_rawlog_dir),

	DEF(BOOLLIST, lmtp_client_workarounds),

	DEF(STR_HIDDEN, login_greeting),
	DEF(BOOLLIST, login_trusted_networks),

	DEF(BOOLLIST, mail_plugins),
	DEF(STR, mail_plugin_dir),
	DEF(BOOL, mail_utf8_extensions),

	SETTING_DEFINE_LIST_END
};
static const struct lmtp_settings lmtp_default_settings = {
	.lmtp_proxy = FALSE,
	.lmtp_save_to_detail_mailbox = FALSE,
	.lmtp_rcpt_check_quota = FALSE,
	.lmtp_add_received_header = TRUE,
	.lmtp_verbose_replies = FALSE,
	.lmtp_user_concurrency_limit = 10,
	.lmtp_hdr_delivery_address = "final:none:original",
	.lmtp_rawlog_dir = "",
	.lmtp_proxy_rawlog_dir = "",

	.lmtp_client_workarounds = ARRAY_INIT,

	.login_greeting = PACKAGE_NAME" ready.",
	.login_trusted_networks = ARRAY_INIT,

	.mail_plugins = ARRAY_INIT,
	.mail_plugin_dir = MODULEDIR,
	.mail_utf8_extensions = FALSE,
};
const struct setting_parser_info lmtp_setting_parser_info = {
	.name = "lmtp",

	.defines = lmtp_setting_defines,
	.defaults = &lmtp_default_settings,

	.struct_size = sizeof(struct lmtp_settings),
	.pool_offset1 = 1 + offsetof(struct lmtp_settings, pool),
	.check_func = lmtp_settings_check,
};
/* /home/gromy/Документы/Development/dovecot-core/src/log/log-settings.c */
struct service_settings log_service_settings = {
	.name = "log",
	.protocol = "",
	.type = "log",
	.executable = "log",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1,
	.idle_kill_interval = SET_TIME_INFINITE,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};
const struct setting_keyvalue log_service_settings_defaults[] = {
	{ "unix_listener", "log-errors" },

	{ "unix_listener/log-errors/path", "log-errors" },
	{ "unix_listener/log-errors/type", "errors" },
	{ "unix_listener/log-errors/mode", "0600" },

	{ NULL, NULL }
};
/* /home/gromy/Документы/Development/dovecot-core/src/login-common/login-settings.c */
extern const struct setting_parser_info login_setting_parser_info;

/* <settings checks> */
static bool login_settings_check(void *_set, pool_t pool,
				 const char **error_r)
{
	struct login_settings *set = _set;

	set->log_format_elements_split =
		p_strsplit(pool, set->login_log_format_elements, " ");

	if (strcmp(set->ssl, "required") == 0 && set->auth_allow_cleartext) {
		*error_r = "auth_allow_cleartext=yes has no effect with ssl=required";
		return FALSE;
	}

	return TRUE;
}
/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct login_settings)
static const struct setting_define login_setting_defines[] = {
	DEF(BOOLLIST, login_trusted_networks),
	DEF(BOOLLIST, login_source_ips),
	DEF(STR_HIDDEN, login_greeting),
	DEF(STR_NOVARS, login_log_format_elements),
	DEF(STR_NOVARS, login_log_format),
	DEF(STR, login_proxy_notify_path),
	DEF(STR, login_plugin_dir),
	DEF(BOOLLIST, login_plugins),
	DEF(TIME_MSECS, login_proxy_timeout),
	DEF(UINT, login_proxy_max_reconnects),
	DEF(TIME, login_proxy_max_disconnect_delay),
	DEF(STR, login_proxy_rawlog_dir),
	DEF(STR_HIDDEN, login_socket_path),

	DEF(BOOL, auth_ssl_require_client_cert),
	DEF(BOOL, auth_ssl_username_from_cert),

	DEF(BOOL, auth_allow_cleartext),
	DEF(BOOL, auth_verbose),
	DEF(BOOL, auth_debug),
	DEF(BOOL, verbose_proctitle),

	DEF(ENUM, ssl),

	DEF(UINT, mail_max_userip_connections),

	SETTING_DEFINE_LIST_END
};
static const struct login_settings login_default_settings = {
	.login_trusted_networks = ARRAY_INIT,
	.login_source_ips = ARRAY_INIT,
	.login_greeting = PACKAGE_NAME" ready.",
	.login_log_format_elements = "user=<%{user}> method=%{mechanism} rip=%{remote_ip} lip=%{local_ip} mpid=%{mail_pid} %{secured} session=<%{session}>",
	.login_log_format = "%{message}: %{elements}",
	.login_proxy_notify_path = "proxy-notify",
	.login_plugin_dir = MODULEDIR"/login",
	.login_plugins = ARRAY_INIT,
	.login_proxy_timeout = 30*1000,
	.login_proxy_max_reconnects = 3,
#ifdef DOVECOT_PRO_EDITION
	.login_proxy_max_disconnect_delay = 30,
#else
	.login_proxy_max_disconnect_delay = 0,
#endif
	.login_proxy_rawlog_dir = "",
	.login_socket_path = "",

	.auth_ssl_require_client_cert = FALSE,
	.auth_ssl_username_from_cert = FALSE,

	.auth_allow_cleartext = FALSE,
	.auth_verbose = FALSE,
	.auth_debug = FALSE,
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,

	.ssl = "yes:no:required",

	.mail_max_userip_connections = 10
};
const struct setting_parser_info login_setting_parser_info = {
	.name = "login",

	.defines = login_setting_defines,
	.defaults = &login_default_settings,

	.struct_size = sizeof(struct login_settings),
	.pool_offset1 = 1 + offsetof(struct login_settings, pool),
	.check_func = login_settings_check
};
/* /home/gromy/Документы/Development/dovecot-core/src/master/master-settings.c */
extern const struct setting_parser_info unix_listener_setting_parser_info;
extern const struct setting_parser_info fifo_listener_setting_parser_info;
extern const struct setting_parser_info inet_listener_setting_parser_info;
extern const struct setting_parser_info service_setting_parser_info;
extern const struct setting_parser_info master_setting_parser_info;

/* <settings checks> */
static void
expand_user(const char **user, enum service_user_default *default_r,
	    const struct master_settings *set)
{
	/* $variable expansion is typically done by doveconf, but these
	   variables can come from built-in settings, so we need to expand
	   them here */
	if (strcmp(*user, "$SET:default_internal_user") == 0) {
		*user = set->default_internal_user;
		*default_r = SERVICE_USER_DEFAULT_INTERNAL;
	} else if (strcmp(*user, "$SET:default_login_user") == 0) {
		*user = set->default_login_user;
		*default_r = SERVICE_USER_DEFAULT_LOGIN;
	} else {
		*default_r = SERVICE_USER_DEFAULT_NONE;
	}
}

static void
expand_group(const char **group, const struct master_settings *set)
{
	/* $variable expansion is typically done by doveconf, but these
	   variables can come from built-in settings, so we need to expand
	   them here */
	if (strcmp(*group, "$SET:default_internal_group") == 0)
		*group = set->default_internal_group;
}

static void
expand_groups(ARRAY_TYPE(const_string) *groups, const struct master_settings *set)
{
	const char **group;
	if (array_is_empty(groups))
		return;
	array_foreach_modifiable(groups, group)
		expand_group(group, set);
}

static bool
fix_file_listener_paths(ARRAY_TYPE(file_listener_settings) *l,
			pool_t pool, const struct master_settings *master_set,
			ARRAY_TYPE(const_string) *all_listeners,
			const char **error_r)
{
	struct file_listener_settings *set;
	size_t base_dir_len = strlen(master_set->base_dir);
	enum service_user_default user_default;

	if (!array_is_created(l))
		return TRUE;

	array_foreach_elem(l, set) {
		if (set->path[0] == '\0') {
			*error_r = "path must not be empty";
			return FALSE;
		}

		expand_user(&set->user, &user_default, master_set);
		expand_group(&set->group, master_set);
		if (*set->path != '/') {
			set->path = p_strconcat(pool, master_set->base_dir, "/",
						set->path, NULL);
		} else if (strncmp(set->path, master_set->base_dir,
				   base_dir_len) == 0 &&
			   set->path[base_dir_len] == '/') {
			i_warning("You should remove base_dir prefix from "
				  "unix_listener: %s", set->path);
		}
		if (set->mode != 0)
			array_push_back(all_listeners, &set->path);
	}
	return TRUE;
}

static void add_inet_listeners(ARRAY_TYPE(inet_listener_settings) *l,
			       ARRAY_TYPE(const_string) *all_listeners)
{
	struct inet_listener_settings *set;
	const char *str;
	const char *address;

	if (!array_is_created(l))
		return;

	array_foreach_elem(l, set) {
		if (set->port != 0) {
			array_foreach_elem(&set->listen, address) {
				str = t_strdup_printf("%u:%s", set->port, address);
				array_push_back(all_listeners, &str);
			}
		}
	}
}

static bool master_settings_parse_type(struct service_settings *set,
				       const char **error_r)
{
	if (*set->type == '\0')
		set->parsed_type = SERVICE_TYPE_UNKNOWN;
	else if (strcmp(set->type, "log") == 0)
		set->parsed_type = SERVICE_TYPE_LOG;
	else if (strcmp(set->type, "config") == 0)
		set->parsed_type = SERVICE_TYPE_CONFIG;
	else if (strcmp(set->type, "anvil") == 0)
		set->parsed_type = SERVICE_TYPE_ANVIL;
	else if (strcmp(set->type, "login") == 0)
		set->parsed_type = SERVICE_TYPE_LOGIN;
	else if (strcmp(set->type, "startup") == 0)
		set->parsed_type = SERVICE_TYPE_STARTUP;
	else if (strcmp(set->type, "worker") == 0)
		set->parsed_type = SERVICE_TYPE_WORKER;
	else {
		*error_r = t_strconcat("Unknown service type: ",
				       set->type, NULL);
		return FALSE;
	}
	return TRUE;
}

static void service_set_login_dump_core(struct service_settings *set)
{
	const char *p;

	if (set->parsed_type != SERVICE_TYPE_LOGIN)
		return;

	p = strstr(set->executable, " -D");
	if (p != NULL && (p[3] == '\0' || p[3] == ' '))
		set->login_dump_core = TRUE;
}

static bool
services_have_protocol(struct master_settings *set, const char *name)
{
	struct service_settings *service;

	array_foreach_elem(&set->parsed_services, service) {
		if (strcmp(service->protocol, name) == 0)
			return TRUE;
	}
	return FALSE;
}

#ifdef CONFIG_BINARY
static const struct service_settings *
master_default_settings_get_service(const char *name)
{
	for (unsigned int i = 0; config_all_services[i].set != NULL; i++) {
		if (strcmp(config_all_services[i].set->name, name) == 0)
			return config_all_services[i].set;
	}
	return NULL;
}
#endif

static unsigned int
service_get_client_limit(struct master_settings *set, const char *name)
{
	struct service_settings *service;

	array_foreach_elem(&set->parsed_services, service) {
		if (strcmp(service->name, name) == 0)
			return service->client_limit;
	}
	i_panic("Unexpectedly didn't find service %s", name);
}

static bool service_is_enabled(const struct master_settings *set,
			       struct service_settings *service)
{
	if (service->protocol[0] == '\0')
		return TRUE;
	return array_is_created(&set->protocols) &&
		array_lsearch(&set->protocols, &service->protocol, i_strcmp_p) != NULL;
}

static bool
master_service_get_file_listeners(pool_t pool, struct event *event,
				  const char *set_name, const char *service_name,
				  const struct setting_parser_info *info,
				  const ARRAY_TYPE(const_string) *listener_names,
				  ARRAY_TYPE(file_listener_settings) *parsed_listeners,
				  const char **error_r)
{
	const struct file_listener_settings *listener_set;
	const char *name, *error;
	bool ret = TRUE;

	if (!array_is_created(listener_names))
		return TRUE;

	event = event_create(event);
	settings_event_add_list_filter_name(event, "service", service_name);

	p_array_init(parsed_listeners, pool, array_count(listener_names));
	array_foreach_elem(listener_names, name) {
		if (settings_get_filter(event, set_name, name, info,
					0, &listener_set, &error) < 0) {
			*error_r = t_strdup_printf("Failed to get %s %s: %s",
						   set_name, name, error);
			ret = FALSE;
			break;
		}
		struct file_listener_settings *listener_set_dup =
			p_memdup(pool, listener_set, sizeof(*listener_set));

		pool_add_external_ref(pool, listener_set->pool);
		array_push_back(parsed_listeners, &listener_set_dup);
		settings_free(listener_set);
	}
	event_unref(&event);
	return ret;
}

static bool
master_service_get_inet_listeners(struct service_settings *service_set,
				  const char *service_name,
				  pool_t pool, struct event *event,
				  const char **error_r)
{
	const struct inet_listener_settings *listener_set;
	const struct master_settings *master_set;
	const char *name, *error;
	bool ret = TRUE;

	if (!array_is_created(&service_set->inet_listeners))
		return TRUE;

	event = event_create(event);
	settings_event_add_list_filter_name(event, "service", service_name);

	p_array_init(&service_set->parsed_inet_listeners, pool,
		     array_count(&service_set->inet_listeners));
	array_foreach_elem(&service_set->inet_listeners, name) {
		if (settings_get_filter(event, "inet_listener", name,
					&inet_listener_setting_parser_info,
					0, &listener_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get inet_listener %s: %s",
				name, error);
			ret = FALSE;
			break;
		}

		struct event *event2 = event_create(event);
		settings_event_add_list_filter_name(event2, "inet_listener",
						    name);
		if (settings_get(event2, &master_setting_parser_info,
				 SETTINGS_GET_FLAG_NO_CHECK,
				 &master_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get inet_listener %s: %s",
				name, error);
			ret = FALSE;
			settings_free(listener_set);
			event_unref(&event2);
			break;
		}
		event_unref(&event2);

		struct inet_listener_settings *listener_set_dup =
			p_memdup(pool, listener_set, sizeof(*listener_set));
		unsigned int listeners = array_count(&master_set->listen);
		p_array_init(&listener_set_dup->listen, pool, listeners);

		pool_add_external_ref(pool, listener_set->pool);
		const char *address;
		array_foreach_elem(&master_set->listen, address) {
			const char **address_copy =
				array_append_space(&listener_set_dup->listen);
			*address_copy = p_strdup(listener_set_dup->pool, address);
		}
		settings_free(master_set);

		array_push_back(&service_set->parsed_inet_listeners,
				&listener_set_dup);
		settings_free(listener_set);
	}
	event_unref(&event);
	return ret;
}

static int
master_settings_get_services(struct master_settings *set, pool_t pool,
			     struct event *event, const char **error_r)
{
	const struct service_settings *service_set;
	const char *service_name, *error;

	p_array_init(&set->parsed_services, pool,
		     array_count(&set->services));
	array_foreach_elem(&set->services, service_name) {
		if (settings_get_filter(event, "service", service_name,
					&service_setting_parser_info,
					0, &service_set, &error) < 0) {
			if (event_find_field_recursive(event,
					SETTINGS_EVENT_NO_EXPAND) != NULL)
				return 0;
			*error_r = t_strdup_printf("Failed to get service %s: %s",
						   service_name, error);
			return -1;
		}
		struct service_settings *service_set_dup =
			p_memdup(pool, service_set, sizeof(*service_set));

		pool_add_external_ref(pool, service_set->pool);
		array_push_back(&set->parsed_services, &service_set_dup);
		settings_free(service_set);

		if (!master_service_get_file_listeners(pool, event,
				"unix_listener", service_name,
				&unix_listener_setting_parser_info,
				&service_set_dup->unix_listeners,
				&service_set_dup->parsed_unix_listeners,
				error_r))
			return -1;
		if (!master_service_get_file_listeners(pool, event,
				"fifo_listener", service_name,
				&fifo_listener_setting_parser_info,
				&service_set_dup->fifo_listeners,
				&service_set_dup->parsed_fifo_listeners,
				error_r))
			return -1;
		if (!master_service_get_inet_listeners(service_set_dup,
						       service_name, pool,
						       event, error_r))
			return -1;
	}
	return 1;
}

static bool
master_settings_ext_check(struct event *event, void *_set,
			  pool_t pool, const char **error_r)
{
	static bool warned_auth = FALSE, warned_anvil = FALSE;
	struct master_settings *set = _set;
	struct service_settings *const *services;
	const char *const *strings, *proto;
	ARRAY_TYPE(const_string) all_listeners;
	struct passwd pw;
	unsigned int i, j, count, client_limit, process_limit;
	unsigned int max_auth_client_processes, max_anvil_client_processes;
	string_t *max_auth_client_processes_reason = t_str_new(64);
	string_t *max_anvil_client_processes_reason = t_str_new(64);
	size_t len;
	int ret;
#ifdef CONFIG_BINARY
	const struct service_settings *default_service;
#else
	rlim_t fd_limit;
	const char *max_client_limit_source = "BUG";
	unsigned int max_client_limit = 0;
#endif


	len = strlen(set->base_dir);
	if (len > 0 && set->base_dir[len-1] == '/') {
		/* drop trailing '/' */
		set->base_dir = p_strndup(pool, set->base_dir, len - 1);
	}

	if (set->last_valid_uid != 0 &&
	    set->first_valid_uid > set->last_valid_uid) {
		*error_r = "first_valid_uid can't be larger than last_valid_uid";
		return FALSE;
	}
	if (set->last_valid_gid != 0 &&
	    set->first_valid_gid > set->last_valid_gid) {
		*error_r = "first_valid_gid can't be larger than last_valid_gid";
		return FALSE;
	}

	if (i_getpwnam(set->default_login_user, &pw) == 0) {
		*error_r = t_strdup_printf("default_login_user doesn't exist: %s",
					   set->default_login_user);
		return FALSE;
	}
	if (i_getpwnam(set->default_internal_user, &pw) == 0) {
		*error_r = t_strdup_printf("default_internal_user doesn't exist: %s",
					   set->default_internal_user);
		return FALSE;
	}

	/* check that we have at least one service. the actual service
	   structure validity is checked later while creating them. */
	if (!array_is_created(&set->services) ||
	    array_count(&set->services) == 0) {
#ifdef CONFIG_BINARY
		return TRUE;
#else
		*error_r = "No services defined";
		return FALSE;
#endif
	}
	if (array_is_empty(&set->listen)) {
		*error_r = "listen can't be set empty";
		return FALSE;
	}
	if ((ret = master_settings_get_services(set, pool, event, error_r)) <= 0)
		return ret == 0;
	services = array_get(&set->parsed_services, &count);
	for (i = 0; i < count; i++) {
		struct service_settings *service = services[i];

		if (*service->name == '\0') {
			*error_r = t_strdup_printf(
				"Service #%d is missing name", i);
			return FALSE;
		}
		if (!master_settings_parse_type(service, error_r))
			return FALSE;
		for (j = 0; j < i; j++) {
			if (strcmp(service->name, services[j]->name) == 0) {
				*error_r = t_strdup_printf(
					"Duplicate service name: %s",
					service->name);
				return FALSE;
			}
		}
		expand_user(&service->user, &service->user_default, set);
		expand_groups(&service->extra_groups, set);
		service_set_login_dump_core(service);
	}

	if (array_is_created(&set->protocols)) {
		array_foreach_elem(&set->protocols, proto) {
			if (!services_have_protocol(set, proto)) {
				*error_r = t_strdup_printf("protocols: "
					"Unknown protocol: %s", proto);
				return FALSE;
			}
		}
	}
	t_array_init(&all_listeners, 64);
	max_auth_client_processes = 0;
	max_anvil_client_processes = 2; /* blocking, nonblocking pipes */
	for (i = 0; i < count; i++) {
		struct service_settings *service = services[i];

		if (!service_is_enabled(set, service)) {
			/* protocol not enabled, ignore its settings */
			continue;
		}

		if (*service->executable != '/' &&
		    *service->executable != '\0') {
			service->executable =
				p_strconcat(pool, set->libexec_dir, "/",
					    service->executable, NULL);
		}
		if (*service->chroot != '/' && *service->chroot != '\0') {
			service->chroot =
				p_strconcat(pool, set->base_dir, "/",
					    service->chroot, NULL);
		}
		if (service->drop_priv_before_exec &&
		    *service->chroot != '\0') {
			*error_r = t_strdup_printf("service(%s): "
				"drop_priv_before_exec=yes can't be "
				"used with chroot", service->name);
			return FALSE;
		}
		process_limit = service->process_limit;
		if (process_limit == 0) {
			*error_r = t_strdup_printf("service(%s): "
				"process_limit must be higher than 0",
				service->name);
			return FALSE;
		}
		if (service->process_min_avail > process_limit) {
			*error_r = t_strdup_printf("service(%s): "
				"process_min_avail is higher than process_limit",
				service->name);
			return FALSE;
		}
		if (service->client_limit == 0) {
			*error_r = t_strdup_printf("service(%s): "
				"client_limit must be higher than 0",
				service->name);
			return FALSE;
		}
		if (service->restart_request_count == 0) {
			*error_r = t_strdup_printf("service(%s): "
				"restart_request_count must be higher than 0 "
				"(did you mean \"unlimited\"?)",
				service->name);
			return FALSE;
		}
		if (service->idle_kill_interval == 0) {
			*error_r = t_strdup_printf("service(%s): "
				"idle_kill_interval must be higher than 0 "
				"(did you mean \"unlimited\"?)",
				service->name);
			return FALSE;
		}
		if (service->vsz_limit < 1024*1024) {
			*error_r = t_strdup_printf("service(%s): "
				"vsz_limit is too low "
				"(did you mean \"unlimited\"?)", service->name);
			return FALSE;
		}

#ifdef CONFIG_BINARY
		default_service =
			master_default_settings_get_service(service->name);
		if (default_service != NULL &&
		    default_service->process_limit_1 && process_limit > 1) {
			*error_r = t_strdup_printf("service(%s): "
				"process_limit must be 1", service->name);
			return FALSE;
		}
#else
		if (max_client_limit < service->client_limit) {
			max_client_limit = service->client_limit;
			max_client_limit_source = t_strdup_printf(
				"service %s { client_limit }", service->name);
		}
#endif

		if (*service->protocol != '\0') {
			/* each imap/pop3/lmtp process can use up a connection,
			   although if restart_request_count=1 it's only temporary.
			   imap-hibernate doesn't do any auth lookups. */
			if ((service->restart_request_count != 1 ||
			     strcmp(service->type, "login") == 0) &&
			    strcmp(service->name, "imap-hibernate") != 0) {
				str_printfa(max_auth_client_processes_reason,
					    " + service %s { process_limit=%u }",
					    service->name, process_limit);
				max_auth_client_processes += process_limit;
			}
		}
		if (strcmp(service->type, "login") == 0 ||
		    strcmp(service->name, "auth") == 0) {
			max_anvil_client_processes += process_limit;
			str_printfa(max_anvil_client_processes_reason,
				    " + service %s { process_limit=%u }",
				    service->name, process_limit);
		}

		if (!fix_file_listener_paths(&service->parsed_unix_listeners, pool,
					     set, &all_listeners, error_r)) {
			*error_r = t_strdup_printf("service(%s): unix_listener: %s",
						   service->name, *error_r);
			return FALSE;
		}
		if (!fix_file_listener_paths(&service->parsed_fifo_listeners, pool,
					     set, &all_listeners, error_r)) {
			*error_r = t_strdup_printf("service(%s): fifo_listener: %s",
						   service->name, *error_r);
			return FALSE;
		}
		add_inet_listeners(&service->parsed_inet_listeners, &all_listeners);
	}

	client_limit = service_get_client_limit(set, "auth");
	if (client_limit < max_auth_client_processes && !warned_auth) {
		warned_auth = TRUE;
		str_delete(max_auth_client_processes_reason, 0, 3);
		i_warning("service auth { client_limit=%u } is lower than "
			  "required under max. load (%u). "
			  "Counted for protocol services with restart_request_count != 1: %s",
			  client_limit, max_auth_client_processes,
			  str_c(max_auth_client_processes_reason));
	}

	client_limit = service_get_client_limit(set, "anvil");
	if (client_limit < max_anvil_client_processes && !warned_anvil) {
		warned_anvil = TRUE;
		str_delete(max_anvil_client_processes_reason, 0, 3);
		i_warning("service anvil { client_limit=%u } is lower than "
			  "required under max. load (%u). Counted with: %s",
			  client_limit, max_anvil_client_processes,
			  str_c(max_anvil_client_processes_reason));
	}
#ifndef CONFIG_BINARY
	if (restrict_get_fd_limit(&fd_limit) == 0 &&
	    fd_limit < (rlim_t)max_client_limit) {
		i_warning("fd limit (ulimit -n) is lower than required "
			  "under max. load (%u < %u), because of %s",
			  (unsigned int)fd_limit, max_client_limit,
			  max_client_limit_source);
	}
#endif

	/* check for duplicate listeners */
	array_sort(&all_listeners, i_strcmp_p);
	strings = array_get(&all_listeners, &count);
	for (i = 1; i < count; i++) {
		if (strcmp(strings[i-1], strings[i]) == 0) {
			*error_r = t_strdup_printf("duplicate listener: %s",
						   strings[i]);
			return FALSE;
		}
	}
	return TRUE;
}
/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("unix_listener_"#name, name, struct file_listener_settings)
static const struct setting_define unix_listener_setting_defines[] = {
	DEF(STR_NOVARS, path),
	DEF(STR, type),
	DEF(UINT_OCT, mode),
	DEF(STR, user),
	DEF(STR, group),

	SETTING_DEFINE_LIST_END
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("fifo_listener_"#name, name, struct file_listener_settings)
static const struct setting_define fifo_listener_setting_defines[] = {
	DEF(STR_NOVARS, path),
	DEF(STR, type),
	DEF(UINT_OCT, mode),
	DEF(STR, user),
	DEF(STR, group),

	SETTING_DEFINE_LIST_END
};
static const struct file_listener_settings file_listener_default_settings = {
	.path = "",
	.type = "",
	.mode = 0600,
	.user = "",
	.group = "",
};
const struct setting_parser_info unix_listener_setting_parser_info = {
	.name = "unix_listener",

	.defines = unix_listener_setting_defines,
	.defaults = &file_listener_default_settings,

	.struct_size = sizeof(struct file_listener_settings),
	.pool_offset1 = 1 + offsetof(struct file_listener_settings, pool),
};
const struct setting_parser_info fifo_listener_setting_parser_info = {
	.name = "fifo_listener",

	.defines = fifo_listener_setting_defines,
	.defaults = &file_listener_default_settings,

	.struct_size = sizeof(struct file_listener_settings),
	.pool_offset1 = 1 + offsetof(struct file_listener_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("inet_listener_"#name, name, struct inet_listener_settings)
static const struct setting_define inet_listener_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, type),
	DEF(IN_PORT, port),
	DEF(BOOL, ssl),
	DEF(BOOL, reuse_port),
	DEF(BOOL, haproxy),

	SETTING_DEFINE_LIST_END
};
static const struct inet_listener_settings inet_listener_default_settings = {
	.name = "",
	.type = "",
	.port = 0,
	.ssl = FALSE,
	.reuse_port = FALSE,
	.haproxy = FALSE
};
const struct setting_parser_info inet_listener_setting_parser_info = {
	.name = "inet_listener",

	.defines = inet_listener_setting_defines,
	.defaults = &inet_listener_default_settings,

	.struct_size = sizeof(struct inet_listener_settings),
	.pool_offset1 = 1 + offsetof(struct inet_listener_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("service_"#name, name, struct service_settings)
static const struct setting_define service_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, protocol),
	DEF(STR, type),
	DEF(STR, executable),
	DEF(STR, user),
	DEF(STR, group),
	DEF(STR, privileged_group),
	DEF(BOOLLIST, extra_groups),
	DEF(STR, chroot),

	DEF(BOOL, drop_priv_before_exec),

	DEF(UINT, process_min_avail),
	DEF(UINT, process_limit),
	DEF(UINT, client_limit),
	DEF(UINT, restart_request_count),
	DEF(TIME, idle_kill_interval),
	DEF(SIZE, vsz_limit),

	{ .type = SET_FILTER_ARRAY, .key = "unix_listener",
	  .offset = offsetof(struct service_settings, unix_listeners),
	  .filter_array_field_name = "unix_listener_path", },
	{ .type = SET_FILTER_ARRAY, .key = "fifo_listener",
	  .offset = offsetof(struct service_settings, fifo_listeners),
	  .filter_array_field_name = "fifo_listener_path", },
	{ .type = SET_FILTER_ARRAY, .key = "inet_listener",
	  .offset = offsetof(struct service_settings, inet_listeners),
	  .filter_array_field_name = "inet_listener_name", },

	SETTING_DEFINE_LIST_END
};
static const struct service_settings service_default_settings = {
	.name = "",
	.protocol = "",
	.type = "",
	.executable = "",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.restart_request_count = SET_UINT_UNLIMITED,
	.idle_kill_interval = 0,
	.vsz_limit = 0,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_parser_info service_setting_parser_info = {
	.name = "service",

	.defines = service_setting_defines,
	.defaults = &service_default_settings,

	.struct_size = sizeof(struct service_settings),
	.pool_offset1 = 1 + offsetof(struct service_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct master_settings)
static const struct setting_define master_setting_defines[] = {
	DEF(STR_HIDDEN, base_dir),
	DEF(STR_HIDDEN, state_dir),
	DEF(STR_HIDDEN, libexec_dir),
	DEF(STR, instance_name),
	DEF(BOOLLIST, protocols),
	DEF(BOOLLIST, listen),
	DEF(ENUM, ssl),
	DEF(STR, default_internal_user),
	DEF(STR, default_internal_group),
	DEF(STR, default_login_user),
	DEF(UINT, default_process_limit),
	DEF(UINT, default_client_limit),
	DEF(TIME, default_idle_kill_interval),
	DEF(SIZE, default_vsz_limit),

	DEF(BOOL, version_ignore),

	DEF(UINT, first_valid_uid),
	DEF(UINT, last_valid_uid),
	DEF(UINT, first_valid_gid),
	DEF(UINT, last_valid_gid),

	{ .type = SET_FILTER_ARRAY, .key = "service",
	  .offset = offsetof(struct master_settings, services),
	  .filter_array_field_name = "service_name", },

	SETTING_DEFINE_LIST_END
};
static const struct master_settings master_default_settings = {
	.base_dir = PKG_RUNDIR,
	.state_dir = PKG_STATEDIR,
	.libexec_dir = PKG_LIBEXECDIR,
	.instance_name = PACKAGE,
	.ssl = "yes:no:required",
	.default_internal_user = "dovecot",
	.default_internal_group = "dovecot",
	.default_login_user = "dovenull",
	.default_process_limit = 100,
	.default_client_limit = 1000,
	.default_idle_kill_interval = 60,
#ifdef DOVECOT_PRO_EDITION
	.default_vsz_limit = 1024*1024*1024,
#else
	.default_vsz_limit = 256*1024*1024,
#endif

	.version_ignore = FALSE,

	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,

	.services = ARRAY_INIT
};
static const struct setting_keyvalue master_default_settings_keyvalue[] = {
	{ "protocols", "" },
	{ "listen", "* ::" },
	{ "service_process_limit", "$SET:default_process_limit" },
	{ "service_client_limit", "$SET:default_client_limit" },
	{ "service_idle_kill_interval", "$SET:default_idle_kill_interval" },
	{ "service_vsz_limit", "$SET:default_vsz_limit" },
	{ NULL, NULL }
};
const struct setting_parser_info master_setting_parser_info = {
	.name = "master",

	.defines = master_setting_defines,
	.defaults = &master_default_settings,
	.default_settings = master_default_settings_keyvalue,

	.struct_size = sizeof(struct master_settings),
	.pool_offset1 = 1 + offsetof(struct master_settings, pool),
	.ext_check_func = master_settings_ext_check
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/acl/acl-rights.c */

/* <settings checks> */
#include "strescape.h"
/* </settings checks> */

/* <settings checks> */
const struct acl_letter_map acl_letter_map[] = {
	{ 'l', MAIL_ACL_LOOKUP },
	{ 'r', MAIL_ACL_READ },
	{ 'w', MAIL_ACL_WRITE },
	{ 's', MAIL_ACL_WRITE_SEEN },
	{ 't', MAIL_ACL_WRITE_DELETED },
	{ 'i', MAIL_ACL_INSERT },
	{ 'p', MAIL_ACL_POST },
	{ 'e', MAIL_ACL_EXPUNGE },
	{ 'k', MAIL_ACL_CREATE },
	{ 'x', MAIL_ACL_DELETE },
	{ 'a', MAIL_ACL_ADMIN },
	{ '\0', NULL }
};

const char *const all_mailbox_rights[] = {
	MAIL_ACL_LOOKUP,
	MAIL_ACL_READ,
	MAIL_ACL_WRITE,
	MAIL_ACL_WRITE_SEEN,
	MAIL_ACL_WRITE_DELETED,
	MAIL_ACL_INSERT,
	MAIL_ACL_POST,
	MAIL_ACL_EXPUNGE,
	MAIL_ACL_CREATE,
	MAIL_ACL_DELETE,
	MAIL_ACL_ADMIN,
	NULL
};

static_assert(N_ELEMENTS(acl_letter_map) == N_ELEMENTS(all_mailbox_rights),
	     "acl_letter_map size differs from all_mailbox_rights");

/* </settings checks> */

/* <settings checks> */
int acl_rights_parse_line(const char *line, pool_t pool,
			  struct acl_rights *rights_r, const char **error_r)
{
	const char *id_str, *const *right_names, *error = NULL;

	/* <id> [<imap acls>] [:<named acls>] */
	if (*line == '"') {
		line++;
		if (str_unescape_next(&line, &id_str) < 0 ||
		    (line[0] != ' ' && line[0] != '\0')) {
			*error_r = "Invalid quoted ID";
			return -1;
		}
		if (line[0] == ' ')
			line++;
	} else {
		id_str = line;
		line = strchr(id_str, ' ');
		if (line == NULL)
			line = "";
		else
			id_str = t_strdup_until(id_str, line++);
	}

	i_zero(rights_r);

	right_names = acl_right_names_parse(pool, line, &error);
	if (*id_str != '-')
		rights_r->rights = right_names;
	else {
		id_str++;
		rights_r->neg_rights = right_names;
	}

	if (acl_identifier_parse(id_str, rights_r) < 0)
		error = t_strdup_printf("Unknown ID '%s'", id_str);

	if (error != NULL) {
		*error_r = error;
		return -1;
	}

	rights_r->identifier = p_strdup(pool, rights_r->identifier);
	return 0;
}
/* </settings checks> */

/* <settings checks> */
int acl_identifier_parse(const char *line, struct acl_rights *rights)
{
	if (str_begins(line, ACL_ID_NAME_USER_PREFIX, &rights->identifier)) {
		rights->id_type = ACL_ID_USER;
	} else if (strcmp(line, ACL_ID_NAME_OWNER) == 0) {
		rights->id_type = ACL_ID_OWNER;
	} else if (str_begins(line, ACL_ID_NAME_GROUP_PREFIX,
			      &rights->identifier)) {
		rights->id_type = ACL_ID_GROUP;
	} else if (str_begins(line, ACL_ID_NAME_GROUP_OVERRIDE_PREFIX,
			      &rights->identifier)) {
		rights->id_type = ACL_ID_GROUP_OVERRIDE;
	} else if (strcmp(line, ACL_ID_NAME_AUTHENTICATED) == 0) {
		rights->id_type = ACL_ID_AUTHENTICATED;
	} else if (strcmp(line, ACL_ID_NAME_ANYONE) == 0 ||
		   strcmp(line, "anonymous") == 0) {
		rights->id_type = ACL_ID_ANYONE;
	} else {
		return -1;
	}
	return 0;
}

static const char *const *
acl_right_names_alloc(pool_t pool, ARRAY_TYPE(const_string) *rights_arr,
		      bool dup_strings)
{
	const char **ret, *const *rights;
	unsigned int i, dest, count;

	/* sort the rights first so we can easily drop duplicates */
	array_sort(rights_arr, i_strcmp_p);

	/* @UNSAFE */
	rights = array_get(rights_arr, &count);
	ret = p_new(pool, const char *, count + 1);
	if (count > 0) {
		ret[0] = rights[0];
		for (i = dest = 1; i < count; i++) {
			if (strcmp(rights[i-1], rights[i]) != 0)
				ret[dest++] = rights[i];
		}
		ret[dest] = NULL;
		if (dup_strings) {
			for (i = 0; i < dest; i++)
				ret[i] = p_strdup(pool, ret[i]);
		}
	}
	return ret;
}

const char *const *
acl_right_names_parse(pool_t pool, const char *acl, const char **error_r)
{
	ARRAY_TYPE(const_string) rights;
	const char *const *names;
	unsigned int i;

	/* parse IMAP ACL list */
	while (*acl == ' ' || *acl == '\t')
		acl++;

	t_array_init(&rights, 64);
	while (*acl != '\0' && *acl != ' ' && *acl != '\t' && *acl != ':') {
		for (i = 0; acl_letter_map[i].letter != '\0'; i++) {
			if (acl_letter_map[i].letter == *acl)
				break;
		}

		if (acl_letter_map[i].letter == '\0') {
			*error_r = t_strdup_printf("Unknown ACL '%c'", *acl);
			return NULL;
		}

		array_push_back(&rights, &acl_letter_map[i].name);
		acl++;
	}
	while (*acl == ' ' || *acl == '\t') acl++;

	if (*acl != '\0') {
		/* parse our own extended ACLs */
		if (*acl != ':') {
			*error_r = "Missing ':' prefix in ACL extensions";
			return NULL;
		}

		names = t_strsplit_spaces(acl + 1, ", \t");
		for (; *names != NULL; names++) {
			const char *name = p_strdup(pool, *names);
			array_push_back(&rights, &name);
		}
	}

	return acl_right_names_alloc(pool, &rights, FALSE);
}
/* </settings checks> */
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/acl/acl-settings.c */
extern const struct setting_parser_info acl_rights_setting_parser_info;
extern const struct setting_parser_info acl_setting_parser_info;

/* <settings checks> */
static bool acl_rights_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct acl_rights_settings *set = _set;
	const char *const *right_names;
	const char *id_str = set->id;
	const char *rights_str = set->rights;

	/* Empty id */
	if (*id_str == '\0')
		return TRUE;

	bool neg = *rights_str == '-';
	if (neg)
		rights_str++;

	set->parsed = p_new(pool, struct acl_rights, 1);

	if (acl_identifier_parse(set->id, set->parsed) < 0) {
		*error_r = t_strdup_printf("Invalid identifier '%s'", set->id);
		return FALSE;
	}

	right_names = acl_right_names_parse(pool, rights_str, error_r);
	if (right_names == NULL)
		return FALSE;

	if (neg) {
		set->parsed->neg_rights = right_names;
	} else {
		set->parsed->rights = right_names;
	}
	return TRUE;
}

static bool acl_settings_check(void *_set ATTR_UNUSED, pool_t pool ATTR_UNUSED,
			       const char **error_r ATTR_UNUSED)
{
	struct acl_settings *set = _set;
	if (array_is_created(&set->acl_groups))
		array_sort(&set->acl_groups, i_strcmp_p);
	return TRUE;
}

/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("acl_"#name, name, struct acl_rights_settings)
static const struct setting_define acl_rights_setting_defines[] = {
	DEF(STR, id),
	DEF(STR, rights),
	SETTING_DEFINE_LIST_END,
};
static const struct acl_rights_settings acl_rights_default_settings = {
	.id = "",
	.rights = "",
};
const struct setting_parser_info acl_rights_setting_parser_info = {
	.name = "acl_rights",
	.plugin_dependency = "lib01_acl_plugin",

	.defines = acl_rights_setting_defines,
	.defaults = &acl_rights_default_settings,

	.struct_size = sizeof(struct acl_rights_settings),

	.check_func = acl_rights_settings_check,

	.pool_offset1 = 1 + offsetof(struct acl_rights_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct acl_settings)
static const struct setting_define acl_setting_defines[] = {
	DEF(STR, acl_user),
	DEF(BOOLLIST, acl_groups),
	DEF(STR, acl_driver),
	DEF(STR, acl_global_path),
	DEF(TIME, acl_cache_ttl),
	DEF(BOOL, acl_globals_only),
	DEF(BOOL, acl_defaults_from_inbox),
	DEF(BOOL, acl_ignore),
	DEF(BOOL, acl_dict_index),
	{ .type = SET_FILTER_NAME, .key = "acl_sharing_map",
		.required_setting = "dict", },
	{ .type = SET_FILTER_ARRAY,
		.key = "acl",
		.filter_array_field_name = "acl_id",
		.required_setting = "acl_rights",
		.offset = offsetof(struct acl_settings, acl_rights)},
	SETTING_DEFINE_LIST_END,
};
static const struct acl_settings acl_default_settings = {
	.acl_user = "%{master_user}",
	.acl_groups = ARRAY_INIT,
	.acl_rights = ARRAY_INIT,
	.acl_driver = "",
	.acl_global_path = "",
	.acl_cache_ttl = ACL_DEFAULT_CACHE_TTL_SECS,
	.acl_globals_only = FALSE,
	.acl_defaults_from_inbox = FALSE,
	.acl_ignore = FALSE,
#ifdef DOVECOT_PRO_EDITION
	.acl_dict_index = TRUE,
#else
	.acl_dict_index = FALSE,
#endif
};
const struct setting_parser_info acl_setting_parser_info = {
	.name = "acl",
	.plugin_dependency = "lib01_acl_plugin",

	.defines = acl_setting_defines,
	.defaults = &acl_default_settings,

	.struct_size = sizeof(struct acl_settings),

	.check_func = acl_settings_check,

	.pool_offset1 = 1 + offsetof(struct acl_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/apparmor/apparmor-plugin.c */
extern const struct setting_parser_info apparmor_setting_parser_info;
struct apparmor_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) apparmor_hats;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct apparmor_settings)
static const struct setting_define apparmor_setting_defines[] = {
	DEF(BOOLLIST, apparmor_hats),

	SETTING_DEFINE_LIST_END
};
static const struct apparmor_settings apparmor_default_settings = {
	.apparmor_hats = ARRAY_INIT,
};
const struct setting_parser_info apparmor_setting_parser_info = {
	.name = "apparmor",
	.plugin_dependency = "lib01_apparmor_plugin",

	.defines = apparmor_setting_defines,
	.defaults = &apparmor_default_settings,

	.struct_size = sizeof(struct apparmor_settings),
	.pool_offset1 = 1 + offsetof(struct apparmor_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/charset-alias/charset-alias-plugin.c */
extern const struct setting_parser_info charset_alias_setting_parser_info;
struct charset_alias_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) charset_aliases;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct charset_alias_settings)
static const struct setting_define charset_alias_setting_defines[] = {
	DEF(STRLIST, charset_aliases),

	SETTING_DEFINE_LIST_END
};
static const struct charset_alias_settings charset_alias_default_settings = {
	.charset_aliases = ARRAY_INIT,
};
const struct setting_parser_info charset_alias_setting_parser_info = {
	.name = "charset_alias",
	.plugin_dependency = "lib20_charset_alias_plugin",

	.defines = charset_alias_setting_defines,
	.defaults = &charset_alias_default_settings,

	.struct_size = sizeof(struct charset_alias_settings),
	.pool_offset1 = 1 + offsetof(struct charset_alias_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/fs-compress/fs-compress.c */
extern const struct setting_parser_info fs_compress_setting_parser_info;
struct fs_compress_settings {
	pool_t pool;
	const char *fs_compress_write_method;
	bool fs_compress_read_plain_fallback;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct fs_compress_settings)
static const struct setting_define fs_compress_setting_defines[] = {
	DEF(STR, fs_compress_write_method),
	DEF(BOOL, fs_compress_read_plain_fallback),

	SETTING_DEFINE_LIST_END
};
static const struct fs_compress_settings fs_compress_default_settings = {
	.fs_compress_write_method = "",
	.fs_compress_read_plain_fallback = FALSE,
};
const struct setting_parser_info fs_compress_setting_parser_info = {
	.name = "fs_compress",
	.plugin_dependency = "libfs_compress",

	.defines = fs_compress_setting_defines,
	.defaults = &fs_compress_default_settings,

	.struct_size = sizeof(struct fs_compress_settings),
	.pool_offset1 = 1 + offsetof(struct fs_compress_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/fts-flatcurve/fts-flatcurve-settings.c */
extern const struct setting_parser_info fts_flatcurve_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("fts_flatcurve_"#name, name, struct fts_flatcurve_settings)
static const struct setting_define fts_flatcurve_setting_defines[] = {
	/* For now this filter just allows grouping the settings
	   like it is possible in the other fts_backends. */
	{ .type = SET_FILTER_NAME, .key = FTS_FLATCURVE_FILTER },
	DEF(UINT, commit_limit),
	DEF(UINT, min_term_size),
	DEF(UINT, optimize_limit),
	DEF(UINT, rotate_count),
	DEF(TIME_MSECS, rotate_time),
	DEF(BOOL, substring_search),
	SETTING_DEFINE_LIST_END
};
static const struct fts_flatcurve_settings fts_flatcurve_default_settings = {
	.commit_limit     =   500,
	.min_term_size    =     2,
	.optimize_limit   =    10,
	.rotate_count     =  5000,
	.rotate_time      =  5000,
	.substring_search = FALSE,
};
const struct setting_parser_info fts_flatcurve_setting_parser_info = {
	.name = "fts_flatcurve",
	.plugin_dependency = "lib21_fts_flatcurve_plugin",

	.defines = fts_flatcurve_setting_defines,
	.defaults = &fts_flatcurve_default_settings,

	.struct_size = sizeof(struct fts_flatcurve_settings),
	.pool_offset1 = 1 + offsetof(struct fts_flatcurve_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/fts-solr/fts-solr-settings.c */
extern const struct setting_parser_info fts_solr_setting_parser_info;
#undef DEF
#define DEF(type, name) SETTING_DEFINE_STRUCT_##type( \
	FTS_SOLR_FILTER"_"#name, name, struct fts_solr_settings)
static const struct setting_define fts_solr_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = FTS_SOLR_FILTER },
	DEF(STR,  url),
	DEF(UINT, batch_size),
	DEF(BOOL, soft_commit),
	SETTING_DEFINE_LIST_END
};
static const struct fts_solr_settings fts_solr_default_settings = {
	.url               = "",
	.batch_size        = 1000,
	.soft_commit       = TRUE,
};
static const struct setting_keyvalue fts_solr_default_settings_keyvalue[] = {
	{ FTS_SOLR_FILTER"/http_client_max_idle_time", "5s" },
	{ FTS_SOLR_FILTER"/http_client_max_parallel_connections", "1" },
	{ FTS_SOLR_FILTER"/http_client_max_pipelined_requests", "1" },
	{ FTS_SOLR_FILTER"/http_client_request_max_redirects", "1" },
	{ FTS_SOLR_FILTER"/http_client_request_max_attempts", "3" },
	{ FTS_SOLR_FILTER"/http_client_connect_timeout", "5s" },
	{ FTS_SOLR_FILTER"/http_client_request_timeout", "60s" },
	{ NULL, NULL }
};
const struct setting_parser_info fts_solr_setting_parser_info = {
	.name = FTS_SOLR_FILTER,
	.plugin_dependency = "lib21_fts_solr_plugin",

	.defines = fts_solr_setting_defines,
	.defaults = &fts_solr_default_settings,
	.default_settings = fts_solr_default_settings_keyvalue,

	.struct_size = sizeof(struct fts_solr_settings),
	.pool_offset1 = 1 + offsetof(struct fts_solr_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/fts/fts-settings.c */
extern const struct setting_parser_info fts_setting_parser_info;

/* <settings checks> */

#define FTS_SEARCH_ADD_MISSING_BODY_SEARCH_ONLY "body-search-only"

#define FTS_DECODER_KEYWORD_NONE   ""
#define FTS_DECODER_KEYWORD_TIKA   "tika"
#define FTS_DECODER_KEYWORD_SCRIPT "script"

static bool fts_settings_check(void *set, pool_t pool, const char **error_r);

/* </settings checks> */

/* <settings checks> */

struct fts_settings_enum_table {
	const char *key;
	int value;
};

static int fts_settings_parse_enum(struct fts_settings_enum_table *table,
				   const char *key)
{
	for (; table->key != NULL; table++)
		if (strcasecmp(key, table->key) == 0)
			return table->value;
	i_unreached();
}

static enum fts_decoder fts_settings_parse_decoder(const char *key)
{
	static struct fts_settings_enum_table table[] = {
		{ FTS_DECODER_KEYWORD_NONE,   FTS_DECODER_NO },
		{ FTS_DECODER_KEYWORD_TIKA,   FTS_DECODER_TIKA },
		{ FTS_DECODER_KEYWORD_SCRIPT, FTS_DECODER_SCRIPT },
		{ NULL, 0 }
	};
	return fts_settings_parse_enum(table, key);
}

static bool fts_settings_check_decoder(struct fts_settings *set,
				       const char **error_r)
{
	switch (set->parsed_decoder_driver) {
	case FTS_DECODER_SCRIPT:
		if (*set->decoder_script_socket_path != '\0')
			return TRUE;
		*error_r = "decoder_script_socket_path is required "
			   "when fts_decoder_driver = script";
		return FALSE;
	case FTS_DECODER_NO:
	case FTS_DECODER_TIKA:
		return TRUE;
	default:
		i_unreached();
	}

	if(*set->decoder_script_socket_path != '\0' &&
	   set->parsed_decoder_driver != FTS_DECODER_SCRIPT) {
		*error_r = "fts_decoder_driver = script is required "
			   "when using decoder_script_socket_path";
		return FALSE;
	}
	if(*set->decoder_tika_url != '\0' &&
	   set->parsed_decoder_driver != FTS_DECODER_TIKA) {
		*error_r = "fts_decoder_script = tika is required "
			   "when using decoder_tika_url";
		return FALSE;
	}
}

static bool fts_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			       const char **error_r)
{
	struct fts_settings *set = _set;

	if (set->search_timeout == 0) {
		*error_r = "fts_search_timeout must not be 0";
		return FALSE;
	}
	set->parsed_search_add_missing_body_only =
		strcmp(set->search_add_missing,
		       FTS_SEARCH_ADD_MISSING_BODY_SEARCH_ONLY) == 0;
	set->parsed_decoder_driver = fts_settings_parse_decoder(set->decoder_driver);
	return fts_settings_check_decoder(set, error_r);
}

/* </settings checks> */
#undef DEF
#define DEF(_type, name) SETTING_DEFINE_STRUCT_##_type( \
	FTS_FILTER"_"#name, name, struct fts_settings)
static const struct setting_define fts_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = FTS_FILTER,
	  .offset = offsetof(struct fts_settings, fts),
	  .filter_array_field_name = "fts_driver", },
	DEF(BOOL,    autoindex),
	DEF(UINT,    autoindex_max_recent_msgs),
	DEF(ENUM,    decoder_driver),
	DEF(STR,     decoder_script_socket_path),
	{ .type = SET_FILTER_NAME, .key = FTS_FILTER_DECODER_TIKA },
	DEF(STR,     decoder_tika_url),
	DEF(STR,     driver),
	DEF(BOOL,    search),
	DEF(ENUM,    search_add_missing),
	DEF(BOOL,    search_read_fallback),
	DEF(BOOLLIST,header_excludes),
	DEF(BOOLLIST,header_includes),
	DEF(TIME,    search_timeout),
	DEF(SIZE,    message_max_size),
	SETTING_DEFINE_LIST_END
};
static const struct fts_settings fts_default_settings = {
	.fts = ARRAY_INIT,
	.autoindex = FALSE,
	.autoindex_max_recent_msgs = 0,
	.decoder_driver = FTS_DECODER_KEYWORD_NONE
		       ":"FTS_DECODER_KEYWORD_TIKA
		       ":"FTS_DECODER_KEYWORD_SCRIPT,
	.decoder_script_socket_path = "",
	.decoder_tika_url = "",
	.driver = "",
	.search = TRUE,
	.search_add_missing = FTS_SEARCH_ADD_MISSING_BODY_SEARCH_ONLY":yes",
#ifdef DOVECOT_PRO_EDITION
	.search_read_fallback = FALSE,
#else
	.search_read_fallback = TRUE,
#endif

	.search_timeout = 30,
	.message_max_size = SET_SIZE_UNLIMITED,
};
static const struct setting_keyvalue fts_default_settings_keyvalue[] = {
	{ FTS_FILTER_DECODER_TIKA"/http_client_max_idle_time", "100ms" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_max_parallel_connections", "1" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_max_pipelined_requests", "1" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_request_max_redirects", "1" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_request_max_attempts", "3" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_connect_timeout", "5s" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_request_timeout", "60s" },
	{ NULL, NULL }
};
const struct setting_parser_info fts_setting_parser_info = {
	.name = FTS_FILTER,
	.plugin_dependency = "lib20_fts_plugin",

	.defines = fts_setting_defines,
	.defaults = &fts_default_settings,
	.default_settings = fts_default_settings_keyvalue,
	.check_func = fts_settings_check,

	.struct_size = sizeof(struct fts_settings),
	.pool_offset1 = 1 + offsetof(struct fts_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/imap-acl/imap-acl-plugin.c */
extern const struct setting_parser_info imap_acl_setting_parser_info;

/* <settings checks> */
struct imap_acl_settings {
	pool_t pool;
	bool allow_anyone;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("imap_acl_" #name, name, \
				     struct imap_acl_settings)

static const struct setting_define imap_acl_setting_defines[] = {
	DEF(BOOL, allow_anyone),

	SETTING_DEFINE_LIST_END
};

static struct imap_acl_settings imap_acl_default_settings = {
	.allow_anyone = FALSE,
};
/* </settings checks> */
const struct setting_parser_info imap_acl_setting_parser_info = {
	.name = "imap_acl",
	.plugin_dependency = "lib02_imap_acl_plugin",

	.defines = imap_acl_setting_defines,
	.defaults = &imap_acl_default_settings,

	.struct_size = sizeof(struct imap_acl_settings),
	.pool_offset1 = 1 + offsetof(struct imap_acl_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/last-login/last-login-plugin.c */
extern const struct setting_parser_info last_login_setting_parser_info;
struct last_login_settings {
	pool_t pool;

	const char *last_login_key;
	const char *last_login_precision;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct last_login_settings)
static const struct setting_define last_login_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "last_login" },
	DEF(STR, last_login_key),
	DEF(ENUM, last_login_precision),

	SETTING_DEFINE_LIST_END
};
static const struct last_login_settings last_login_default_settings = {
	.last_login_key = "last-login/%{user}",
	.last_login_precision = "s:ms:us:ns",
};
const struct setting_parser_info last_login_setting_parser_info = {
	.name = "last_login",
	.plugin_dependency = "lib10_last_login_plugin",

	.defines = last_login_setting_defines,
	.defaults = &last_login_default_settings,

	.struct_size = sizeof(struct last_login_settings),
	.pool_offset1 = 1 + offsetof(struct last_login_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/lazy-expunge/lazy-expunge-settings.c */
extern const struct setting_parser_info lazy_expunge_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct lazy_expunge_settings)
static struct setting_define lazy_expunge_setting_defines[] = {
	DEF(BOOL, lazy_expunge_only_last_instance),
	DEF(STR, lazy_expunge_mailbox),

	SETTING_DEFINE_LIST_END
};
static struct lazy_expunge_settings lazy_expunge_default_settings = {
	.lazy_expunge_only_last_instance = FALSE,
	.lazy_expunge_mailbox = "",
};
const struct setting_parser_info lazy_expunge_setting_parser_info = {
	.name = "lazy_expunge",
	.plugin_dependency = "lib02_lazy_expunge_plugin",

	.defines = lazy_expunge_setting_defines,
	.defaults = &lazy_expunge_default_settings,

	.struct_size = sizeof(struct lazy_expunge_settings),
	.pool_offset1 = 1 + offsetof(struct lazy_expunge_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/mail-compress/mail-compress-plugin.c */
extern const struct setting_parser_info mail_compress_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_compress_settings)
static struct setting_define mail_compress_setting_defines[] = {
	DEF(STR, mail_compress_write_method),

	SETTING_DEFINE_LIST_END
};
static struct mail_compress_settings mail_compress_default_settings = {
	.mail_compress_write_method = "",
};
const struct setting_parser_info mail_compress_setting_parser_info = {
	.name = "mail_compress",
	.plugin_dependency = "lib20_mail_compress_plugin",

	.defines = mail_compress_setting_defines,
	.defaults = &mail_compress_default_settings,

	.struct_size = sizeof(struct mail_compress_settings),
	.pool_offset1 = 1 + offsetof(struct mail_compress_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/mail-crypt/crypt-settings.c */
extern const struct setting_parser_info crypt_private_key_setting_parser_info;
extern const struct setting_parser_info crypt_setting_parser_info;
extern const struct setting_parser_info crypt_acl_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct crypt_private_key_settings)
static const struct setting_define crypt_private_key_setting_defines[] = {
	DEF(STR, crypt_private_key_name),
	DEF(FILE, crypt_private_key_file),
	DEF(STR, crypt_private_key_password),

	SETTING_DEFINE_LIST_END
};
static const struct crypt_private_key_settings crypt_private_key_default_settings = {
	.crypt_private_key_name = "",
	.crypt_private_key_file = "",
	.crypt_private_key_password = "",
};
const struct setting_parser_info crypt_private_key_setting_parser_info = {
	.name = "crypt_private_key",
	.plugin_dependency = "lib10_mail_crypt_plugin",

	.defines = crypt_private_key_setting_defines,
	.defaults = &crypt_private_key_default_settings,

	.struct_size = sizeof(struct crypt_private_key_settings),
	.pool_offset1 = 1 + offsetof(struct crypt_private_key_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct crypt_settings)
static const struct setting_define crypt_setting_defines[] = {
	DEF(BOOL, fs_crypt_read_plain_fallback),

	DEF(FILE, crypt_global_public_key_file),
	{ .type = SET_FILTER_ARRAY, .key = "crypt_global_private_key",
	   .offset = offsetof(struct crypt_settings, crypt_global_private_keys),
	   .filter_array_field_name = "crypt_private_key_name" },

	DEF(STR, crypt_write_algorithm),

	{ .type = SET_FILTER_ARRAY, .key = "crypt_user_key_encryption_key",
	   .offset = offsetof(struct crypt_settings, crypt_user_key_encryption_keys),
	   .filter_array_field_name = "crypt_private_key_name" },
	DEF(STR, crypt_user_key_password),
	DEF(STR, crypt_user_key_curve),
	DEF(BOOL, crypt_user_key_require_encrypted),

	SETTING_DEFINE_LIST_END
};
static const struct crypt_settings crypt_default_settings = {
	.fs_crypt_read_plain_fallback = FALSE,

	.crypt_global_public_key_file = "",
	.crypt_global_private_keys = ARRAY_INIT,

	.crypt_write_algorithm = "aes-256-gcm-sha256",

	.crypt_user_key_encryption_keys = ARRAY_INIT,
	.crypt_user_key_password = "",
	.crypt_user_key_curve = "",
	.crypt_user_key_require_encrypted = FALSE,
};
const struct setting_parser_info crypt_setting_parser_info = {
	.name = "crypt",
	.plugin_dependency = "lib10_mail_crypt_plugin",

	.defines = crypt_setting_defines,
	.defaults = &crypt_default_settings,

	.struct_size = sizeof(struct crypt_settings),
	.pool_offset1 = 1 + offsetof(struct crypt_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct crypt_acl_settings)
static const struct setting_define crypt_acl_setting_defines[] = {
	DEF(BOOL, crypt_acl_require_secure_key_sharing),

	SETTING_DEFINE_LIST_END
};
static const struct crypt_acl_settings crypt_acl_default_settings = {
	.crypt_acl_require_secure_key_sharing = FALSE,
};
const struct setting_parser_info crypt_acl_setting_parser_info = {
	.name = "crypt_acl",
	.plugin_dependency = "lib05_mail_crypt_acl_plugin",

	.defines = crypt_acl_setting_defines,
	.defaults = &crypt_acl_default_settings,

	.struct_size = sizeof(struct crypt_acl_settings),
	.pool_offset1 = 1 + offsetof(struct crypt_acl_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/mail-log/mail-log-plugin.c */
extern const struct setting_parser_info mail_log_setting_parser_info;

/* <settings checks> */
enum mail_log_field {
	MAIL_LOG_FIELD_UID	= 0x01,
	MAIL_LOG_FIELD_BOX	= 0x02,
	MAIL_LOG_FIELD_MSGID	= 0x04,
	MAIL_LOG_FIELD_PSIZE	= 0x08,
	MAIL_LOG_FIELD_VSIZE	= 0x10,
	MAIL_LOG_FIELD_FLAGS	= 0x20,
	MAIL_LOG_FIELD_FROM	= 0x40,
	MAIL_LOG_FIELD_SUBJECT	= 0x80
};

enum mail_log_event {
	MAIL_LOG_EVENT_DELETE		= 0x01,
	MAIL_LOG_EVENT_UNDELETE		= 0x02,
	MAIL_LOG_EVENT_EXPUNGE		= 0x04,
	MAIL_LOG_EVENT_SAVE		= 0x08,
	MAIL_LOG_EVENT_COPY		= 0x10,
	MAIL_LOG_EVENT_MAILBOX_CREATE	= 0x20,
	MAIL_LOG_EVENT_MAILBOX_DELETE	= 0x40,
	MAIL_LOG_EVENT_MAILBOX_RENAME	= 0x80,
	MAIL_LOG_EVENT_FLAG_CHANGE	= 0x100
};

static const char *field_names[] = {
	"uid",
	"box",
	"msgid",
	"size",
	"vsize",
	"flags",
	"from",
	"subject",
	NULL
};

static const char *event_names[] = {
	"delete",
	"undelete",
	"expunge",
	"save",
	"copy",
	"mailbox_create",
	"mailbox_delete",
	"mailbox_rename",
	"flag_change",
	NULL
};

struct mail_log_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) mail_log_fields;
	ARRAY_TYPE(const_string) mail_log_events;
	bool mail_log_cached_only;

	enum mail_log_field parsed_fields;
	enum mail_log_event parsed_events;
};
/* </settings checks> */

/* <settings checks> */
static enum mail_log_field mail_log_field_find(const char *name)
{
	unsigned int i;

	for (i = 0; field_names[i] != NULL; i++) {
		if (strcmp(name, field_names[i]) == 0)
			return 1 << i;
	}
	return 0;
}

static enum mail_log_event mail_log_event_find(const char *name)
{
	unsigned int i;

	if (strcmp(name, "append") == 0) {
		/* v1.x backwards compatibility */
		name = "save";
	}
	for (i = 0; event_names[i] != NULL; i++) {
		if (strcmp(name, event_names[i]) == 0)
			return 1 << i;
	}
	return 0;
}

static int
mail_log_parse_fields(const ARRAY_TYPE(const_string) *arr,
		      enum mail_log_field *fields_r, const char **error_r)
{
	const char *str;
	enum mail_log_field field;

	*fields_r = 0;
	array_foreach_elem(arr, str) {
		field = mail_log_field_find(str);
		if (field == 0) {
			*error_r = t_strdup_printf(
				"Unknown field in mail_log_fields: '%s'", str);
			return -1;
		}
		*fields_r |= field;
	}
	return 0;
}

static int
mail_log_parse_events(const ARRAY_TYPE(const_string) *arr,
		      enum mail_log_event *events_r, const char **error_r)
{
	const char *str;
	enum mail_log_event event;

	*events_r = 0;
	array_foreach_elem(arr, str) {
		event = mail_log_event_find(str);
		if (event == 0) {
			*error_r = t_strdup_printf(
				"Unknown event in mail_log_events: '%s'", str);
			return -1;
		}
		*events_r |= event;
	}
	return 0;
}

static bool mail_log_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				    const char **error_r)
{
	struct mail_log_settings *set = _set;

	if (mail_log_parse_fields(&set->mail_log_fields, &set->parsed_fields,
				  error_r) < 0)
		return FALSE;
	if (mail_log_parse_events(&set->mail_log_events, &set->parsed_events,
				  error_r) < 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct mail_log_settings)
static const struct setting_define mail_log_setting_defines[] = {
	DEF(BOOLLIST, mail_log_fields),
	DEF(BOOLLIST, mail_log_events),
	DEF(BOOL, mail_log_cached_only),

	SETTING_DEFINE_LIST_END
};
static const struct mail_log_settings mail_log_default_settings = {
	.mail_log_fields = ARRAY_INIT,
	.mail_log_events = ARRAY_INIT,
	.mail_log_cached_only = FALSE,
};
static const struct setting_keyvalue mail_log_default_settings_keyvalue[] = {
	{ "mail_log_fields/uid", "yes" },
	{ "mail_log_fields/msgid", "yes" },
	{ "mail_log_fields/size", "yes" },
	{ "mail_log_events/delete", "yes" },
	{ "mail_log_events/undelete", "yes" },
	{ "mail_log_events/expunge", "yes" },
	{ "mail_log_events/save", "yes" },
	{ "mail_log_events/copy", "yes" },
	{ "mail_log_events/mailbox_delete", "yes" },
	{ "mail_log_events/mailbox_rename", "yes" },
	{ NULL, NULL }
};
const struct setting_parser_info mail_log_setting_parser_info = {
	.name = "mail_log",
	.plugin_dependency = "lib20_mail_log_plugin",

	.defines = mail_log_setting_defines,
	.defaults = &mail_log_default_settings,
	.default_settings = mail_log_default_settings_keyvalue,
	.check_func = mail_log_settings_check,

	.struct_size = sizeof(struct mail_log_settings),
	.pool_offset1 = 1 + offsetof(struct mail_log_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/mail-lua/mail-lua-settings.c */
extern const struct setting_parser_info mail_lua_setting_parser_info;
static const struct setting_define mail_lua_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = MAIL_LUA_FILTER },
	SETTING_DEFINE_LIST_END
};
static const struct mail_lua_settings mail_lua_default_settings = {
};
const struct setting_parser_info mail_lua_setting_parser_info = {
	.name = "mail_lua",
	.plugin_dependency = "lib01_mail_lua_plugin",

	.defines = mail_lua_setting_defines,
	.defaults = &mail_lua_default_settings,

	.struct_size = sizeof(struct mail_lua_settings),
	.pool_offset1 = 1 + offsetof(struct mail_lua_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/notify-status/notify-status-plugin.c */
extern const struct setting_parser_info notify_status_plugin_setting_parser_info;
#define NOTIFY_STATUS_SETTING_VALUE_TEMPLATE_DEFAULT "{\"messages\":%{messages},\"unseen\":%{unseen}}"
struct notify_status_plugin_settings {
	pool_t pool;

	bool mailbox_notify_status;
	const char *notify_status_value;
};
#undef DEF
#define DEF(type, name) \
       SETTING_DEFINE_STRUCT_##type(#name, name, struct notify_status_plugin_settings)
static const struct setting_define notify_status_plugin_setting_defines[] = {
       DEF(BOOL, mailbox_notify_status),
       DEF(STR_NOVARS, notify_status_value),
       { .type = SET_FILTER_NAME, .key = "notify_status",
	 .required_setting = "dict", },

       SETTING_DEFINE_LIST_END
};
static const struct notify_status_plugin_settings notify_status_plugin_default_settings = {
	.notify_status_value = NOTIFY_STATUS_SETTING_VALUE_TEMPLATE_DEFAULT,
	.mailbox_notify_status = FALSE,
};
const struct setting_parser_info notify_status_plugin_setting_parser_info = {
       .name = "notify_status",
       .plugin_dependency = "lib20_notify_status_plugin",

       .defines = notify_status_plugin_setting_defines,
       .defaults = &notify_status_plugin_default_settings,

       .struct_size = sizeof(struct notify_status_plugin_settings),
       .pool_offset1 = 1 + offsetof(struct notify_status_plugin_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/pop3-migration/pop3-migration-plugin.c */
extern const struct setting_parser_info pop3_migration_setting_parser_info;
struct pop3_migration_settings {
	pool_t pool;

	const char *mailbox;
	bool all_mailboxes;
	bool ignore_missing_uidls;
	bool ignore_extra_uidls;
	bool skip_size_check;
	bool skip_uidl_cache;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("pop3_migration_"#name, name, \
		struct pop3_migration_settings)
static const struct setting_define pop3_migration_setting_defines[] = {
	DEF(STR, mailbox),
	DEF(BOOL, all_mailboxes),
	DEF(BOOL, ignore_missing_uidls),
	DEF(BOOL, ignore_extra_uidls),
	DEF(BOOL, skip_size_check),
	DEF(BOOL, skip_uidl_cache),

	SETTING_DEFINE_LIST_END
};
static const struct pop3_migration_settings pop3_migration_default_settings = {
	.mailbox = "",
	.all_mailboxes = FALSE,
	.ignore_missing_uidls = FALSE,
	.ignore_extra_uidls = FALSE,
	.skip_size_check = FALSE,
	.skip_uidl_cache = FALSE,
};
const struct setting_parser_info pop3_migration_setting_parser_info = {
	.name = "pop3_migration",
	.plugin_dependency = "lib05_pop3_migration_plugin",

	.defines = pop3_migration_setting_defines,
	.defaults = &pop3_migration_default_settings,

	.struct_size = sizeof(struct pop3_migration_settings),
	.pool_offset1 = 1 + offsetof(struct pop3_migration_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/push-notification/push-notification-settings.c */
extern const struct setting_parser_info push_notification_ox_setting_parser_info;
extern const struct setting_parser_info push_notification_setting_parser_info;

/* <settings checks> */
#include "http-url.h"
/* </settings checks> */

/* <settings checks> */
static bool
push_notification_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r ATTR_UNUSED)
{
	struct push_notification_settings *set = _set;

	if (set->driver[0] == '\0')
		set->driver = set->name;
	return TRUE;
}

static bool
push_notification_ox_settings_check(void *_set, pool_t pool,
				    const char **error_r)
{
	struct push_notification_ox_settings *set = _set;
	const char *error;

	if (set->url[0] != '\0') {
		if (http_url_parse(set->url, NULL, HTTP_URL_ALLOW_USERINFO_PART,
				   pool, &set->parsed_url, &error) < 0) {
			*error_r = t_strdup_printf(
				"Invalid push_notification_ox_url '%s': %s",
				set->url, error);
			return FALSE;
		}
	} else
		set->parsed_url = NULL;

	if (set->cache_ttl == 0) {
		*error_r = "push_notification_ox_cache_ttl must not be 0";
		return FALSE;
	}

	return TRUE;
}
/* </settings checks> */
#define PUSH_NOTIFICATION_DRIVER_OX_DEFAULT_CACHE_TTL_MSECS (60 * 1000)
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("push_notification_ox_"#name, name, struct push_notification_ox_settings)
static const struct setting_define push_notification_ox_setting_defines[] = {
	DEF(STR, url),
	DEF(TIME_MSECS, cache_ttl),
	DEF(BOOL, user_from_metadata),

	SETTING_DEFINE_LIST_END,
};
static const struct push_notification_ox_settings push_notification_ox_default_settings = {
	.url = "",
	.cache_ttl = PUSH_NOTIFICATION_DRIVER_OX_DEFAULT_CACHE_TTL_MSECS,
	.user_from_metadata = FALSE,
};
const struct setting_parser_info push_notification_ox_setting_parser_info = {
	.name = "push_notification_ox",
	.plugin_dependency = "lib20_push_notification_plugin",

	.defines = push_notification_ox_setting_defines,
	.defaults = &push_notification_ox_default_settings,

	.struct_size = sizeof(struct push_notification_ox_settings),
	.pool_offset1 = 1 + offsetof(struct push_notification_ox_settings, pool),
	.check_func = push_notification_ox_settings_check,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("push_notification_"#name, name, struct push_notification_settings)
static const struct setting_define push_notification_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	{
		.type = SET_FILTER_ARRAY,
		.key = PUSH_NOTIFICATION_SETTINGS_FILTER_NAME,
		.offset = offsetof(struct push_notification_settings, push_notifications),
		.filter_array_field_name = "push_notification_name",
	},

	SETTING_DEFINE_LIST_END,
};
static const struct push_notification_settings push_notification_default_settings = {
	.name = "",
	.driver = "",
	.push_notifications = ARRAY_INIT,
};
const struct setting_parser_info push_notification_setting_parser_info = {
	.name = "push_notification",
	.plugin_dependency = "lib20_push_notification_plugin",

	.defines = push_notification_setting_defines,
	.defaults = &push_notification_default_settings,

	.struct_size = sizeof(struct push_notification_settings),
	.pool_offset1 = 1 + offsetof(struct push_notification_settings, pool),

	.check_func = push_notification_settings_check,
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/quota-clone/quota-clone-settings.c */
extern const struct setting_parser_info quota_clone_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("quota_clone_"#name, name, struct quota_clone_settings)
static const struct setting_define quota_clone_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "quota_clone", .required_setting = "dict" },
	DEF(BOOL, unset),
	SETTING_DEFINE_LIST_END
};
static const struct quota_clone_settings quota_clone_default_settings = {
	.unset = FALSE,
};
const struct setting_parser_info quota_clone_setting_parser_info = {
	.name = "quota_clone",
	.plugin_dependency = "lib20_quota_clone_plugin",
	.defines = quota_clone_setting_defines,
	.defaults = &quota_clone_default_settings,
	.struct_size = sizeof(struct quota_clone_settings),
	.pool_offset1 = 1 + offsetof(struct quota_clone_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/quota/quota-fs.c */
extern const struct setting_parser_info quota_fs_setting_parser_info;
struct quota_fs_settings {
	pool_t pool;

	const char *quota_fs_mount_path;
	const char *quota_fs_type;
	bool quota_fs_message_limit;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_fs_settings)
static const struct setting_define quota_fs_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "quota_fs" },
	DEF(STR, quota_fs_mount_path),
	DEF(ENUM, quota_fs_type),
	DEF(BOOL, quota_fs_message_limit),

	SETTING_DEFINE_LIST_END
};
static const struct quota_fs_settings quota_fs_default_settings = {
	.quota_fs_mount_path = "",
	.quota_fs_type = "any:user:group",
	.quota_fs_message_limit = FALSE,
};
const struct setting_parser_info quota_fs_setting_parser_info = {
	.name = "quota_fs",
	.plugin_dependency = "lib10_quota_plugin",
	.defines = quota_fs_setting_defines,
	.defaults = &quota_fs_default_settings,
	.struct_size = sizeof(struct quota_fs_settings),
	.pool_offset1 = 1 + offsetof(struct quota_fs_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/quota/quota-imapc.c */
extern const struct setting_parser_info quota_imapc_setting_parser_info;
struct quota_imapc_settings {
	pool_t pool;

	const char *quota_imapc_mailbox_name;
	const char *quota_imapc_root_name;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_imapc_settings)
static const struct setting_define quota_imapc_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "quota_imapc" },
	DEF(STR, quota_imapc_mailbox_name),
	DEF(STR, quota_imapc_root_name),

	SETTING_DEFINE_LIST_END
};
static const struct quota_imapc_settings quota_imapc_default_settings = {
	.quota_imapc_mailbox_name = "INBOX",
	.quota_imapc_root_name = "",
};
static const struct setting_keyvalue quota_imapc_default_settings_keyvalue[] = {
	/* imapc should never try to enforce the quota - it's just a lot of
	   unnecessary remote GETQUOTA calls. */
	{ "quota_imapc/quota_enforce", "no" },
	{ NULL, NULL }
};
const struct setting_parser_info quota_imapc_setting_parser_info = {
	.name = "quota_imapc",
	.plugin_dependency = "lib10_quota_plugin",
	.defines = quota_imapc_setting_defines,
	.defaults = &quota_imapc_default_settings,
	.default_settings = quota_imapc_default_settings_keyvalue,
	.struct_size = sizeof(struct quota_imapc_settings),
	.pool_offset1 = 1 + offsetof(struct quota_imapc_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/quota/quota-settings.c */
extern const struct setting_parser_info quota_setting_parser_info;
extern const struct setting_parser_info quota_root_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_settings)
static const struct setting_define quota_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "quota_count" },
	{ .type = SET_FILTER_NAME, .key = "quota_maildir" },

	{ .type = SET_FILTER_ARRAY, .key = "quota",
	  .offset = offsetof(struct quota_settings, quota_roots),
	  .filter_array_field_name = "quota_name", },

	DEF(UINT, quota_mailbox_count),
	DEF(UINT, quota_mailbox_message_count),
	DEF(SIZE, quota_mail_size),
	DEF(STR, quota_exceeded_message),

	SETTING_DEFINE_LIST_END
};
static const struct quota_settings quota_default_settings = {
	.quota_roots = ARRAY_INIT,

	.quota_mailbox_count = SET_UINT_UNLIMITED,
	.quota_mail_size = SET_SIZE_UNLIMITED,
	.quota_mailbox_message_count = SET_UINT_UNLIMITED,
	.quota_exceeded_message = "Quota exceeded (mailbox for user is full)",
};
const struct setting_parser_info quota_setting_parser_info = {
	.name = "quota",
	.plugin_dependency = "lib10_quota_plugin",
	.defines = quota_setting_defines,
	.defaults = &quota_default_settings,
	.struct_size = sizeof(struct quota_settings),
	.pool_offset1 = 1 + offsetof(struct quota_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_root_settings)
static const struct setting_define quota_root_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = "quota_warning",
	  .offset = offsetof(struct quota_root_settings, quota_warnings),
	  .filter_array_field_name = "quota_warning_name",
	  .required_setting = "execute", },

	DEF(STR, quota_name),
	DEF(STR, quota_driver),
	DEF(BOOL, quota_ignore),
	DEF(BOOL, quota_ignore_unlimited),
	DEF(BOOL, quota_enforce),
	DEF(BOOL, quota_hidden),
	DEF(SIZE, quota_storage_size),
	DEF(UINT, quota_storage_percentage),
	DEF(SIZE, quota_storage_extra),
	DEF(SIZE, quota_storage_grace),
	DEF(UINT, quota_message_count),
	DEF(UINT, quota_message_percentage),

	DEF(STR, quota_warning_name),
	DEF(ENUM, quota_warning_resource),
	DEF(ENUM, quota_warning_threshold),

	{ .type = SET_FILTER_NAME, .key = "quota_over_status",
	  .required_setting = "execute", },
	DEF(BOOL, quota_over_status_lazy_check),
	DEF(STR, quota_over_status_current),
	DEF(STR, quota_over_status_mask),

	SETTING_DEFINE_LIST_END
};
static const struct quota_root_settings quota_root_default_settings = {
	.quota_warnings = ARRAY_INIT,

	.quota_name = "",
	.quota_driver = "count",
	.quota_ignore = FALSE,
	.quota_ignore_unlimited = FALSE,
	.quota_enforce = TRUE,
	.quota_hidden = FALSE,
	.quota_storage_size = SET_SIZE_UNLIMITED,
	.quota_storage_percentage = 100,
	.quota_storage_extra = 0,
	.quota_storage_grace = 1024 * 1024 * 10,
	.quota_message_count = SET_UINT_UNLIMITED,
	.quota_message_percentage = 100,

	.quota_warning_name = "",
	.quota_warning_resource = QUOTA_WARNING_RESOURCE_STORAGE":"
		QUOTA_WARNING_RESOURCE_MESSAGE,
	.quota_warning_threshold = QUOTA_WARNING_THRESHOLD_OVER":"
		QUOTA_WARNING_THRESHOLD_UNDER,

	.quota_over_status_lazy_check = FALSE,
	.quota_over_status_current = "",
	.quota_over_status_mask = "",
};
const struct setting_parser_info quota_root_setting_parser_info = {
	.name = "quota_root",
	.plugin_dependency = "lib10_quota_plugin",
	.defines = quota_root_setting_defines,
	.defaults = &quota_root_default_settings,
	.struct_size = sizeof(struct quota_root_settings),
#ifndef CONFIG_BINARY
	.check_func = quota_root_settings_check,
#endif
	.pool_offset1 = 1 + offsetof(struct quota_root_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/quota/quota-status-settings.c */
extern const struct setting_parser_info quota_status_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_status_settings)
static const struct setting_define quota_status_setting_defines[] = {
	DEF(STR, recipient_delimiter),
	DEF(STR, quota_status_nouser),

	SETTING_DEFINE_LIST_END
};
static const struct quota_status_settings quota_status_default_settings = {
	.recipient_delimiter = "+",
	.quota_status_nouser = "REJECT Unknown user",
};
const struct setting_parser_info quota_status_setting_parser_info = {
	.name = "quota_status",
	.plugin_dependency = "lib10_quota_plugin",

	.defines = quota_status_setting_defines,
	.defaults = &quota_status_default_settings,

	.struct_size = sizeof(struct quota_status_settings),
	.pool_offset1 = 1 + offsetof(struct quota_status_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/quota/quota-status.c */
extern const struct setting_parser_info quota_status_result_setting_parser_info;
struct quota_status_result_settings {
	pool_t pool;

	const char *quota_status_success;
	const char *quota_status_toolarge;
	const char *quota_status_overquota;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct quota_status_result_settings)
static const struct setting_define quota_status_result_setting_defines[] = {
	DEF(STR, quota_status_success),
	DEF(STR, quota_status_toolarge),
	DEF(STR, quota_status_overquota),

	SETTING_DEFINE_LIST_END
};
static const struct quota_status_result_settings quota_status_result_default_settings = {
	.quota_status_success = "OK",
	.quota_status_toolarge = "",
	.quota_status_overquota = "554 5.2.2 %{error}",
};
const struct setting_parser_info quota_status_result_setting_parser_info = {
	.name = "quota_status_result",
	.plugin_dependency = "lib10_quota_plugin",
	.defines = quota_status_result_setting_defines,
	.defaults = &quota_status_result_default_settings,
	.struct_size = sizeof(struct quota_status_result_settings),
	.pool_offset1 = 1 + offsetof(struct quota_status_result_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/trash/trash-plugin.c */
extern const struct setting_parser_info trash_setting_parser_info;
struct trash_settings {
	pool_t pool;

	unsigned int trash_priority;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct trash_settings)
static const struct setting_define trash_setting_defines[] = {
	DEF(UINT, trash_priority),

	SETTING_DEFINE_LIST_END
};
static const struct trash_settings trash_default_settings = {
	.trash_priority = 0,
};
const struct setting_parser_info trash_setting_parser_info = {
	.name = "trash",
	.plugin_dependency = "lib11_trash_plugin",

	.defines = trash_setting_defines,
	.defaults = &trash_default_settings,

	.struct_size = sizeof(struct trash_settings),
	.pool_offset1 = 1 + offsetof(struct trash_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/virtual/virtual-settings.c */
extern const struct setting_parser_info virtual_setting_parser_info;
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct virtual_settings)
static const struct setting_define virtual_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "virtual" },
	DEF(UINT, virtual_max_open_mailboxes),

	SETTING_DEFINE_LIST_END
};
static const struct virtual_settings virtual_default_settings = {
	.virtual_max_open_mailboxes = 64,
};
static const struct setting_keyvalue virtual_default_settings_keyvalue[] = {
	{ "virtual/mailbox_subscriptions_filename", ".virtual-subscriptions" },
	{ NULL, NULL }
};
const struct setting_parser_info virtual_setting_parser_info = {
	.name = "virtual",
	.plugin_dependency = "lib20_virtual_plugin",

	.defines = virtual_setting_defines,
	.defaults = &virtual_default_settings,
	.default_settings = virtual_default_settings_keyvalue,

	.struct_size = sizeof(struct virtual_settings),
	.pool_offset1 = 1 + offsetof(struct virtual_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/plugins/welcome/welcome-plugin.c */
extern const struct setting_parser_info welcome_setting_parser_info;
struct welcome_settings {
	pool_t pool;
	bool welcome_wait;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct welcome_settings)
static const struct setting_define welcome_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "welcome",
	  .required_setting = "execute", },
	DEF(BOOL, welcome_wait),

	SETTING_DEFINE_LIST_END
};
static const struct welcome_settings welcome_default_settings = {
	.welcome_wait = FALSE,
};
const struct setting_parser_info welcome_setting_parser_info = {
	.name = "welcome",
	.plugin_dependency = "lib99_welcome_plugin",
	.defines = welcome_setting_defines,
	.defaults = &welcome_default_settings,
	.struct_size = sizeof(struct welcome_settings),
	.pool_offset1 = 1 + offsetof(struct welcome_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/pop3-login/pop3-login-settings.c */
extern const struct setting_parser_info pop3_login_setting_parser_info;
struct service_settings pop3_login_service_settings = {
	.name = "pop3-login",
	.protocol = "pop3",
	.type = "login",
	.executable = "pop3-login",
	.user = "$SET:default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

#ifndef DOVECOT_PRO_EDITION
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,
};
const struct setting_keyvalue pop3_login_service_settings_defaults[] = {
	{ "unix_listener", "srv.pop3-login\\s%{pid}" },

	{ "unix_listener/srv.pop3-login\\s%{pid}/path", "srv.pop3-login/%{pid}" },
	{ "unix_listener/srv.pop3-login\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.pop3-login\\s%{pid}/mode", "0600" },

	{ "inet_listener", "pop3 pop3s" },

	{ "inet_listener/pop3/name", "pop3" },
	{ "inet_listener/pop3/port", "110" },

	{ "inet_listener/pop3s/name", "pop3s" },
	{ "inet_listener/pop3s/port", "995" },
	{ "inet_listener/pop3s/ssl", "yes" },

	{ NULL, NULL }
};
static const struct setting_keyvalue pop3_login_default_settings_keyvalue[] = {
#ifdef DOVECOT_PRO_EDITION
	{ "service/pop3-login/service_process_limit", "%{system:cpu_count}" },
	{ "service/pop3-login/service_process_min_avail", "%{system:cpu_count}" },
#endif
	{ NULL, NULL },
};
static const struct setting_define pop3_login_setting_defines[] = {
	SETTING_DEFINE_LIST_END
};
const struct setting_parser_info pop3_login_setting_parser_info = {
	.name = "pop3_login",

	.defines = pop3_login_setting_defines,
	.default_settings = pop3_login_default_settings_keyvalue,
};
/* /home/gromy/Документы/Development/dovecot-core/src/pop3/pop3-settings.c */
extern const struct setting_parser_info pop3_setting_parser_info;

/* <settings checks> */
struct pop3_client_workaround_list {
	const char *name;
	enum pop3_client_workarounds num;
};

static const struct pop3_client_workaround_list pop3_client_workaround_list[] = {
	{ "outlook-no-nuls", WORKAROUND_OUTLOOK_NO_NULS },
	{ "oe-ns-eoh", WORKAROUND_OE_NS_EOH },
	{ NULL, 0 }
};

static int
pop3_settings_parse_workarounds(struct pop3_settings *set,
				const char **error_r)
{
	enum pop3_client_workarounds client_workarounds = 0;
	const struct pop3_client_workaround_list *list;
	const char *const *str;

	str = settings_boollist_get(&set->pop3_client_workarounds);
	for (; *str != NULL; str++) {
		list = pop3_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("pop3_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool
pop3_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct pop3_settings *set = _set;

	if (pop3_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;
	if (strcmp(set->pop3_delete_type, "default") == 0) {
		if (set->pop3_deleted_flag[0] == '\0')
			set->parsed_delete_type = POP3_DELETE_TYPE_EXPUNGE;
		else
			set->parsed_delete_type = POP3_DELETE_TYPE_FLAG;
	} else if (strcmp(set->pop3_delete_type, "expunge") == 0) {
		set->parsed_delete_type = POP3_DELETE_TYPE_EXPUNGE;
	} else if (strcmp(set->pop3_delete_type, "flag") == 0) {
		if (set->pop3_deleted_flag[0] == '\0') {
			*error_r = "pop3_delete_type=flag, but pop3_deleted_flag not set";
			return FALSE;
		}
		set->parsed_delete_type = POP3_DELETE_TYPE_FLAG;
	} else {
		*error_r = t_strdup_printf("pop3_delete_type: Unknown value '%s'",
					   set->pop3_delete_type);
		return FALSE;
	}

	struct var_expand_program *prog;
	const char *error;
	if (var_expand_program_create(set->pop3_logout_format, &prog, &error) < 0) {
		*error_r = t_strdup_printf("Invalid pop3_logout_format: %s", error);
		return FALSE;
	}
	const char *const *vars = var_expand_program_variables(prog);
	set->parsed_want_uidl_change = str_array_find(vars, "uidl_change");
	var_expand_program_free(&prog);

	return TRUE;
}
/* </settings checks> */
struct service_settings pop3_service_settings = {
	.name = "pop3",
	.protocol = "pop3",
	.type = "",
	.executable = "pop3",
	.user = "",
	.group = "",
	.privileged_group = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1024,
	.client_limit = 1,
#ifdef DOVECOT_PRO_EDITION
	.restart_request_count = 1000,
#else
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue pop3_service_settings_defaults[] = {
	{ "unix_listener", "login\\spop3 srv.pop3\\s%{pid}" },

	{ "unix_listener/login\\spop3/path", "login/pop3" },
	{ "unix_listener/login\\spop3/mode", "0666" },

	{ "unix_listener/srv.pop3\\s%{pid}/path", "srv.pop3/%{pid}" },
	{ "unix_listener/srv.pop3\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.pop3\\s%{pid}/mode", "0600" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct pop3_settings)
static const struct setting_define pop3_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(STR, rawlog_dir),

	DEF(BOOL, pop3_no_flag_updates),
	DEF(BOOL, pop3_enable_last),
	DEF(BOOL, pop3_reuse_xuidl),
	DEF(BOOL, pop3_save_uidl),
	DEF(BOOL, pop3_lock_session),
	DEF(BOOL, pop3_fast_size_lookups),
	DEF(BOOLLIST, pop3_client_workarounds),
	DEF(STR_NOVARS, pop3_logout_format),
	DEF(ENUM, pop3_uidl_duplicates),
	DEF(STR, pop3_deleted_flag),
	DEF(ENUM, pop3_delete_type),

	SETTING_DEFINE_LIST_END
};
static const struct pop3_settings pop3_default_settings = {
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,
	.rawlog_dir = "",

	.pop3_no_flag_updates = FALSE,
	.pop3_enable_last = FALSE,
	.pop3_reuse_xuidl = FALSE,
	.pop3_save_uidl = FALSE,
	.pop3_lock_session = FALSE,
	.pop3_fast_size_lookups = FALSE,
	.pop3_client_workarounds = ARRAY_INIT,
	.pop3_logout_format =
		"top=%{top_count}/%{top_bytes}, "
		"retr=%{retr_count}/%{retr_bytes}, "
		"del=%{deleted_count}/%{deleted_bytes}, "
		"size=%{message_bytes}",
	.pop3_uidl_duplicates = "allow:rename",
	.pop3_deleted_flag = "",
	.pop3_delete_type = "default:expunge:flag"
};
static const struct setting_keyvalue pop3_default_settings_keyvalue[] = {
#ifdef DOVECOT_PRO_EDITION
	{ "service/pop3/process_shutdown_filter", "event=mail_user_session_finished AND rss > 20MB" },
#endif
	{ NULL, NULL },
};
const struct setting_parser_info pop3_setting_parser_info = {
	.name = "pop3",

	.defines = pop3_setting_defines,
	.defaults = &pop3_default_settings,
	.default_settings = pop3_default_settings_keyvalue,

	.struct_size = sizeof(struct pop3_settings),
	.pool_offset1 = 1 + offsetof(struct pop3_settings, pool),
	.check_func = pop3_settings_verify,
};
/* /home/gromy/Документы/Development/dovecot-core/src/stats/event-exporter-transport-file.c */
extern const struct setting_parser_info event_exporter_file_setting_parser_info;
struct event_exporter_file_settings {
	pool_t pool;

	const char *event_exporter_file_path;
	const char *event_exporter_unix_path;
	unsigned int event_exporter_unix_connect_timeout_msecs;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct event_exporter_file_settings)
#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name##_msecs, struct event_exporter_file_settings)
static const struct setting_define event_exporter_file_setting_defines[] = {
	DEF(STR, event_exporter_file_path),
	DEF(STR, event_exporter_unix_path),
	DEF_MSECS(TIME_MSECS, event_exporter_unix_connect_timeout),

	SETTING_DEFINE_LIST_END
};
static const struct event_exporter_file_settings event_exporter_file_default_settings = {
	.event_exporter_file_path = "",
	.event_exporter_unix_path = "",
	.event_exporter_unix_connect_timeout_msecs = 250,
};
const struct setting_parser_info event_exporter_file_setting_parser_info = {
	.name = "event_exporter_file",

	.defines = event_exporter_file_setting_defines,
	.defaults = &event_exporter_file_default_settings,

	.struct_size = sizeof(struct event_exporter_file_settings),
	.pool_offset1 = 1 + offsetof(struct event_exporter_file_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/stats/event-exporter-transport-http-post.c */
extern const struct setting_parser_info event_exporter_http_post_setting_parser_info;
struct event_exporter_http_post_settings {
	pool_t pool;

	const char *event_exporter_http_post_url;
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct event_exporter_http_post_settings)
static const struct setting_define event_exporter_http_post_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "event_exporter_http_post", },
	DEF(STR, event_exporter_http_post_url),

	SETTING_DEFINE_LIST_END
};
static const struct event_exporter_http_post_settings event_exporter_http_post_default_settings = {
	.event_exporter_http_post_url = "",
};
static const struct setting_keyvalue event_exporter_http_post_default_settings_keyvalue[] = {
	{ "event_exporter_http_post/http_client_request_absolute_timeout", "250ms" },
	{ NULL, NULL }
};
const struct setting_parser_info event_exporter_http_post_setting_parser_info = {
	.name = "event_exporter_http_post",

	.defines = event_exporter_http_post_setting_defines,
	.defaults = &event_exporter_http_post_default_settings,
	.default_settings = event_exporter_http_post_default_settings_keyvalue,

	.struct_size = sizeof(struct event_exporter_http_post_settings),
	.pool_offset1 = 1 + offsetof(struct event_exporter_http_post_settings, pool),
};
/* /home/gromy/Документы/Development/dovecot-core/src/stats/stats-settings.c */
extern const struct setting_parser_info stats_exporter_setting_parser_info;
extern const struct setting_parser_info stats_metric_group_by_setting_parser_info;
extern const struct setting_parser_info stats_metric_group_by_method_setting_parser_info;
extern const struct setting_parser_info stats_metric_setting_parser_info;
extern const struct setting_parser_info stats_setting_parser_info;

/* <settings checks> */
#include "event-filter.h"
#include <math.h>
/* </settings checks> */

/* <settings checks> */
static bool stats_exporter_settings_check(void *_set, pool_t pool ATTR_UNUSED,
					  const char **error_r)
{
	struct stats_exporter_settings *set = _set;
	bool time_fmt_required;

	if (set->name[0] == '\0')
		return TRUE;

	/* TODO: The following should be plugable.
	 *
	 * Note: Make sure to mirror any changes to the below code in
	 * stats_exporters_add_set().
	 */
	if (set->format[0] == '\0') {
		*error_r = "Exporter format name can't be empty";
		return FALSE;
	} else if (strcmp(set->format, "none") == 0) {
		time_fmt_required = FALSE;
	} else if (strcmp(set->format, "json") == 0) {
		time_fmt_required = TRUE;
	} else if (strcmp(set->format, "tab-text") == 0) {
		time_fmt_required = TRUE;
	} else {
		*error_r = t_strdup_printf("Unknown exporter format '%s'",
					   set->format);
		return FALSE;
	}

	if (strcmp(set->time_format, "rfc3339") == 0)
		set->parsed_time_format = EVENT_EXPORTER_TIME_FMT_RFC3339;
	else if (strcmp(set->time_format, "unix") == 0)
		set->parsed_time_format = EVENT_EXPORTER_TIME_FMT_UNIX;
	else
		i_unreached();

	/* Some formats don't have a native way of serializing time stamps */
	if (time_fmt_required &&
	    set->parsed_time_format == EVENT_EXPORTER_TIME_FMT_NATIVE) {
		*error_r = t_strdup_printf("%s exporter format requires a "
					   "time-* argument", set->format);
		return FALSE;
	}

	return TRUE;
}

#ifdef CONFIG_BINARY
void metrics_group_by_exponential_init(struct stats_metric_settings_group_by *group_by,
				       pool_t pool, unsigned int base,
				       unsigned int min, unsigned int max);
void metrics_group_by_linear_init(struct stats_metric_settings_group_by *group_by,
				  pool_t pool, uint64_t min, uint64_t max,
				  uint64_t step);
#endif

void metrics_group_by_exponential_init(struct stats_metric_settings_group_by *group_by,
				       pool_t pool, unsigned int base,
				       unsigned int min, unsigned int max)
{
	group_by->func = STATS_METRIC_GROUPBY_QUANTIZED;
	/*
	 * Allocate the bucket range array and fill it in
	 *
	 * The first bucket is special - it contains everything less than or
	 * equal to 'base^min'.  The last bucket is also special - it
	 * contains everything greater than 'base^max'.
	 *
	 * The second bucket begins at 'base^min + 1', the third bucket
	 * begins at 'base^(min + 1) + 1', and so on.
	 */
	group_by->num_ranges = max - min + 2;
	group_by->ranges = p_new(pool, struct stats_metric_settings_bucket_range,
				 group_by->num_ranges);

	/* set up min & max buckets */
	group_by->ranges[0].min = INTMAX_MIN;
	group_by->ranges[0].max = pow(base, min);
	group_by->ranges[group_by->num_ranges - 1].min = pow(base, max);
	group_by->ranges[group_by->num_ranges - 1].max = INTMAX_MAX;

	/* remaining buckets */
	for (unsigned int i = 1; i < group_by->num_ranges - 1; i++) {
		group_by->ranges[i].min = pow(base, min + (i - 1));
		group_by->ranges[i].max = pow(base, min + i);
	}
}

void metrics_group_by_linear_init(struct stats_metric_settings_group_by *group_by,
				  pool_t pool, uint64_t min, uint64_t max,
				  uint64_t step)
{
	group_by->func = STATS_METRIC_GROUPBY_QUANTIZED;
	/*
	 * Allocate the bucket range array and fill it in
	 *
	 * The first bucket is special - it contains everything less than or
	 * equal to 'min'.  The last bucket is also special - it contains
	 * everything greater than 'max'.
	 *
	 * The second bucket begins at 'min + 1', the third bucket begins at
	 * 'min + 1 * step + 1', the fourth at 'min + 2 * step + 1', and so on.
	 */
	i_assert(step > 0);
	group_by->num_ranges = (max - min) / step + 2;
	group_by->ranges = p_new(pool, struct stats_metric_settings_bucket_range,
				 group_by->num_ranges);

	/* set up min & max buckets */
	group_by->ranges[0].min = INTMAX_MIN;
	group_by->ranges[0].max = min;
	group_by->ranges[group_by->num_ranges - 1].min = max;
	group_by->ranges[group_by->num_ranges - 1].max = INTMAX_MAX;

	/* remaining buckets */
	for (unsigned int i = 1; i < group_by->num_ranges - 1; i++) {
		group_by->ranges[i].min = min + (i - 1) * step;
		group_by->ranges[i].max = min + i * step;
	}
}
/* </settings checks> */

/* <settings checks> */
static bool stats_metric_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct stats_metric_settings *set = _set;

	if (set->name[0] == '\0')
		return TRUE;

	if (set->filter[0] == '\0') {
		*error_r = t_strdup_printf("metric %s { filter } is empty - "
					   "will not match anything", set->name);
		return FALSE;
	}

	set->parsed_filter = event_filter_create_fragment(pool);
	if (event_filter_parse(set->filter, set->parsed_filter, error_r) < 0)
		return FALSE;

	return TRUE;
}

static bool
stats_settings_ext_check(struct event *event, void *_set,
			 pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct stats_settings *set = _set;
	const struct stats_exporter_settings *exporter;
	struct stats_metric_settings *metric;
	const char *metric_name, *error;
	int ret;

	if (!array_is_created(&set->metrics))
		return TRUE;

	/* check that all metrics refer to exporters that exist */
	array_foreach_elem(&set->metrics, metric_name) {
		if (settings_get_filter(event, "metric", metric_name,
					&stats_metric_setting_parser_info,
					SETTINGS_GET_FLAG_NO_CHECK |
					SETTINGS_GET_FLAG_NO_EXPAND,
					&metric, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get metric %s: %s",
				metric_name, error);
			return FALSE;
		}

		const char *metric_exporter = t_strdup(metric->exporter);
		settings_free(metric);

		if (metric_exporter[0] == '\0')
			continue; /* metric not exported */

		ret = settings_try_get_filter(event, "event_exporter",
					      metric_exporter,
					      &stats_exporter_setting_parser_info,
					      SETTINGS_GET_FLAG_NO_CHECK |
					      SETTINGS_GET_FLAG_NO_EXPAND,
					      &exporter, &error);
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"Failed to get event_exporter %s: %s",
				metric_exporter, error);
			return FALSE;
		}
		if (ret == 0) {
			*error_r = t_strdup_printf("metric %s refers to "
						   "non-existent exporter '%s'",
						   metric_name,
						   metric_exporter);
			return FALSE;
		}
		settings_free(exporter);
	}

	return TRUE;
}

/* </settings checks> */
struct service_settings stats_service_settings = {
	.name = "stats",
	.protocol = "",
	.type = "",
	.executable = "stats",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1,
	.idle_kill_interval = SET_TIME_INFINITE,

	.unix_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,
};
const struct setting_keyvalue stats_service_settings_defaults[] = {
	{ "unix_listener", "login\\sstats-writer stats-reader stats-writer" },

	{ "unix_listener/login\\sstats-writer/path", "login/stats-writer" },
	{ "unix_listener/login\\sstats-writer/type", "writer" },
	{ "unix_listener/login\\sstats-writer/mode", "0600" },
	{ "unix_listener/login\\sstats-writer/user", "$SET:default_login_user" },

	{ "unix_listener/stats-reader/path", "stats-reader" },
	{ "unix_listener/stats-reader/type", "reader" },
	{ "unix_listener/stats-reader/mode", "0600" },

	{ "unix_listener/stats-writer/path", "stats-writer" },
	{ "unix_listener/stats-writer/type", "writer" },
	{ "unix_listener/stats-writer/mode", "0660" },
	{ "unix_listener/stats-writer/group", "$SET:default_internal_group" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("event_exporter_"#name, name, struct stats_exporter_settings)
static const struct setting_define stats_exporter_setting_defines[] = {
	DEF(STR, name),
	DEF(ENUM, driver),
	DEF(STR, format),
	DEF(ENUM, time_format),
	SETTING_DEFINE_LIST_END
};
static const struct stats_exporter_settings stats_exporter_default_settings = {
	.name = "",
	.driver = "log:file:unix:http-post:drop",
	.format = "",
	.time_format = "rfc3339:unix",
};
const struct setting_parser_info stats_exporter_setting_parser_info = {
	.name = "stats_exporter",

	.defines = stats_exporter_setting_defines,
	.defaults = &stats_exporter_default_settings,

	.struct_size = sizeof(struct stats_exporter_settings),
	.pool_offset1 = 1 + offsetof(struct stats_exporter_settings, pool),
	.check_func = stats_exporter_settings_check,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("metric_group_by_"#name, name, struct stats_metric_group_by_settings)
static const struct setting_define stats_metric_group_by_setting_defines[] = {
	DEF(STR, field),

	{ .type = SET_FILTER_ARRAY, .key = "metric_group_by_method",
	  .offset = offsetof(struct stats_metric_group_by_settings, method),
	  .filter_array_field_name = "metric_group_by_method_method", },

	SETTING_DEFINE_LIST_END
};
static const struct stats_metric_group_by_settings stats_metric_group_by_default_settings = {
	.field = "",
	.method = ARRAY_INIT,
};
const struct setting_parser_info stats_metric_group_by_setting_parser_info = {
	.name = "stats_metric_group_by",

	.defines = stats_metric_group_by_setting_defines,
	.defaults = &stats_metric_group_by_default_settings,

	.struct_size = sizeof(struct stats_metric_group_by_settings),
	.pool_offset1 = 1 + offsetof(struct stats_metric_group_by_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("metric_group_by_method_"#name, name, struct stats_metric_group_by_method_settings)
static const struct setting_define stats_metric_group_by_method_setting_defines[] = {
	DEF(ENUM, method),
	DEF(STR_NOVARS, discrete_modifier),
	DEF(UINT, exponential_min_magnitude),
	DEF(UINT, exponential_max_magnitude),
	DEF(UINT, exponential_base),
	DEF(UINTMAX, linear_min),
	DEF(UINTMAX, linear_max),
	DEF(UINTMAX, linear_step),

	SETTING_DEFINE_LIST_END
};
static const struct stats_metric_group_by_method_settings stats_metric_group_by_method_default_settings = {
	.method = "discrete:exponential:linear",
	.discrete_modifier = "",
	.exponential_min_magnitude = 0,
	.exponential_max_magnitude = 0,
	.exponential_base = 10,
	.linear_min = 0,
	.linear_max = 0,
	.linear_step = 0,
};
const struct setting_parser_info stats_metric_group_by_method_setting_parser_info = {
	.name = "stats_metric_group_by_",

	.defines = stats_metric_group_by_method_setting_defines,
	.defaults = &stats_metric_group_by_method_default_settings,

	.struct_size = sizeof(struct stats_metric_group_by_method_settings),
	.pool_offset1 = 1 + offsetof(struct stats_metric_group_by_method_settings, pool),
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("metric_"#name, name, struct stats_metric_settings)
static const struct setting_define stats_metric_setting_defines[] = {
	DEF(STR, name),
	DEF(BOOLLIST, fields),
	DEF(STR, filter),
	DEF(STR, exporter),
	DEF(BOOLLIST, exporter_include),
	DEF(STR, description),

	{ .type = SET_FILTER_ARRAY, .key = "metric_group_by",
	  .offset = offsetof(struct stats_metric_settings, group_by),
	  .filter_array_field_name = "metric_group_by_field", },

	SETTING_DEFINE_LIST_END
};
const struct stats_metric_settings stats_metric_default_settings = {
	.name = "",
	.fields = ARRAY_INIT,
	.filter = "",
	.exporter = "",
	.group_by = ARRAY_INIT,
	.description = "",
};
static const struct setting_keyvalue stats_metric_default_settings_keyvalue[] = {
	{ "metric_exporter_include", STATS_METRIC_SETTINGS_DEFAULT_EXPORTER_INCLUDE },
	{ NULL, NULL }
};
const struct setting_parser_info stats_metric_setting_parser_info = {
	.name = "stats_metric",

	.defines = stats_metric_setting_defines,
	.defaults = &stats_metric_default_settings,
	.default_settings = stats_metric_default_settings_keyvalue,

	.struct_size = sizeof(struct stats_metric_settings),
	.pool_offset1 = 1 + offsetof(struct stats_metric_settings, pool),
	.check_func = stats_metric_settings_check,
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct stats_settings)
static const struct setting_define stats_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = STATS_SERVER_FILTER },
	{ .type = SET_FILTER_ARRAY, .key = "metric",
	  .offset = offsetof(struct stats_settings, metrics),
	  .filter_array_field_name = "metric_name",
	  .required_setting = "metric_filter", },
	{ .type = SET_FILTER_ARRAY, .key = "event_exporter",
	  .offset = offsetof(struct stats_settings, exporters),
	  .filter_array_field_name = "event_exporter_name", },
	SETTING_DEFINE_LIST_END
};
const struct stats_settings stats_default_settings = {
	.metrics = ARRAY_INIT,
	.exporters = ARRAY_INIT,
};
const struct setting_parser_info stats_setting_parser_info = {
	.name = "stats",

	.defines = stats_setting_defines,
	.defaults = &stats_default_settings,

	.struct_size = sizeof(struct stats_settings),
	.pool_offset1 = 1 + offsetof(struct stats_settings, pool),
	.ext_check_func = stats_settings_ext_check,
};
/* /home/gromy/Документы/Development/dovecot-core/src/submission-login/submission-login-settings.c */
extern const struct setting_parser_info submission_login_setting_parser_info;

/* <settings checks> */
struct submission_login_client_workaround_list {
	const char *name;
	enum submission_login_client_workarounds num;
};

/* These definitions need to be kept in sync with equivalent definitions present
   in src/submission/submission-settings.c. Workarounds that are not relevant
   to the submission-login service are defined as 0 here to prevent "Unknown
   workaround" errors below. */
static const struct submission_login_client_workaround_list
submission_login_client_workaround_list[] = {
	{ "whitespace-before-path", 0},
	{ "mailbox-for-path", 0 },
	{ "implicit-auth-external",
	  SUBMISSION_LOGIN_WORKAROUND_IMPLICIT_AUTH_EXTERNAL },
	{ "exotic-backend",
	  SUBMISSION_LOGIN_WORKAROUND_EXOTIC_BACKEND },
	{ NULL, 0 }
};

static int
submission_login_settings_parse_workarounds(
	struct submission_login_settings *set, const char **error_r)
{
	enum submission_login_client_workarounds client_workarounds = 0;
	const struct submission_login_client_workaround_list *list;
	const char *const *str;

	str = settings_boollist_get(&set->submission_client_workarounds);
	for (; *str != NULL; str++) {
		list = submission_login_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf(
				"submission_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool
submission_login_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				const char **error_r)
{
	struct submission_login_settings *set = _set;

#ifndef EXPERIMENTAL_MAIL_UTF8
	if (set->mail_utf8_extensions) {
		*error_r = "Dovecot not built with --enable-experimental-mail-utf8";
		return FALSE;
	}
#endif
	if (submission_login_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

#ifndef CONFIG_BINARY
	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
#endif
	return TRUE;
}
/* </settings checks> */
struct service_settings submission_login_service_settings = {
	.name = "submission-login",
	.protocol = "submission",
	.type = "login",
	.executable = "submission-login",
	.user = "$SET:default_login_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "login",

	.drop_priv_before_exec = FALSE,

#ifndef DOVECOT_PRO_EDITION
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,
};
const struct setting_keyvalue submission_login_service_settings_defaults[] = {
	{ "unix_listener", "srv.submission-login\\s%{pid}" },

	{ "unix_listener/srv.submission-login\\s%{pid}/path", "srv.submission-login/%{pid}" },
	{ "unix_listener/srv.submission-login\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.submission-login\\s%{pid}/mode", "0600" },

	{ "inet_listener", "submission submissions" },

	{ "inet_listener/submission/name", "submission" },
	{ "inet_listener/submission/port", "587" },

	{ "inet_listener/submissions/name", "submissions" },
	{ "inet_listener/submissions/port", "465" },
	{ "inet_listener/submissions/ssl", "yes" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct submission_login_settings)
static const struct setting_define submission_login_setting_defines[] = {
	DEF(STR, hostname),
	DEF(BOOL, mail_utf8_extensions),

	DEF(SIZE, submission_max_mail_size),
	DEF(BOOLLIST, submission_client_workarounds),
	DEF(BOOLLIST, submission_backend_capabilities),

	SETTING_DEFINE_LIST_END
};
static const struct submission_login_settings submission_login_default_settings = {
	.hostname = "",
	.mail_utf8_extensions = FALSE,

	.submission_max_mail_size = 0,
	.submission_client_workarounds = ARRAY_INIT,
	.submission_backend_capabilities = ARRAY_INIT,
};
static const struct setting_keyvalue submission_login_default_settings_keyvalue[] = {
#ifdef DOVECOT_PRO_EDITION
	{ "service/submission-login/service_process_limit", "%{system:cpu_count}" },
	{ "service/submission-login/service_process_min_avail", "%{system:cpu_count}" },
#endif
	{ NULL, NULL },
};
const struct setting_parser_info submission_login_setting_parser_info = {
	.name = "submission_login",

	.defines = submission_login_setting_defines,
	.defaults = &submission_login_default_settings,
	.default_settings = submission_login_default_settings_keyvalue,

	.struct_size = sizeof(struct submission_login_settings),
	.pool_offset1 = 1 + offsetof(struct submission_login_settings, pool),
	.check_func = submission_login_settings_check,
};
/* /home/gromy/Документы/Development/dovecot-core/src/submission/submission-settings.c */
extern const struct setting_parser_info submission_setting_parser_info;

/* <settings checks> */
struct submission_client_workaround_list {
	const char *name;
	enum submission_client_workarounds num;
};

/* These definitions need to be kept in sync with equivalent definitions present
   in src/submission-login/submission-login-settings.c. Workarounds that are not
   relevant to the submission service are defined as 0 here to prevent "Unknown
   workaround" errors below. */
static const struct submission_client_workaround_list
submission_client_workaround_list[] = {
	{ "whitespace-before-path",
	  SUBMISSION_WORKAROUND_WHITESPACE_BEFORE_PATH },
	{ "mailbox-for-path",
	  SUBMISSION_WORKAROUND_MAILBOX_FOR_PATH },
	{ "implicit-auth-external", 0 },
	{ "exotic-backend", 0 },
	{ NULL, 0 }
};

static int
submission_settings_parse_workarounds(struct submission_settings *set,
				const char **error_r)
{
	enum submission_client_workarounds client_workarounds = 0;
	const struct submission_client_workaround_list *list;
	const char *const *str;

	str = settings_boollist_get(&set->submission_client_workarounds);
	for (; *str != NULL; str++) {
		list = submission_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf(
				"submission_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool
submission_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct submission_settings *set = _set;

#ifndef EXPERIMENTAL_MAIL_UTF8
	if (set->mail_utf8_extensions) {
		*error_r = "Dovecot not built with --enable-experimental-mail-utf8";
		return FALSE;
	}
#endif

	if (submission_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

#ifndef CONFIG_BINARY
	if (set->submission_relay_max_idle_time == 0) {
		*error_r = "submission_relay_max_idle_time must not be 0";
		return FALSE;
	}
	if (*set->hostname == '\0')
		set->hostname = p_strdup(pool, my_hostdomain());
#endif
	return TRUE;
}
/* </settings checks> */
struct service_settings submission_service_settings = {
	.name = "submission",
	.protocol = "submission",
	.type = "",
	.executable = "submission",
	.user = "",
	.group = "",
	.privileged_group = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1024,
	.client_limit = 1,
#ifdef DOVECOT_PRO_EDITION
	.restart_request_count = 1000,
#else
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
const struct setting_keyvalue submission_service_settings_defaults[] = {
	{ "unix_listener", "login\\ssubmission srv.submission\\s%{pid}" },

	{ "unix_listener/login\\ssubmission/path", "login/submission" },
	{ "unix_listener/login\\ssubmission/mode", "0666" },

	{ "unix_listener/srv.submission\\s%{pid}/path", "srv.submission/%{pid}" },
	{ "unix_listener/srv.submission\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.submission\\s%{pid}/mode", "0600" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct submission_settings)
static const struct setting_define submission_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(STR, rawlog_dir),

	DEF(STR, hostname),

	DEF(STR_HIDDEN, login_greeting),
	DEF(BOOLLIST, login_trusted_networks),

	DEF(STR, recipient_delimiter),

	DEF(SIZE, submission_max_mail_size),
	DEF(UINT, submission_max_recipients),
	DEF(BOOLLIST, submission_client_workarounds),
	DEF(STR_NOVARS, submission_logout_format),
	DEF(BOOL, submission_add_received_header),
	DEF(BOOL, mail_utf8_extensions),

	DEF(BOOLLIST, submission_backend_capabilities),

	DEF(STR, submission_relay_host),
	DEF(IN_PORT, submission_relay_port),
	DEF(BOOL, submission_relay_trusted),

	DEF(STR, submission_relay_user),
	DEF(STR, submission_relay_master_user),
	DEF(STR, submission_relay_password),

	DEF(ENUM, submission_relay_ssl),
	DEF(BOOL, submission_relay_ssl_verify),

	DEF(STR, submission_relay_rawlog_dir),
	DEF(TIME, submission_relay_max_idle_time),

	DEF(TIME_MSECS, submission_relay_connect_timeout),
	DEF(TIME_MSECS, submission_relay_command_timeout),

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	SETTING_DEFINE_LIST_END
};
static const struct submission_settings submission_default_settings = {
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,
	.rawlog_dir = "",

	.hostname = "",

	.login_greeting = PACKAGE_NAME" ready.",
	.login_trusted_networks = ARRAY_INIT,

	.recipient_delimiter = "+",

	.submission_max_mail_size = 40*1024*1024,
	.submission_max_recipients = 0,
	.submission_client_workarounds = ARRAY_INIT,
	.submission_logout_format = "in=%{input} out=%{output}",
	.submission_add_received_header = TRUE,
	.mail_utf8_extensions = FALSE,

	.submission_backend_capabilities = ARRAY_INIT,

	.submission_relay_host = "",
	.submission_relay_port = 25,
	.submission_relay_trusted = FALSE,

	.submission_relay_user = "",
	.submission_relay_master_user = "",
	.submission_relay_password = "",

	.submission_relay_ssl = "no:smtps:starttls",
	.submission_relay_ssl_verify = TRUE,

	.submission_relay_rawlog_dir = "",
	.submission_relay_max_idle_time = 60*29,

	.submission_relay_connect_timeout = 30*1000,
	.submission_relay_command_timeout = 60*5*1000,

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143,
};
static const struct setting_keyvalue submission_default_settings_keyvalue[] = {
#ifdef DOVECOT_PRO_EDITION
	{ "service/submission/process_shutdown_filter", "event=mail_user_session_finished AND rss > 20MB" },
#endif
	{ NULL, NULL },
};
const struct setting_parser_info submission_setting_parser_info = {
	.name = "submission",

	.defines = submission_setting_defines,
	.defaults = &submission_default_settings,
	.default_settings = submission_default_settings_keyvalue,

	.struct_size = sizeof(struct submission_settings),
	.pool_offset1 = 1 + offsetof(struct submission_settings, pool),
	.check_func = submission_settings_verify,
};
/* /home/gromy/Документы/Development/dovecot-core/src/util/health-check-settings.c */
struct service_settings health_check_service_settings = {
	.name = "health-check",
	.protocol = "",
	.type = "",
	.executable = "script -p health-check.sh",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = TRUE,

	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict-extra/dict-client.c */
extern const struct setting_parser_info dict_proxy_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict/dict-file.c */
extern const struct setting_parser_info dict_file_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict/dict-redis.c */
extern const struct setting_parser_info redis_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dict/dict.c */
extern const struct setting_parser_info dict_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-dns-client/dns-client-settings.c */
extern const struct setting_parser_info dns_client_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-fs/fs-api.c */
extern const struct setting_parser_info fs_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-fs/fs-dict.c */
extern const struct setting_parser_info fs_dict_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-fs/fs-posix.c */
extern const struct setting_parser_info fs_posix_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-fs/fs-randomfail.c */
extern const struct setting_parser_info fs_randomfail_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-fs/fs-sis-queue.c */
extern const struct setting_parser_info fs_sis_queue_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-http/http-client-settings.c */
extern const struct setting_parser_info http_client_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-http/http-server-settings.c */
extern const struct setting_parser_info http_server_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-master/master-service-settings.c */
extern const struct setting_parser_info master_service_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-program-client/program-client.c */
extern const struct setting_parser_info program_client_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-smtp/smtp-submit-settings.c */
extern const struct setting_parser_info smtp_submit_setting_parser_info;
/* /home/gromy/Документы/Development/dovecot-core/src/lib-ssl-iostream/ssl-settings.c */
extern const struct setting_parser_info ssl_setting_parser_info;
extern const struct setting_parser_info ssl_server_setting_parser_info;
static const struct config_service config_default_services[] = {
	{ &anvil_service_settings, anvil_service_settings_defaults },
	{ &auth_service_settings, auth_service_settings_defaults },
	{ &auth_worker_service_settings, auth_worker_service_settings_defaults },
	{ &config_service_settings, config_service_settings_defaults },
	{ &dict_service_settings, dict_service_settings_defaults },
	{ &dict_async_service_settings, dict_async_service_settings_defaults },
	{ &dict_expire_service_settings, NULL },
	{ &dns_client_service_settings, dns_client_service_settings_defaults },
	{ &doveadm_service_settings, doveadm_service_settings_defaults },
	{ &health_check_service_settings, NULL },
	{ &imap_service_settings, imap_service_settings_defaults },
	{ &imap_hibernate_service_settings, imap_hibernate_service_settings_defaults },
	{ &imap_login_service_settings, imap_login_service_settings_defaults },
	{ &imap_urlauth_service_settings, imap_urlauth_service_settings_defaults },
	{ &imap_urlauth_login_service_settings, imap_urlauth_login_service_settings_defaults },
	{ &imap_urlauth_worker_service_settings, imap_urlauth_worker_service_settings_defaults },
	{ &indexer_service_settings, indexer_service_settings_defaults },
	{ &indexer_worker_service_settings, indexer_worker_service_settings_defaults },
	{ &lmtp_service_settings, lmtp_service_settings_defaults },
	{ &log_service_settings, log_service_settings_defaults },
	{ &pop3_service_settings, pop3_service_settings_defaults },
	{ &pop3_login_service_settings, pop3_login_service_settings_defaults },
	{ &stats_service_settings, stats_service_settings_defaults },
	{ &submission_service_settings, submission_service_settings_defaults },
	{ &submission_login_service_settings, submission_login_service_settings_defaults },
	{ NULL, NULL }
};
const struct setting_parser_info *all_default_infos[] = {

	&acl_rights_setting_parser_info,

	&acl_setting_parser_info,

	&apparmor_setting_parser_info,
#if defined(BUILTIN_LUA) || defined(PLUGIN_BUILD)
	&auth_lua_setting_parser_info,
#endif

	&auth_oauth2_post_setting_parser_info,

	&auth_oauth2_setting_parser_info,
#ifdef PASSDB_PAM
	&auth_pam_setting_parser_info,
#endif

	&auth_passdb_post_setting_parser_info,

	&auth_passdb_setting_parser_info,
#ifdef PASSDB_PASSWD
	&auth_passwd_info,
#endif

	&auth_policy_request_setting_parser_info,

	&auth_setting_parser_info,

	&auth_static_setting_parser_info,

	&auth_userdb_post_setting_parser_info,

	&auth_userdb_setting_parser_info,
#ifdef HAVE_BZLIB
	&bzlib_setting_parser_info,
#endif
#ifdef BUILD_CASSANDRA
	&cassandra_setting_parser_info,
#endif
#ifdef BUILD_CDB
	&cdb_setting_parser_info,
#endif

	&charset_alias_setting_parser_info,

	&crypt_acl_setting_parser_info,

	&crypt_private_key_setting_parser_info,

	&crypt_setting_parser_info,

	&dict_file_setting_parser_info,
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
	&dict_ldap_map_post_setting_parser_info,
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
	&dict_ldap_map_pre_setting_parser_info,
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
	&dict_ldap_map_setting_parser_info,
#endif
#if defined(HAVE_LDAP) && (defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD))
	&dict_ldap_setting_parser_info,
#endif

	&dict_map_key_field_setting_parser_info,

	&dict_map_setting_parser_info,

	&dict_map_value_field_setting_parser_info,

	&dict_proxy_setting_parser_info,

	&dict_server_setting_parser_info,

	&dict_setting_parser_info,

	&dlua_setting_parser_info,

	&dns_client_setting_parser_info,

	&doveadm_setting_parser_info,

	&event_exporter_file_setting_parser_info,

	&event_exporter_http_post_setting_parser_info,

	&fifo_listener_setting_parser_info,

	&fs_compress_setting_parser_info,

	&fs_dict_setting_parser_info,

	&fs_posix_setting_parser_info,

	&fs_randomfail_setting_parser_info,

	&fs_setting_parser_info,

	&fs_sis_queue_setting_parser_info,

	&fts_flatcurve_setting_parser_info,

	&fts_setting_parser_info,

	&fts_solr_setting_parser_info,

	&http_client_setting_parser_info,

	&http_server_setting_parser_info,

	&imap_acl_setting_parser_info,

	&imap_login_setting_parser_info,

	&imap_setting_parser_info,

	&imap_urlauth_login_setting_parser_info,

	&imap_urlauth_setting_parser_info,

	&imap_urlauth_worker_setting_parser_info,

	&imapc_setting_parser_info,

	&inet_listener_setting_parser_info,

	&lang_setting_parser_info,

	&langs_setting_parser_info,

	&last_login_setting_parser_info,

	&lazy_expunge_setting_parser_info,

	&lda_setting_parser_info,

	&ldap_client_setting_parser_info,
#ifdef HAVE_LDAP
	&ldap_post_setting_parser_info,
#endif
#ifdef HAVE_LDAP
	&ldap_pre_setting_parser_info,
#endif
#ifdef HAVE_LDAP
	&ldap_setting_parser_info,
#endif

	&lmtp_pre_mail_setting_parser_info,

	&lmtp_setting_parser_info,

	&login_setting_parser_info,

	&mail_compress_setting_parser_info,

	&mail_driver_setting_parser_info,

	&mail_log_setting_parser_info,

	&mail_lua_setting_parser_info,

	&mail_namespace_setting_parser_info,

	&mail_storage_setting_parser_info,

	&mail_user_setting_parser_info,

	&mailbox_list_layout_setting_parser_info,

	&mailbox_setting_parser_info,

	&maildir_setting_parser_info,

	&master_service_setting_parser_info,

	&master_setting_parser_info,

	&mbox_setting_parser_info,

	&mdbox_setting_parser_info,
#ifdef BUILD_MYSQL
	&mysql_setting_parser_info,
#endif

	&notify_status_plugin_setting_parser_info,
#ifdef PASSDB_BSDAUTH
	&passdb_bsdauth_setting_parser_info,
#endif

	&passdb_imap_setting_parser_info,
#ifdef PASSDB_SQL
	&passdb_sql_setting_parser_info,
#endif
#if defined (USERDB_PASSWD_FILE) || defined(PASSDB_PASSWD_FILE)
	&passwd_file_setting_parser_info,
#endif
#ifdef BUILD_PGSQL
	&pgsql_setting_parser_info,
#endif

	&pop3_login_setting_parser_info,

	&pop3_migration_setting_parser_info,

	&pop3_setting_parser_info,

	&pop3c_setting_parser_info,

	&program_client_setting_parser_info,

	&push_notification_ox_setting_parser_info,

	&push_notification_setting_parser_info,

	&quota_clone_setting_parser_info,

	&quota_fs_setting_parser_info,

	&quota_imapc_setting_parser_info,

	&quota_root_setting_parser_info,

	&quota_setting_parser_info,

	&quota_status_result_setting_parser_info,

	&quota_status_setting_parser_info,

	&redis_setting_parser_info,

	&sdbox_setting_parser_info,

	&service_setting_parser_info,

	&smtp_submit_setting_parser_info,

	&sql_setting_parser_info,
#ifdef BUILD_SQLITE
	&sqlite_setting_parser_info,
#endif

	&ssl_server_setting_parser_info,

	&ssl_setting_parser_info,

	&stats_exporter_setting_parser_info,

	&stats_metric_group_by_method_setting_parser_info,

	&stats_metric_group_by_setting_parser_info,

	&stats_metric_setting_parser_info,

	&stats_setting_parser_info,

	&submission_login_setting_parser_info,

	&submission_setting_parser_info,

	&trash_setting_parser_info,

	&unix_listener_setting_parser_info,
#ifdef USERDB_SQL
	&userdb_sql_setting_parser_info,
#endif

	&virtual_setting_parser_info,

	&welcome_setting_parser_info,

	&zlib_setting_parser_info,
#ifdef HAVE_ZSTD
	&zstd_setting_parser_info,
#endif
	NULL
};
const struct setting_parser_info *const *all_infos = all_default_infos;
const struct config_service *config_all_services = config_default_services;
