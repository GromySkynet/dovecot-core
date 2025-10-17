/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define if you have buggy CMSG macros */
/* #undef BUGGY_CMSG_MACROS */

/* Built-in Cassandra support */
/* #undef BUILD_CASSANDRA */

/* Build with CDB support */
/* #undef BUILD_CDB */

/* Build with imap hibernate */
#define BUILD_IMAP_HIBERNATE /**/

/* Built-in MySQL support */
/* #undef BUILD_MYSQL */

/* Built-in PostgreSQL support */
#define BUILD_PGSQL /**/

/* Built-in SQLite support */
/* #undef BUILD_SQLITE */

/* GSSAPI support is built in */
/* #undef BUILTIN_GSSAPI */

/* LDAP support is built in */
/* #undef BUILTIN_LDAP */

/* Lua support is builtin */
/* #undef BUILTIN_LUA */

/* Define if _XPG6 macro is needed for crypt() */
#define CRYPT_USE_XPG6 /**/

/* Build with extra debugging checks */
/* #undef DEBUG */

/* Path to random source */
#define DEV_URANDOM_PATH "/dev/urandom"

/* Disable asserts */
/* #undef DISABLE_ASSERTS */

/* Lua scripts will be able to yield */
#define DLUA_WITH_YIELDS /**/

/* Dovecot ABI version */
#define DOVECOT_ABI_VERSION "2.4.ABIv1"

/* Dovecot configuration version */
#define DOVECOT_CONFIG_VERSION "2.4.1"

/* Documentation URL */
#define DOVECOT_DOC_URL "https://doc.dovecot.org/"

/* Dovecot edition */
/* #undef DOVECOT_EDITION */

/* Dovecot name */
#define DOVECOT_NAME "Dovecot"

/* Define this if you want Dovecot Pro defaults */
/* #undef DOVECOT_PRO_EDITION */

/* Dovecot string */
#define DOVECOT_STRING "Dovecot 2.4.1"

/* Dovecot version */
#define DOVECOT_VERSION "2.4.1"

/* Dovecot major version */
#define DOVECOT_VERSION_MAJOR 2

/* Dovecot micro version */
#define DOVECOT_VERSION_MICRO 1

/* Dovecot minor version */
#define DOVECOT_VERSION_MINOR 4

/* Build with IMAP4REV2 support */
/* #undef EXPERIMENTAL_IMAP4REV2 */

/* Build with SMTPUTF8 and UTF8=ACCEPT support */
#define EXPERIMENTAL_MAIL_UTF8 /**/

/* Define to nothing if C supports flexible array members, and to 1 if it does
   not. That way, with a declaration like `struct s { int n; double
   d[FLEXIBLE_ARRAY_MEMBER]; };', the struct hack can be used with pre-C99
   compilers. When computing the size of such an object, don't use 'sizeof
   (struct s)' as it overestimates the size. Use 'offsetof (struct s, d)'
   instead. Don't use 'offsetof (struct s, d[0])', as this doesn't work with
   MSVC and with C++ compilers. */
#define FLEXIBLE_ARRAY_MEMBER /**/

/* Define this if you have arc4random_buf() */
#define HAVE_ARC4RANDOM 1

/* define if you have nonstring attribute */
#define HAVE_ATTR_NONSTRING /**/

/* Define to 1 if you have the `backtrace_symbols' function. */
#define HAVE_BACKTRACE_SYMBOLS 1

/* Define if you have bzlib library */
#define HAVE_BZLIB /**/

/* Build with Cassandra support */
/* #undef HAVE_CASSANDRA */

/* Cassandra supports speculative execution policy */
/* #undef HAVE_CASSANDRA_SPECULATIVE_POLICY */

/* Define to 1 if you have the `clearenv' function. */
#define HAVE_CLEARENV 1

/* Define to 1 if you have the `cpuset_getaffinity' function. */
/* #undef HAVE_CPUSET_GETAFFINITY */

/* Define to 1 if you have the <crypt.h> header file. */
#define HAVE_CRYPT_H 1

/* Define to 1 if you have the declaration of `getrandom', and to 0 if you
   don't. */
#define HAVE_DECL_GETRANDOM 1

/* Define to 1 if you have the declaration of
   `ZSTD_error_parameter_unsupported', and to 0 if you don't. */
#define HAVE_DECL_ZSTD_ERROR_PARAMETER_UNSUPPORTED 1

/* Define to 1 if you have the declaration of `ZSTD_minCLevel', and to 0 if
   you don't. */
#define HAVE_DECL_ZSTD_MINCLEVEL 0

/* Define if you have struct dirent->d_type */
#define HAVE_DIRENT_D_TYPE /**/

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the `dirfd' function. */
#define HAVE_DIRFD 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define if you have ENGINE_by_id */
/* #undef HAVE_ENGINE_by_id */

/* Define if you have ERR_get_error_all */
#define HAVE_ERR_get_error_all /**/

/* Define if you have EVP_MAC_CTX_new */
#define HAVE_EVP_MAC_CTX_new /**/

/* Define if you have EVP_PKEY_check */
#define HAVE_EVP_PKEY_check /**/

/* Define to 1 if you have the <execinfo.h> header file. */
#define HAVE_EXECINFO_H 1

/* Define if we have syscall faccessat2 */
#define HAVE_FACCESSAT2 /**/

/* Define to 1 if you have the `fallocate' function. */
#define HAVE_FALLOCATE 1

/* Define to 1 if you have the `flock' function. */
#define HAVE_FLOCK 1

/* Define if your compiler has -fno-sanitize=nonnull-attribute */
/* #undef HAVE_FNO_SANITIZE_NONNULL_ATTRIBUTE */

/* Define if you have FreeBSD-compatible sendfile() */
/* #undef HAVE_FREEBSD_SENDFILE */

/* Define if your compiler has -fsanitize=implicit-integer-truncation */
/* #undef HAVE_FSANITIZE_IMPLICIT_INTEGER_TRUNCATION */

/* Define if your compiler has -fsanitize=integer */
/* #undef HAVE_FSANITIZE_INTEGER */

/* Define if your compiler has -fsanitize=local-bounds */
/* #undef HAVE_FSANITIZE_LOCAL_BOUNDS */

/* Define if your compiler has -fsanitize=nullability */
/* #undef HAVE_FSANITIZE_NULLABILITY */

/* Define if your compiler has -fsanitize=undefined */
/* #undef HAVE_FSANITIZE_UNDEFINED */

/* Define to 1 if you have the `getmntent' function. */
#define HAVE_GETMNTENT 1

/* Define to 1 if you have the `getmntinfo' function. */
/* #undef HAVE_GETMNTINFO */

/* Define to 1 if you have the `getpeereid' function. */
/* #undef HAVE_GETPEEREID */

/* Define to 1 if you have the `getpeerucred' function. */
/* #undef HAVE_GETPEERUCRED */

/* Define to 1 if you have the `getrandom' function. */
#define HAVE_GETRANDOM 1

/* Define to 1 if you have the `glob' function. */
#define HAVE_GLOB 1

/* Define to 1 if you have the <glob.h> header file. */
#define HAVE_GLOB_H 1

/* Build with GSSAPI support */
#define HAVE_GSSAPI /**/

/* Define to 1 if you have the <gssapi/gssapi_ext.h> header file. */
#define HAVE_GSSAPI_GSSAPI_EXT_H 1

/* GSSAPI headers in gssapi/gssapi.h */
#define HAVE_GSSAPI_GSSAPI_H /**/

/* Define to 1 if you have the <gssapi/gssapi_krb5.h> header file. */
#define HAVE_GSSAPI_GSSAPI_KRB5_H 1

/* GSSAPI headers in gssapi.h */
#define HAVE_GSSAPI_H /**/

/* Define to 1 if you have the <gssapi_krb5.h> header file. */
/* #undef HAVE_GSSAPI_KRB5_H */

/* GSSAPI supports SPNEGO */
#define HAVE_GSSAPI_SPNEGO /**/

/* Define to 1 if you have the `gsskrb5_register_acceptor_identity' function.
   */
/* #undef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY */

/* Define to 1 if you have the `inotify_init' function. */
#define HAVE_INOTIFY_INIT 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <jfs/quota.h> header file. */
/* #undef HAVE_JFS_QUOTA_H */

/* Define to 1 if you have the `kevent' function. */
/* #undef HAVE_KEVENT */

/* Define to 1 if you have the `kqueue' function. */
/* #undef HAVE_KQUEUE */

/* Define to 1 if you have the `krb5_free_context' function. */
#define HAVE_KRB5_FREE_CONTEXT 1

/* Define to 1 if you have the `krb5_gss_register_acceptor_identity' function.
   */
#define HAVE_KRB5_GSS_REGISTER_ACCEPTOR_IDENTITY 1

/* Define if you want exttextcat support for lib-language */
#define HAVE_LANG_EXTTEXTCAT /**/

/* Define if you want stemming support for lib-language */
#define HAVE_LANG_STEMMER /**/

/* Define if you want textcat support for lib-language */
#define HAVE_LANG_TEXTCAT /**/

/* Build with LDAP support */
#define HAVE_LDAP /**/

/* Define this if you have libbsd */
/* #undef HAVE_LIBBSD */

/* libcap is installed for cap_init() */
#define HAVE_LIBCAP /**/

/* Define to 1 if you have the <libexttextcat/textcat.h> header file. */
#define HAVE_LIBEXTTEXTCAT_TEXTCAT_H 1

/* Define if you want ICU normalization support for lib-language */
#define HAVE_LIBICU /**/

/* Define if you have libpcre2 backed regular expressions */
/* #undef HAVE_LIBPCRE */

/* Define if you have libsodium */
#define HAVE_LIBSODIUM 1

/* Define to 1 if you have libsystemd */
/* #undef HAVE_LIBSYSTEMD */

/* Define to 1 if you have the <libtextcat/textcat.h> header file. */
/* #undef HAVE_LIBTEXTCAT_TEXTCAT_H */

/* Define this if you have libunwind */
#define HAVE_LIBUNWIND /**/

/* Define to 1 if you have the <linux/dqblk_xfs.h> header file. */
#define HAVE_LINUX_DQBLK_XFS_H 1

/* Define to 1 if you have the <linux/falloc.h> header file. */
#define HAVE_LINUX_FALLOC_H 1

/* Define if you have Linux-compatible mremap() */
#define HAVE_LINUX_MREMAP /**/

/* Define if you have Linux-compatible sendfile() */
#define HAVE_LINUX_SENDFILE /**/

/* Enable fuzzer aspects suitable only for local use (not for e.g. OSS-Fuzz)
   */
/* #undef HAVE_LOCAL_FUZZER */

/* Define to 1 if you have Lua */
#define HAVE_LUA 1

/* Define to 1 if you have the `luaL_setfuncs' function. */
#define HAVE_LUAL_SETFUNCS 1

/* Define to 1 if you have the `luaL_setmetatable' function. */
#define HAVE_LUAL_SETMETATABLE 1

/* Define to 1 if you have the `lua_isinteger' function. */
#define HAVE_LUA_ISINTEGER 1

/* Define to 1 if you have the `lua_resume' function. */
#define HAVE_LUA_RESUME 1

/* Define to 1 if you have the `lua_seti' function. */
#define HAVE_LUA_SETI 1

/* Define to 1 if you have the `lua_tointegerx' function. */
#define HAVE_LUA_TOINTEGERX 1

/* Define to 1 if you have the `lua_yieldk' function. */
#define HAVE_LUA_YIELDK 1

/* Define if you have lz4 library */
#define HAVE_LZ4 /**/

/* Define if you have LZ4_compress_default */
#define HAVE_LZ4_COMPRESS_DEFAULT /**/

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the <malloc_np.h> header file. */
/* #undef HAVE_MALLOC_NP_H */

/* Define to 1 if you have the `malloc_usable_size' function. */
#define HAVE_MALLOC_USABLE_SIZE 1

/* Define to 1 if you have the <mntent.h> header file. */
#define HAVE_MNTENT_H 1

/* Build with MySQL support */
/* #undef HAVE_MYSQL */

/* Define if your MySQL library has SSL functions */
/* #undef HAVE_MYSQL_SSL */

/* Define if your MySQL library supports setting cipher */
/* #undef HAVE_MYSQL_SSL_CIPHER */

/* Define if your MySQL library supports verifying the name in the SSL
   certificate */
/* #undef HAVE_MYSQL_SSL_VERIFY_SERVER_CERT */

/* 1 */
#define HAVE_OPENSSL3 /**/

/* Define to 1 if you have the <openssl/err.h> header file. */
/* #undef HAVE_OPENSSL_ERR_H */

/* Define if you have openssl/rand.h */
/* #undef HAVE_OPENSSL_RAND_H */

/* Define to 1 if you have the <openssl/ssl.h> header file. */
/* #undef HAVE_OPENSSL_SSL_H */

/* Define if you have OPENSSL_buf2hexstr */
#define HAVE_OPENSSL_buf2hexstr /**/

/* Define if you have OSSL_PROVIDER_try_load */
#define HAVE_OSSL_PROVIDER_try_load /**/

/* Define if you have pam/pam_appl.h */
/* #undef HAVE_PAM_PAM_APPL_H */

/* Define if you have pam_setcred() */
/* #undef HAVE_PAM_SETCRED */

/* Define if you have pcre2_substitute_callout_block */
/* #undef HAVE_PCRE2_SUBSTITUTE_CALLOUT_BLOCK */

/* Build with PostgreSQL support */
#define HAVE_PGSQL /**/

/* Define to 1 if you have the `posix_fadvise' function. */
#define HAVE_POSIX_FADVISE 1

/* Define if you have a working posix_fallocate() */
#define HAVE_POSIX_FALLOCATE /**/

/* Define if libpq has PQescapeStringConn function */
#define HAVE_PQESCAPE_STRING_CONN /**/

/* Define to 1 if you have the `pread' function. */
#define HAVE_PREAD 1

/* Define if you have prctl(PR_SET_DUMPABLE) */
#define HAVE_PR_SET_DUMPABLE /**/

/* Define to 1 if you have the `quotactl' function. */
#define HAVE_QUOTACTL 1

/* Define to 1 if you have the <quota.h> header file. */
/* #undef HAVE_QUOTA_H */

/* Define if you have quota_open() */
/* #undef HAVE_QUOTA_OPEN */

/* Define if Q_QUOTACTL exists */
/* #undef HAVE_Q_QUOTACTL */

/* Define if you have RLIMIT_AS for setrlimit() */
#define HAVE_RLIMIT_AS /**/

/* Define if you have RLIMIT_CORE for getrlimit() */
#define HAVE_RLIMIT_CORE /**/

/* Define if you have RLIMIT_NPROC for setrlimit() */
#define HAVE_RLIMIT_NPROC /**/

/* Define if you wish to retrieve quota of NFS mounted mailboxes */
#define HAVE_RQUOTA /**/

/* Define to 1 if you have the <sasl.h> header file. */
/* #undef HAVE_SASL_H */

/* Define to 1 if you have the <sasl/sasl.h> header file. */
#define HAVE_SASL_SASL_H 1

/* Define to 1 if you have the `sched_getaffinity' function. */
#define HAVE_SCHED_GETAFFINITY 1

/* Define to 1 if you have the <sched.h> header file. */
#define HAVE_SCHED_H 1

/* Define if you have security/pam_appl.h */
/* #undef HAVE_SECURITY_PAM_APPL_H */

/* Define to 1 if you have the `setpriority' function. */
#define HAVE_SETPRIORITY 1

/* Define to 1 if you have the `setproctitle' function. */
/* #undef HAVE_SETPROCTITLE */

/* Define to 1 if you have the `setresgid' function. */
#define HAVE_SETRESGID 1

/* Define if you have Solaris-compatible sendfile() */
/* #undef HAVE_SOLARIS_SENDFILE */

/* Build with SQLite3 support */
/* #undef HAVE_SQLITE */

/* Define if you have SSL_CTX_select_current_cert */
#define HAVE_SSL_CTX_select_current_cert /**/

/* Define if you have SSL_CTX_set0_tmp_dh_pkey */
#define HAVE_SSL_CTX_set0_tmp_dh_pkey /**/

/* Define if you have SSL_CTX_set_alpn_select_cb */
#define HAVE_SSL_CTX_set_alpn_select_cb /**/

/* Define if you have SSL_CTX_set_client_hello_cb */
#define HAVE_SSL_CTX_set_client_hello_cb /**/

/* Define if you have SSL_CTX_set_current_cert */
#define HAVE_SSL_CTX_set_current_cert /**/

/* Define if you have SSL_CTX_set_tmp_dh_callback */
/* #undef HAVE_SSL_CTX_set_tmp_dh_callback */

/* Define if CRYPTO_set_mem_functions has new style parameters */
#define HAVE_SSL_NEW_MEM_FUNCS /**/

/* Define if you have SSL_client_hello_get0_ciphers */
#define HAVE_SSL_client_hello_get0_ciphers /**/

/* Define if you have SSL_get1_peer_certificate */
#define HAVE_SSL_get1_peer_certificate /**/

/* Define if you have statfs.f_mntfromname */
/* #undef HAVE_STATFS_MNTFROMNAME */

/* Define if you have statvfs.f_mntfromname */
/* #undef HAVE_STATVFS_MNTFROMNAME */

/* Define if you have st_?tim timespec fields in struct stat */
#define HAVE_STAT_XTIM /**/

/* Define if you have st_?timespec fields in struct stat */
/* #undef HAVE_STAT_XTIMESPEC */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* we have strict bool */
/* #undef HAVE_STRICT_BOOL */

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if struct sqblk.dqb_curblocks exists */
/* #undef HAVE_STRUCT_DQBLK_CURBLOCKS */

/* Define if struct sqblk.dqb_curspace exists */
#define HAVE_STRUCT_DQBLK_CURSPACE /**/

/* Define if you have struct iovec */
#define HAVE_STRUCT_IOVEC /**/

/* Define to 1 if the system has the type `struct sockpeercred'. */
/* #undef HAVE_STRUCT_SOCKPEERCRED */

/* Define to 1 if you have the <sys/cpuset.h> header file. */
/* #undef HAVE_SYS_CPUSET_H */

/* Define to 1 if you have the <sys/event.h> header file. */
/* #undef HAVE_SYS_EVENT_H */

/* Define to 1 if you have the <sys/fs/quota_common.h> header file. */
/* #undef HAVE_SYS_FS_QUOTA_COMMON_H */

/* Define to 1 if you have the <sys/fs/ufs_quota.h> header file. */
/* #undef HAVE_SYS_FS_UFS_QUOTA_H */

/* Define to 1 if you have the <sys/mkdev.h> header file. */
/* #undef HAVE_SYS_MKDEV_H */

/* Define to 1 if you have the <sys/mnttab.h> header file. */
/* #undef HAVE_SYS_MNTTAB_H */

/* Define to 1 if you have the <sys/quota.h> header file. */
#define HAVE_SYS_QUOTA_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/sysmacros.h> header file. */
#define HAVE_SYS_SYSMACROS_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/ucred.h> header file. */
/* #undef HAVE_SYS_UCRED_H */

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <sys/utsname.h> header file. */
#define HAVE_SYS_UTSNAME_H 1

/* Define to 1 if you have the <sys/vmount.h> header file. */
/* #undef HAVE_SYS_VMOUNT_H */

/* Define to 1 if you have the `timegm' function. */
#define HAVE_TIMEGM 1

/* Define if you have struct tm->tm_gmtoff */
#define HAVE_TM_GMTOFF /**/

/* Define if you have typeof() */
#define HAVE_TYPEOF /**/

/* Define to 1 if you have the <ucontext.h> header file. */
#define HAVE_UCONTEXT_H 1

/* Define to 1 if you have the <ucred.h> header file. */
/* #undef HAVE_UCRED_H */

/* Define to 1 if you have the <ufs/ufs/quota.h> header file. */
/* #undef HAVE_UFS_UFS_QUOTA_H */

/* Define if your compiler supports undefined sanitizers */
/* #undef HAVE_UNDEFINED_SANITIZER */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define if you have a native uoff_t type */
/* #undef HAVE_UOFF_T */

/* Define to 1 if you have the <valgrind/valgrind.h> header file. */
/* #undef HAVE_VALGRIND_VALGRIND_H */

/* Define to 1 if you have the `walkcontext' function. */
/* #undef HAVE_WALKCONTEXT */

/* Xapian is available */
#define HAVE_XAPIAN 1

/* Define to 1 if you have the <xfs/xqm.h> header file. */
/* #undef HAVE_XFS_XQM_H */

/* Define if you have ZSTD library */
#define HAVE_ZSTD /**/

/* Whether zstd has ZSTD_getErrorCode */
#define HAVE_ZSTD_GETERRORCODE 1

/* Implement I/O loop with Linux 2.6 epoll() */
#define IOLOOP_EPOLL /**/

/* Implement I/O loop with BSD kqueue() */
/* #undef IOLOOP_KQUEUE */

/* Use Linux inotify */
#define IOLOOP_NOTIFY_INOTIFY /**/

/* Use BSD kqueue directory changes notification */
/* #undef IOLOOP_NOTIFY_KQUEUE */

/* No special notify support */
/* #undef IOLOOP_NOTIFY_NONE */

/* Implement I/O loop with poll() */
/* #undef IOLOOP_POLL */

/* Implement I/O loop with select() */
/* #undef IOLOOP_SELECT */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Required memory alignment */
#define MEM_ALIGN_SIZE 8

/* Define if shared mmaps don't get updated by write()s */
/* #undef MMAP_CONFLICTS_WRITE */

/* Dynamic module suffix */
#define MODULE_SUFFIX ".so"

/* Maximum value of off_t */
#define OFF_T_MAX LONG_MAX

/* Name of package */
#define PACKAGE "dovecot"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "dovecot@dovecot.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "Dovecot"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "Dovecot 2.4.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "dovecot"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.4.1"

/* Support URL */
#define PACKAGE_WEBPAGE "https://www.dovecot.org/"

/* Build with BSD authentication support */
/* #undef PASSDB_BSDAUTH */

/* Build with PAM support */
/* #undef PASSDB_PAM */

/* Build with passwd support */
#define PASSDB_PASSWD /**/

/* Build with passwd-file support */
#define PASSDB_PASSWD_FILE /**/

/* Build with SQL support */
#define PASSDB_SQL /**/

/* printf() fmt for dec time_t */
#define PRIdTIME_T "ld"

/* printf() format for uoff_t */
#define PRIuUOFF_T "lu"

/* printf() fmt for hex time_t */
#define PRIxTIME_T "lx"

/* Define if process title can be changed by modifying argv */
#define PROCTITLE_HACK /**/

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 8

/* The size of `long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of `size_t', as computed by sizeof. */
#define SIZEOF_SIZE_T 8

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Build SQL drivers as plugins */
#define SQL_DRIVER_PLUGINS /**/

/* Maximum value of ssize_t */
#define SSIZE_T_MAX LONG_MAX

/* Building with static code analyzer */
/* #undef STATIC_CHECKER */

/* reasonable mntctl buffer size */
/* #undef STATIC_MTAB_SIZE */

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Points to textcat pkgdatadir containing the language files */
#define TEXTCAT_DATADIR "/usr/share/libexttextcat"

/* max. time_t bits gmtime() can handle */
#define TIME_T_MAX_BITS 40

/* Define if your time_t is signed */
#define TIME_T_SIGNED /**/

/* Define if off_t is int */
/* #undef UOFF_T_INT */

/* Define if off_t is long */
#define UOFF_T_LONG /**/

/* Define if off_t is long long */
/* #undef UOFF_T_LONG_LONG */

/* Maximum value of uoff_t */
#define UOFF_T_MAX ULONG_MAX

/* Build with passwd support */
#define USERDB_PASSWD /**/

/* Build with passwd-file support */
#define USERDB_PASSWD_FILE /**/

/* Build with prefetch userdb support */
#define USERDB_PREFETCH /**/

/* Build with SQL support */
#define USERDB_SQL /**/

/* A 'va_copy' style function */
#define VA_COPY va_copy

/* Version number of package */
#define VERSION "2.4.1"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to 'unsigned int' if you don't have it */
/* #undef size_t */

/* Define to 'int' if you don't have it */
/* #undef ssize_t */
