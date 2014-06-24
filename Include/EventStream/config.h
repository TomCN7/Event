#ifndef __ESOCKET_CONFIG_H__
#define __ESOCKET_CONFIG_H__

#define EVENT__SIZEOF_SIZE_T 4

/* Define to 1 if the system has the type `struct in6_addr'. */
#define EVENT__HAVE_STRUCT_IN6_ADDR 1

/* Define to 1 if the system has the type `struct sockaddr_in6'. */
#define EVENT__HAVE_STRUCT_SOCKADDR_IN6 1

/* Define to 1 if the system has the type `struct sockaddr_storage'. */
#define EVENT__HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define to 1 if you have the <stdarg.h> header file. */
#define EVENT__HAVE_STDARG_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define EVENT__HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define EVENT__HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define EVENT__HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
/* #undef EVENT__HAVE_STRINGS_H */

/* Define to 1 if you have the <string.h> header file. */
#define EVENT__HAVE_STRING_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define EVENT__HAVE_FCNTL_H 1

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
#define EVENT__inline __inline
#endif

/* Define to appropriate substitute if compiler doesnt have __func__ */
#define EVENT____func__ __FUNCTION__

/* Number of bits in a file offset, on hosts where this is settable. */
#define EVENT___FILE_OFFSET_BITS _FILE_OFFSET_BITS

/* Define to 1 if you have the <sys/stat.h> header file. */
#define EVENT__HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define EVENT__HAVE_SYS_TYPES_H 1

/* Define to `int' if <sys/types.h> does not define. */
#define EVENT__ssize_t SSIZE_T

#define event_core_EXPORTS

#endif //__ESOCKET_CONFIG_H__
