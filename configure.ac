# Prelude
AC_PREREQ([2.69])
AC_INIT([btest], [160], [alex.burlyga.ietf@gmail.com])
AC_CONFIG_SRCDIR([src/btest.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Checks for programs
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for libraries
# Checks for header files
AC_CHECK_HEADERS([fcntl.h inttypes.h stdint.h stdlib.h string.h sys/ioctl.h sys/mount.h sys/time.h unistd.h])
AC_CHECK_HEADERS([libaio.h])

# Checks for typdefs, structures, and compiler characterisctics
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero clock_gettime ftruncate gettimeofday memset strchr strdup strerror strtol strtoul strtoull])

# Output files
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
