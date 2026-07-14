# Runtime environment for the bc-java jdk1.3 (build1-3) legacy build.
#
# Base: Debian 4.0 "etch" i386 (glibc 2.3.6). Chosen deliberately:
#   * i386 userland  -> matches the 32-bit Sun JDK 1.3.1 binaries.
#   * glibc < 2.4    -> no PTR_MANGLE pointer mangling. Sun's Classic VM green
#                       threads hand-roll jmp_buf context switches; on glibc
#                       >= 2.4 (e.g. bullseye/jessie 2.19) longjmp demangles a
#                       raw poked-in PC and jumps to garbage -> SIGSEGV. 2.3.6
#                       does not mangle, so the Classic/green VM runs.
# The host kernel is shared (containers share it), but green threads are
# user-space, so no kernel-version dependency bites here.
FROM debian/eol:etch

# The 2001-era Sun launch wrapper (bin/.java_wrapper) predates x86-64: it reads
# `uname -m`, and because this container shares the host's amd64 kernel that
# returns "x86_64", which the wrapper cannot map to its i386 lib dir -> it dies
# with "can't find libjava.so". apt is dead on EOL etch (no `linux32`), so shim
# `uname -m` to report i686. Everything else passes through to the real uname.
RUN cp -a /bin/uname /bin/uname.real \
 && printf '%s\n' \
      '#!/bin/sh' \
      'if [ "$1" = "-m" ]; then echo i686; exit 0; fi' \
      'exec /bin/uname.real "$@"' > /bin/uname \
 && chmod 0755 /bin/uname

# Nothing else is baked in: the JDK, ant, aux jars and the repo are all
# bind-mounted at run time by build-jdk13.sh so the image stays tiny and the
# host tree is the single source of truth.
