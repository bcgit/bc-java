#!/bin/sh -
#
# Drive the bc-java jdk1.3 (build1-3) legacy build inside an i386 / glibc-2.3.6
# container, because a genuine Sun JDK 1.3.1 no longer runs on a modern host
# (its native-threads launcher needs the extinct libstdc++-libc6.1-1.so.2, and
# its green-threads Classic VM segfaults on glibc >= 2.4 pointer mangling).
#
# Usage:
#   ./build-jdk13.sh                # full build   (build1-3, no arg)
#   ./build-jdk13.sh provider       # provider only (build1-3 provider)
#   ./build-jdk13.sh test           # build + run the test suite
#   ./build-jdk13.sh shell          # interactive shell in the container (debug)
#
# Override any host path via env, e.g.  BC_JAVA=/path/to/bc-java ./build-jdk13.sh
#
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# --- host paths (all bind-mounted read-only except the repo) -----------------
BC_JAVA=${BC_JAVA:-/home/dgh/bc/git/repositories/bc-java}
# Resolve the /opt/jdk1.3.1 symlink to its real target so the mount is stable.
JDK_HOST=${JDK_HOST:-$(readlink -f /opt/jdk1.3.1)}
ANT_HOST=${ANT_HOST:-/opt/apache-ant-1.6.5}
MAIL_HOST=${MAIL_HOST:-/opt/javamail-1.3.1}
JAF_HOST=${JAF_HOST:-/opt/jaf-1.0.2}
IMAGE=${IMAGE:-bc-jdk13:etch}

# ORO impl for ant's <replaceregexp> (JDK 1.3 has no java.util.regex). Not
# bundled with the skill (it is a binary); located from common host spots, or
# set ORO_JAR explicitly. Any jakarta-oro / oro 2.0.x jar works.
if [ -z "$ORO_JAR" ]; then
    for c in /home/dgh/.m2/repository/oro/oro/2.0.8/oro-2.0.8.jar \
             /home/dgh/.m2/repository/oro/oro/2.0.7/oro-2.0.7.jar \
             "$SCRIPT_DIR"/oro-*.jar "$SCRIPT_DIR"/jakarta-oro*.jar; do
        [ -e "$c" ] && { ORO_JAR=$c; break; }
    done
fi

for p in "$BC_JAVA/build1-3" "$JDK_HOST/bin/.java_wrapper" "$ANT_HOST/bin/ant" \
         "$MAIL_HOST/mail.jar" "$JAF_HOST/activation.jar" "$ORO_JAR" \
         "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR/jvm.cfg"; do
    [ -n "$p" ] && [ -e "$p" ] || {
        echo "ERROR: missing required path: ${p:-<ORO_JAR unset: set ORO_JAR=/path/to/oro-2.0.x.jar>}" >&2
        exit 1
    }
done

# --- build the (tiny) image once ---------------------------------------------
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo ">> building $IMAGE"
    docker build --platform linux/386 -t "$IMAGE" "$SCRIPT_DIR"
fi

# --- what to run inside -------------------------------------------------------
if [ "$1" = "shell" ]; then
    RUNCMD="exec /bin/sh"
    TTY="-it"
else
    # build1-3 references $JAVA_MAIL_HOME / $JAVA_ACTIVATION_HOME but never sets
    # them, and hardcodes JDKPATH=/opt/jdk1.3.1 -- so we mount the JDK there and
    # export the two homes. ANT_HOME is auto-detected by the ant script.
    RUNCMD="cd /work && exec sh build1-3 $*"
    TTY=""
fi

# --- run ----------------------------------------------------------------------
# Nested bind mounts overlay a single file inside a read-only tree:
#   * jvm.cfg -> make -classic (green threads) the default VM. This works only
#     because jvm.cfg already EXISTS in the ro JDK mount; docker cannot create a
#     NEW mountpoint inside a ro mount (that is why oro goes to its own dir and
#     is added with ant -lib, not dropped into the ro /opt/ant/lib).
exec docker run --rm $TTY --platform linux/386 \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e JAVA_MAIL_HOME=/opt/javamail-1.3.1 \
    -e JAVA_ACTIVATION_HOME=/opt/jaf-1.0.2 \
    -e ANT_HOME=/opt/ant \
    -e ANT_ARGS="-lib /opt/extralib" \
    -e PATH=/opt/jdk1.3.1/bin:/opt/ant/bin:/usr/bin:/bin \
    -w /work \
    -v "$BC_JAVA":/work \
    -v "$JDK_HOST":/opt/jdk1.3.1:ro \
    -v "$SCRIPT_DIR/jvm.cfg":/opt/jdk1.3.1/jre/lib/jvm.cfg:ro \
    -v "$ANT_HOST":/opt/ant:ro \
    -v "$ORO_JAR":/opt/extralib/oro.jar:ro \
    -v "$MAIL_HOST":/opt/javamail-1.3.1:ro \
    -v "$JAF_HOST":/opt/jaf-1.0.2:ro \
    "$IMAGE" /bin/sh -c "$RUNCMD"
