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
BC_TEST_DATA=${BC_TEST_DATA:-$(dirname "$BC_JAVA")/bc-test-data}
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

# Real JDK 1.3.1 predates JAXP (added in J2SE 1.4): its rt.jar has no
# org.w3c.dom / javax.xml.transform at all. Two separate classpaths need a
# JAXP/TrAX implementation as a result:
#   * ant's OWN JVM, for the "test" target's <junitreport> XSLT step (else
#     TransformerFactoryConfigurationError: Provider
#     org.apache.xalan.processor.TransformerFactoryImpl not found) -- fixed by
#     mounting xalan/serializer into /opt/extralib, picked up automatically via
#     ANT_ARGS="-lib /opt/extralib" below (same mechanism as ORO_JAR).
#   * the forked <junit> test JVM, whose classpath is built independently by
#     ant/bc+-build.xml from build/artifacts/jdk1.3/jars/*.jar (NOT ant's own
#     -lib classpath) -- for the XML result formatter's org.w3c.dom.Node, else
#     every test suite fails with NoClassDefFoundError. Fixed by copying
#     xercesImpl/xml-apis into that jars/ directory as part of the "test" run
#     below (build/ is gitignored and gets wiped by `rm -rf build`, so this
#     cannot be a one-off manual copy -- it has to happen every run).
if [ -z "$XALAN_JAR" ]; then
    for c in /home/dgh/.m2/repository/xalan/xalan/2.7.2/xalan-2.7.2.jar \
             /home/dgh/.m2/repository/xalan/xalan/2.7.1/xalan-2.7.1.jar; do
        [ -e "$c" ] && { XALAN_JAR=$c; break; }
    done
fi
if [ -z "$SERIALIZER_JAR" ]; then
    for c in /home/dgh/.m2/repository/xalan/serializer/2.7.2/serializer-2.7.2.jar \
             /home/dgh/.m2/repository/xalan/serializer/2.7.1/serializer-2.7.1.jar; do
        [ -e "$c" ] && { SERIALIZER_JAR=$c; break; }
    done
fi
if [ -z "$XERCES_JAR" ]; then
    for c in /home/dgh/.m2/repository/xerces/xercesImpl/2.8.1/xercesImpl-2.8.1.jar \
             /home/dgh/.m2/repository/xerces/xercesImpl/2.9.1/xercesImpl-2.9.1.jar; do
        [ -e "$c" ] && { XERCES_JAR=$c; break; }
    done
fi
if [ -z "$XML_APIS_JAR" ]; then
    for c in /home/dgh/.m2/repository/xml-apis/xml-apis/1.3.04/xml-apis-1.3.04.jar \
             /home/dgh/.m2/repository/xml-apis/xml-apis/1.4.01/xml-apis-1.4.01.jar; do
        [ -e "$c" ] && { XML_APIS_JAR=$c; break; }
    done
fi

for p in "$BC_JAVA/build1-3" "$JDK_HOST/bin/.java_wrapper" "$ANT_HOST/bin/ant" \
         "$MAIL_HOST/mail.jar" "$JAF_HOST/activation.jar" "$ORO_JAR" \
         "$XALAN_JAR" "$SERIALIZER_JAR" "$XERCES_JAR" "$XML_APIS_JAR" \
         "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR/jvm.cfg"; do
    [ -n "$p" ] && [ -e "$p" ] || {
        echo "ERROR: missing required path: ${p:-<unset: set ORO_JAR/XALAN_JAR/SERIALIZER_JAR/XERCES_JAR/XML_APIS_JAR explicitly>}" >&2
        exit 1
    }
done

# bc-test-data is optional -- most SimpleTest/JUnit fixtures need it, but its
# absence should degrade (FileNotFoundException per test) rather than block
# the build. TestResourceFinder's walk-up starts from the forked <junit>'s
# cwd ("${build.dir}/${target.prefix}" = /work/build/jdk13) and climbs one
# path segment at a time; /work/bc-test-data is the candidate it actually
# reaches (its final, root-level candidate collapses to a relative path
# against the JVM's real cwd due to a File("", child) edge case, so mounting
# at the container's true "/" does not work).
BC_TEST_DATA_MOUNT=""
if [ -n "$BC_TEST_DATA" ] && [ -d "$BC_TEST_DATA" ]; then
    BC_TEST_DATA_MOUNT="-v $BC_TEST_DATA:/work/bc-test-data:ro"
fi

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
    if [ "$1" = "test" ]; then
        # See the XERCES_JAR/XML_APIS_JAR note above: the forked <junit> JVM's
        # classpath is every jar in build/artifacts/jdk1.3/jars/, so dropping
        # a JAXP/DOM impl there (that directory must already exist from a
        # prior plain build -- build-test only depends on init, not on build)
        # is how it gets one. Idempotent and silent if the dir is missing.
        RUNCMD="cd /work && mkdir -p build/artifacts/jdk1.3/jars && cp /opt/extralib/xercesImpl.jar /opt/extralib/xml-apis.jar build/artifacts/jdk1.3/jars/ && $RUNCMD"
    fi
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
    -v "$XALAN_JAR":/opt/extralib/xalan.jar:ro \
    -v "$SERIALIZER_JAR":/opt/extralib/serializer.jar:ro \
    -v "$XERCES_JAR":/opt/extralib/xercesImpl.jar:ro \
    -v "$XML_APIS_JAR":/opt/extralib/xml-apis.jar:ro \
    -v "$MAIL_HOST":/opt/javamail-1.3.1:ro \
    -v "$JAF_HOST":/opt/jaf-1.0.2:ro \
    $BC_TEST_DATA_MOUNT \
    "$IMAGE" /bin/sh -c "$RUNCMD"
