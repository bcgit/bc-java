package org.bouncycastle.tls;

import java.security.Security;

import junit.framework.TestCase;

/**
 * The key-log security property selects a sink; it must not be a way to run arbitrary code.
 * <p>
 * Resolving the named class is the one moment this build acts on an outside string, and the
 * dangerous shape is loading it with initialisation on and only discovering it is the wrong type
 * once its static initialiser and constructor have already run. So this points the property at a
 * class that is not a {@link org.bouncycastle.tls.keylog.TlsKeyLog} and checks that neither ran.
 * <p>
 * Needs a JVM in which {@link KeyLog} has not yet resolved, since it resolves once and keeps the
 * answer; the build gives it one by running this class separately from the handshake tests. It sits
 * in <code>org.bouncycastle.tls</code> to reach the package-private seam directly, which triggers
 * that resolution without needing a handshake.
 */
public class KeyLogRejectsNonSinkTest
    extends TestCase
{
    /*
     * Both are string literals rather than references to NotAKeyLog, deliberately: naming that
     * class through a class literal or one of its constants risks loading it here, which is the
     * very thing the assertion is trying to measure.
     */
    private static final String NOT_A_KEY_LOG = "org.bouncycastle.tls.keylog.test.NotAKeyLog";
    private static final String CANARY_PROPERTY = "org.bouncycastle.tls.keylog.test.canary";

    static
    {
        Security.setProperty(KeyLog.KEY_LOG_CLASS_PROPERTY, NOT_A_KEY_LOG);
    }

    public void testNonSinkClassIsNeitherInitialisedNorConstructed()
    {
        assertNull("the canary ran before the test started", System.getProperty(CANARY_PROPERTY));

        /*
         * Forces KeyLog to resolve the property. With the class rejected there is no sink, so the
         * seam returns on its first check and never touches the (null) context.
         */
        KeyLog.logMasterSecret(null);

        assertNull("naming a non-TlsKeyLog class ran code in it", System.getProperty(CANARY_PROPERTY));
    }
}
