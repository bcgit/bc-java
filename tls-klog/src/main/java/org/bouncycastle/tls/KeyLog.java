package org.bouncycastle.tls;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.TlsSecretExporter;
import org.bouncycastle.tls.keylog.TlsKeyLog;
import org.bouncycastle.tls.keylog.TlsKeyLogLabel;
import org.bouncycastle.util.Arrays;

/**
 * RFC 9850 (SSLKEYLOGFILE) key logging, as built into <code>bctls-klog</code>.
 * <p>
 * This class replaces the no-op of the same name in the standard <code>bctls</code> build, and is
 * the only difference between the two: the seam calls in {@link TlsUtils} are the same in both, and
 * in <code>bctls</code> they go nowhere. Here they end up at a
 * {@link TlsKeyLog} named by the <code>org.bouncycastle.tls.keylog.class</code> security property,
 * which is resolved once and, if the property is unset, is never resolved to anything &mdash; so
 * even this build discloses nothing until an administrator asks it to.
 * <p>
 * All of the RFC's vocabulary lives here rather than in {@link TlsUtils}: the seam reports secrets
 * in the key schedule's own terms and this class decides which of them RFC 9850 names, what it
 * calls them, and when they are worth reporting at all.
 */
abstract class KeyLog
{
    /**
     * Security property naming the {@link TlsKeyLog} implementation to report secrets to. Read with
     * {@link Security#getProperty(String)}, deliberately not as a system property; see
     * {@link TlsKeyLog} for why.
     */
    static final String KEY_LOG_CLASS_PROPERTY = "org.bouncycastle.tls.keylog.class";

    private static final Logger LOG = Logger.getLogger(KeyLog.class.getName());

    private static final TlsKeyLog keyLog = createKeyLog();

    static void logMasterSecret(TlsContext context)
    {
        if (null == keyLog)
        {
            return;
        }

        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        if (null == securityParameters)
        {
            return;
        }

        /*
         * TLS 1.3 reaches the seam too, and has no CLIENT_RANDOM record: RFC 9850 2.2 is the master
         * secret of TLS 1.2 and earlier, and the 1.3 secret of that name protects nothing directly.
         */
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (null == negotiatedVersion || TlsUtils.isTLSv13(negotiatedVersion))
        {
            return;
        }

        log(TlsKeyLogLabel.CLIENT_RANDOM, securityParameters, securityParameters.getMasterSecret());
    }

    static void log13Secret(TlsContext context, String label, TlsSecret secret)
    {
        if (null == keyLog)
        {
            return;
        }

        String keyLogLabel = getKeyLogLabel(label);
        if (null == keyLogLabel)
        {
            return;
        }

        log(keyLogLabel, context.getSecurityParametersHandshake(), secret);
    }

    /**
     * Map an RFC 8446 key-schedule label onto the RFC 9850 sec. 2.1 label for the same secret,
     * returning null for the schedule's many other labels ("derived", "res master", the binder and
     * Finished keys), none of which RFC 9850 reports.
     */
    private static String getKeyLogLabel(String label)
    {
        if ("c e traffic".equals(label))
        {
            return TlsKeyLogLabel.CLIENT_EARLY_TRAFFIC_SECRET;
        }
        if ("e exp master".equals(label))
        {
            return TlsKeyLogLabel.EARLY_EXPORTER_SECRET;
        }
        if ("c hs traffic".equals(label))
        {
            return TlsKeyLogLabel.CLIENT_HANDSHAKE_TRAFFIC_SECRET;
        }
        if ("s hs traffic".equals(label))
        {
            return TlsKeyLogLabel.SERVER_HANDSHAKE_TRAFFIC_SECRET;
        }
        if ("c ap traffic".equals(label))
        {
            return TlsKeyLogLabel.CLIENT_TRAFFIC_SECRET_0;
        }
        if ("s ap traffic".equals(label))
        {
            return TlsKeyLogLabel.SERVER_TRAFFIC_SECRET_0;
        }
        if ("exp master".equals(label))
        {
            return TlsKeyLogLabel.EXPORTER_SECRET;
        }

        return null;
    }

    private static void log(String label, SecurityParameters securityParameters, TlsSecret secret)
    {
        if (null == securityParameters || null == secret)
        {
            return;
        }

        byte[] clientRandom = securityParameters.getClientRandom();
        if (null == clientRandom)
        {
            return;
        }

        byte[] secretBytes = TlsSecretExporter.exportSecret(secret);
        if (null == secretBytes)
        {
            LOG.warning("Unable to read the secret for key log label " + label);
            return;
        }

        try
        {
            keyLog.log(label, Arrays.clone(clientRandom), secretBytes);
        }
        catch (Exception e)
        {
            /*
             * Key logging is a debugging aid attached to a connection that is not itself being
             * debugged. A sink that cannot cope is a broken key log, not a broken connection.
             */
            LOG.log(Level.WARNING, "TlsKeyLog failed to log " + label, e);
        }
    }

    private static TlsKeyLog createKeyLog()
    {
        String className = getSecurityProperty(KEY_LOG_CLASS_PROPERTY);
        if (null == className || className.length() < 1)
        {
            return null;
        }

        try
        {
            TlsKeyLog instance = (TlsKeyLog)loadClass(className).newInstance();

            /*
             * Say so, loudly and once. A JVM that is handing out the keys to its own TLS traffic
             * should not be doing it quietly; RFC 9850 1.1 rules this out of production entirely.
             */
            LOG.warning("TLS key logging is enabled: connection secrets are being reported to "
                + className + " as described by RFC 9850. This must not be done in production.");

            return instance;
        }
        catch (Exception e)
        {
            LOG.log(Level.SEVERE, "Unable to load the TlsKeyLog named by the " + KEY_LOG_CLASS_PROPERTY
                + " security property (" + className + "); TLS key logging is disabled", e);
            return null;
        }
    }

    private static Class loadClass(String className) throws ClassNotFoundException
    {
        /*
         * The implementation is the application's, so prefer whichever loader can see it: ours if
         * it is alongside this jar, the context loader if this jar sits in a container's shared
         * libraries and the implementation does not.
         */
        try
        {
            return Class.forName(className, true, KeyLog.class.getClassLoader());
        }
        catch (ClassNotFoundException e)
        {
            ClassLoader contextClassLoader = getContextClassLoader();
            if (null == contextClassLoader)
            {
                throw e;
            }

            return contextClassLoader.loadClass(className);
        }
    }

    private static String getSecurityProperty(final String propertyName)
    {
        return (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                return Security.getProperty(propertyName);
            }
        });
    }

    private static ClassLoader getContextClassLoader()
    {
        return (ClassLoader)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                return Thread.currentThread().getContextClassLoader();
            }
        });
    }
}
