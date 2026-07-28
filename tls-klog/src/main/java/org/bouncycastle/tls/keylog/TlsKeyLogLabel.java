package org.bouncycastle.tls.keylog;

/**
 * The RFC 9850 labels a {@link TlsKeyLog} can be handed by this implementation.
 * <p>
 * RFC 9850 sec. 2.3 additionally defines <code>ECH_SECRET</code> and <code>ECH_CONFIG</code> for
 * Encrypted ClientHello. Bouncy Castle does not implement ECH, so those labels are not defined
 * here; they belong with the code that would emit them.
 */
public abstract class TlsKeyLogLabel
{
    /**
     * The TLS 1.2-and-earlier master secret (RFC 9850 sec. 2.2), 48 bytes.
     */
    public static final String CLIENT_RANDOM = "CLIENT_RANDOM";

    /**
     * The TLS 1.3 client early traffic secret protecting early data (RFC 9850 sec. 2.1).
     */
    public static final String CLIENT_EARLY_TRAFFIC_SECRET = "CLIENT_EARLY_TRAFFIC_SECRET";

    /**
     * The TLS 1.3 early exporter master secret (RFC 9850 sec. 2.1).
     */
    public static final String EARLY_EXPORTER_SECRET = "EARLY_EXPORTER_SECRET";

    /**
     * The TLS 1.3 client handshake traffic secret (RFC 9850 sec. 2.1).
     */
    public static final String CLIENT_HANDSHAKE_TRAFFIC_SECRET = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";

    /**
     * The TLS 1.3 server handshake traffic secret (RFC 9850 sec. 2.1).
     */
    public static final String SERVER_HANDSHAKE_TRAFFIC_SECRET = "SERVER_HANDSHAKE_TRAFFIC_SECRET";

    /**
     * The TLS 1.3 client application traffic secret, before any KeyUpdate (RFC 9850 sec. 2.1).
     */
    public static final String CLIENT_TRAFFIC_SECRET_0 = "CLIENT_TRAFFIC_SECRET_0";

    /**
     * The TLS 1.3 server application traffic secret, before any KeyUpdate (RFC 9850 sec. 2.1).
     */
    public static final String SERVER_TRAFFIC_SECRET_0 = "SERVER_TRAFFIC_SECRET_0";

    /**
     * The TLS 1.3 exporter master secret (RFC 9850 sec. 2.1).
     */
    public static final String EXPORTER_SECRET = "EXPORTER_SECRET";
}
