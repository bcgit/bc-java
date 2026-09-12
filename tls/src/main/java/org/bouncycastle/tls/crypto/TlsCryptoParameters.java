package org.bouncycastle.tls.crypto;

import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsContext;

/**
 * Carrier class for context-related parameters needed for creating secrets and ciphers.
 */
public class TlsCryptoParameters
{
    private final TlsContext context;

    /**
     * Base constructor.
     *
     * @param context the context for this parameters object.
     */
    public TlsCryptoParameters(TlsContext context)
    {
        this.context = context;
    }

    /**
     * Return the security parameters currently in force: the handshake parameters while a handshake is in
     * progress, the connection parameters once it has completed. This mirrors
     * {@code AbstractTlsContext.getSecurityParameters()}, and lets a cipher be built after the handshake has
     * completed (RFC 9147 4.6.3 key update), when the handshake parameters no longer exist.
     *
     * @return the security parameters in force, or null before any handshake has begun.
     */
    public SecurityParameters getSecurityParameters()
    {
        return context.getSecurityParameters();
    }

    public SecurityParameters getSecurityParametersConnection()
    {
        return context.getSecurityParametersConnection();
    }

    public SecurityParameters getSecurityParametersHandshake()
    {
        return context.getSecurityParametersHandshake();
    }

    public ProtocolVersion getClientVersion()
    {
        return context.getClientVersion();
    }

    public ProtocolVersion getRSAPreMasterSecretVersion()
    {
        return context.getRSAPreMasterSecretVersion();
    }

    public ProtocolVersion getServerVersion()
    {
        return context.getServerVersion();
    }

    public boolean isServer()
    {
        return context.isServer();
    }

    public TlsNonceGenerator getNonceGenerator()
    {
        return context.getNonceGenerator();
    }
}
