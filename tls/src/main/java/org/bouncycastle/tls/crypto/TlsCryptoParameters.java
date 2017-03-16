package org.bouncycastle.tls.crypto;

import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsContext;

/**
 * Carrier class for context related parameters needed for creating secrets and cipher suites,
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

    public SecurityParameters getSecurityParameters()
    {
        return context.getSecurityParameters();
    }

    public ProtocolVersion getClientVersion()
    {
        return context.getClientVersion();
    }

    public ProtocolVersion getServerVersion()
    {
        return context.getServerVersion();
    }

    public boolean isServer()
    {
        return context.isServer();
    }
}
