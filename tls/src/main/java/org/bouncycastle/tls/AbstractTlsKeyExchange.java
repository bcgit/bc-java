package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;

/**
 * Base class for supporting a TLS key exchange implementation.
 */
public abstract class AbstractTlsKeyExchange
    implements TlsKeyExchange
{
    protected int keyExchange;

    protected TlsContext context;

    protected AbstractTlsKeyExchange(int keyExchange)
    {
        this.keyExchange = keyExchange;
    }

    public void init(TlsContext context)
    {
        this.context = context;
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public boolean requiresServerKeyExchange()
    {
        return false;
    }

    public byte[] generateServerKeyExchange()
        throws IOException
    {
        if (requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        return null;
    }

    public void skipServerKeyExchange()
        throws IOException
    {
        if (requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void processServerKeyExchange(InputStream input)
        throws IOException
    {
        if (!requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public short[] getClientCertificateTypes()
    {
        return null;
    }

    public void skipClientCredentials() throws IOException
    {
    }

    public void processClientCertificate(Certificate clientCertificate)
        throws IOException
    {
    }

    public void processClientKeyExchange(InputStream input)
        throws IOException
    {
        // Key exchange implementation MUST support client key exchange
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public boolean requiresCertificateVerify()
    {
        return true;
    }
}
