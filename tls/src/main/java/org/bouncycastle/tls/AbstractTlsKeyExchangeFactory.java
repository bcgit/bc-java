package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

/**
 * Base class for supporting a TLS key exchange factory implementation.
 */
public class AbstractTlsKeyExchangeFactory
    implements TlsKeyExchangeFactory
{
    public TlsKeyExchange createDHKeyExchange(int keyExchange) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHanonKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHKeyExchange(int keyExchange) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHanonKeyExchangeClient(int keyExchange) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, TlsPSKIdentity pskIdentity,
        TlsDHGroupVerifier dhGroupVerifier) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, TlsPSKIdentityManager pskIdentityManager,
        TlsDHConfig dhConfig, TlsECConfig ecConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createRSAKeyExchange(int keyExchange) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, TlsSRPIdentity srpIdentity,
        TlsSRPConfigVerifier srpConfigVerifier) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, TlsSRPLoginParameters loginParameters)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
