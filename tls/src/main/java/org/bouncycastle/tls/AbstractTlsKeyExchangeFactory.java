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
    public TlsKeyExchange createDHKeyExchangeClient(int keyExchange) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHKeyExchangeServer(int keyExchange) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHanonKeyExchangeClient(int keyExchange, TlsDHConfigVerifier dhConfigVerifier)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, TlsDHConfigVerifier dhConfigVerifier)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHKeyExchangeClient(int keyExchange) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHKeyExchangeServer(int keyExchange) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHanonKeyExchangeClient(int keyExchange, TlsECConfigVerifier ecConfigVerifier)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange, TlsECConfigVerifier ecConfigVerifier)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, TlsPSKIdentity pskIdentity,
        TlsDHConfigVerifier dhConfigVerifier, TlsECConfigVerifier ecConfigVerifier) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, TlsPSKIdentityManager pskIdentityManager,
        TlsDHConfig dhConfig, TlsECConfig ecConfig) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createRSAKeyExchange() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, TlsSRPConfigVerifier srpConfigVerifier,
        byte[] identity, byte[] password) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, byte[] identity,
        TlsSRPLoginParameters loginParameters) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
