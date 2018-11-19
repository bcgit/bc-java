package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

public class DefaultTlsKeyExchangeFactory
    extends AbstractTlsKeyExchangeFactory
{
    public TlsKeyExchange createDHKeyExchange(int keyExchange) throws IOException
    {
        return new TlsDHKeyExchange(keyExchange);
    }

    public TlsKeyExchange createDHanonKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
        throws IOException
    {
        return new TlsDHanonKeyExchange(keyExchange, dhGroupVerifier);
    }

    public TlsKeyExchange createDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException
    {
        return new TlsDHanonKeyExchange(keyExchange, dhConfig);
    }

    public TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
        throws IOException
    {
        return new TlsDHEKeyExchange(keyExchange, dhGroupVerifier);
    }

    public TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException
    {
        return new TlsDHEKeyExchange(keyExchange, dhConfig);
    }

    public TlsKeyExchange createECDHKeyExchange(int keyExchange) throws IOException
    {
        return new TlsECDHKeyExchange(keyExchange);
    }

    public TlsKeyExchange createECDHanonKeyExchangeClient(int keyExchange) throws IOException
    {
        return new TlsECDHanonKeyExchange(keyExchange);
    }

    public TlsKeyExchange createECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException
    {
        return new TlsECDHanonKeyExchange(keyExchange, ecConfig);
    }

    public TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange)
        throws IOException
    {
        return new TlsECDHEKeyExchange(keyExchange);
    }

    public TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException
    {
        return new TlsECDHEKeyExchange(keyExchange, ecConfig);
    }

    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, TlsPSKIdentity pskIdentity,
        TlsDHGroupVerifier dhGroupVerifier) throws IOException
    {
        return new TlsPSKKeyExchange(keyExchange, pskIdentity, dhGroupVerifier);
    }

    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, TlsPSKIdentityManager pskIdentityManager,
        TlsDHConfig dhConfig, TlsECConfig ecConfig) throws IOException
    {
        return new TlsPSKKeyExchange(keyExchange, pskIdentityManager, dhConfig, ecConfig);
    }

    public TlsKeyExchange createRSAKeyExchange(int keyExchange) throws IOException
    {
        return new TlsRSAKeyExchange(keyExchange);
    }

    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, TlsSRPIdentity srpIdentity,
        TlsSRPConfigVerifier srpConfigVerifier) throws IOException
    {
        return new TlsSRPKeyExchange(keyExchange, srpIdentity, srpConfigVerifier);
    }

    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, TlsSRPLoginParameters loginParameters)
        throws IOException
    {
        return new TlsSRPKeyExchange(keyExchange, loginParameters);
    }
}
