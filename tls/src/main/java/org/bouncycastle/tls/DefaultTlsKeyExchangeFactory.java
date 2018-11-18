package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

public class DefaultTlsKeyExchangeFactory
    extends AbstractTlsKeyExchangeFactory
{
    public TlsKeyExchange createDHKeyExchangeClient(int keyExchange) throws IOException
    {
        return new TlsDHKeyExchange(keyExchange);
    }

    public TlsKeyExchange createDHKeyExchangeServer(int keyExchange) throws IOException
    {
        return new TlsDHKeyExchange(keyExchange);
    }

    public TlsKeyExchange createDHanonKeyExchangeClient(int keyExchange, TlsDHConfigVerifier dhConfigVerifier)
        throws IOException
    {
        return new TlsDHanonKeyExchange(keyExchange, dhConfigVerifier);
    }

    public TlsKeyExchange createDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException
    {
        return new TlsDHanonKeyExchange(keyExchange, dhConfig);
    }

    public TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, TlsDHConfigVerifier dhConfigVerifier)
        throws IOException
    {
        return new TlsDHEKeyExchange(keyExchange, dhConfigVerifier);
    }

    public TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException
    {
        return new TlsDHEKeyExchange(keyExchange, dhConfig);
    }

    public TlsKeyExchange createECDHKeyExchangeClient(int keyExchange) throws IOException
    {
        return new TlsECDHKeyExchange(keyExchange);
    }

    public TlsKeyExchange createECDHKeyExchangeServer(int keyExchange) throws IOException
    {
        return new TlsECDHKeyExchange(keyExchange);
    }

    public TlsKeyExchange createECDHanonKeyExchangeClient(int keyExchange, TlsECConfigVerifier ecConfigVerifier)
        throws IOException
    {
        return new TlsECDHanonKeyExchange(keyExchange, ecConfigVerifier);
    }

    public TlsKeyExchange createECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException
    {
        return new TlsECDHanonKeyExchange(keyExchange, ecConfig);
    }

    public TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange, TlsECConfigVerifier ecConfigVerifier)
        throws IOException
    {
        return new TlsECDHEKeyExchange(keyExchange, ecConfigVerifier);
    }

    public TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException
    {
        return new TlsECDHEKeyExchange(keyExchange, ecConfig);
    }

    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, TlsPSKIdentity pskIdentity,
        TlsDHConfigVerifier dhConfigVerifier, TlsECConfigVerifier ecConfigVerifier) throws IOException
    {
        return new TlsPSKKeyExchange(keyExchange, pskIdentity, dhConfigVerifier, ecConfigVerifier);
    }

    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, TlsPSKIdentityManager pskIdentityManager,
        TlsDHConfig dhConfig, TlsECConfig ecConfig) throws IOException
    {
        return new TlsPSKKeyExchange(keyExchange, null, pskIdentityManager, dhConfig, ecConfig);
    }

    public TlsKeyExchange createRSAKeyExchange() throws IOException
    {
        return new TlsRSAKeyExchange();
    }

    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, TlsSRPConfigVerifier srpConfigVerifier,
        byte[] identity, byte[] password) throws IOException
    {
        return new TlsSRPKeyExchange(keyExchange, srpConfigVerifier, identity, password);
    }

    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, byte[] identity,
        TlsSRPLoginParameters loginParameters) throws IOException
    {
        return new TlsSRPKeyExchange(keyExchange, identity, loginParameters);
    }
}
