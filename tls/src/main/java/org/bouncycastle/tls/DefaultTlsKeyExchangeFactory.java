package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

public class DefaultTlsKeyExchangeFactory
    extends AbstractTlsKeyExchangeFactory
{
    public TlsKeyExchange createDHKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms)
        throws IOException
    {
        return new TlsDHKeyExchange(keyExchange, supportedSignatureAlgorithms);
    }

    public TlsKeyExchange createDHKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms)
        throws IOException
    {
        return new TlsDHKeyExchange(keyExchange, supportedSignatureAlgorithms);
    }

    public TlsKeyExchange createDHanonKeyExchangeClient(int keyExchange, TlsDHConfigVerifier dhConfigVerifier)
        throws IOException
    {
        return new TlsDHanonKeyExchange(keyExchange, dhConfigVerifier);
    }

    public TlsKeyExchange createDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig)
        throws IOException
    {
        return new TlsDHanonKeyExchange(keyExchange, dhConfig);
    }

    public TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfigVerifier dhConfigVerifier) throws IOException
    {
        return new TlsDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, dhConfigVerifier);
    }

    public TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfig dhConfig) throws IOException
    {
        return new TlsDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, dhConfig);
    }

    public TlsKeyExchange createECDHKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms)
        throws IOException
    {
        return new TlsECDHKeyExchange(keyExchange, supportedSignatureAlgorithms);
    }

    public TlsKeyExchange createECDHKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms)
        throws IOException
    {
        return new TlsECDHKeyExchange(keyExchange, supportedSignatureAlgorithms);
    }

    public TlsKeyExchange createECDHanonKeyExchangeClient(int keyExchange, TlsECConfigVerifier ecConfigVerifier,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        return new TlsECDHanonKeyExchange(keyExchange, ecConfigVerifier, clientECPointFormats, serverECPointFormats);
    }

    public TlsKeyExchange createECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig,
        short[] serverECPointFormats) throws IOException
    {
        return new TlsECDHanonKeyExchange(keyExchange, ecConfig, serverECPointFormats);
    }

    public TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, short[] clientECPointFormats, short[] serverECPointFormats)
        throws IOException
    {
        return new TlsECDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, ecConfigVerifier,
            clientECPointFormats, serverECPointFormats);
    }

    public TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfig ecConfig, short[] serverECPointFormats) throws IOException
    {
        return new TlsECDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, ecConfig, serverECPointFormats);
    }

    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentity pskIdentity, TlsDHConfigVerifier dhConfigVerifier, TlsECConfigVerifier ecConfigVerifier,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, pskIdentity, dhConfigVerifier,
            ecConfigVerifier, clientECPointFormats, serverECPointFormats);
    }

    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentityManager pskIdentityManager, TlsDHConfig dhConfig, TlsECConfig ecConfig,
        short[] serverECPointFormats) throws IOException
    {
        return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, null, pskIdentityManager, dhConfig,
            ecConfig, serverECPointFormats);
    }

    public TlsKeyExchange createRSAKeyExchange(Vector supportedSignatureAlgorithms) throws IOException
    {
        return new TlsRSAKeyExchange(supportedSignatureAlgorithms);
    }

    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsSRPConfigVerifier srpConfigVerifier, byte[] identity, byte[] password) throws IOException
    {
        return new TlsSRPKeyExchange(keyExchange, supportedSignatureAlgorithms, srpConfigVerifier, identity, password);
    }

    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        byte[] identity, TlsSRPLoginParameters loginParameters) throws IOException
    {
        return new TlsSRPKeyExchange(keyExchange, supportedSignatureAlgorithms, identity, loginParameters);
    }
}
