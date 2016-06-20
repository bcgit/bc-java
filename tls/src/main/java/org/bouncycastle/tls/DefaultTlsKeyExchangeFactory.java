package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsDHConfig;

public class DefaultTlsKeyExchangeFactory extends AbstractTlsKeyExchangeFactory
{
    public TlsKeyExchange createDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfig dhConfig) throws IOException
    {
        return new TlsDHKeyExchange(keyExchange, supportedSignatureAlgorithms, dhConfig);
    }

    public TlsKeyExchange createDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfig dhConfig) throws IOException
    {
        return new TlsDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, dhConfig);
    }

    public TlsKeyExchange createECDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        return new TlsECDHKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,
            serverECPointFormats);
    }

    public TlsKeyExchange createECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        return new TlsECDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,
            serverECPointFormats);
    }

    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentity pskIdentity, int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats)
            throws IOException
    {
        return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, pskIdentity, null, null,
            namedCurves, clientECPointFormats, serverECPointFormats);
    }

    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentityManager pskIdentityManager, TlsDHConfig dhConfig,
        int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, null, pskIdentityManager,
            dhConfig, namedCurves, clientECPointFormats, serverECPointFormats);
    }

    public TlsKeyExchange createRSAKeyExchange(Vector supportedSignatureAlgorithms) throws IOException
    {
        return new TlsRSAKeyExchange(supportedSignatureAlgorithms);
    }

    public TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsSRPGroupVerifier groupVerifier, byte[] identity, byte[] password) throws IOException
    {
        return new TlsSRPKeyExchange(keyExchange, supportedSignatureAlgorithms, groupVerifier, identity, password);
    }

    public TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        byte[] identity, TlsSRPLoginParameters loginParameters) throws IOException
    {
        return new TlsSRPKeyExchange(keyExchange, supportedSignatureAlgorithms, identity, loginParameters);
    }
}
