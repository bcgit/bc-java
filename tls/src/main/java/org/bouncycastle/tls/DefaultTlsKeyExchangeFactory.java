package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.crypto.params.DHParameters;

public class DefaultTlsKeyExchangeFactory extends AbstractTlsKeyExchangeFactory
{
    public TlsKeyExchange createDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        DHParameters dhParameters) throws IOException
    {
        return new TlsDHKeyExchange(keyExchange, supportedSignatureAlgorithms, dhParameters);
    }

    public TlsKeyExchange createDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        DHParameters dhParameters) throws IOException
    {
        return new TlsDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, dhParameters);
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

    public TlsKeyExchange createPSKKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentity pskIdentity, TlsPSKIdentityManager pskIdentityManager, DHParameters dhParameters,
        int[] namedCurves, short[] clientECPointFormats, short[] serverECPointFormats) throws IOException
    {
        return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, pskIdentity, pskIdentityManager,
            dhParameters, namedCurves, clientECPointFormats, serverECPointFormats);
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
