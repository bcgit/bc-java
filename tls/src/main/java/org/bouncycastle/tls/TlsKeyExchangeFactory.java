package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsDHConfig;

public interface TlsKeyExchangeFactory
{
    TlsKeyExchange createDHKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfigVerifier dhConfigVerifier) throws IOException;

    TlsKeyExchange createDHKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfig dhConfig)
        throws IOException;

    TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfigVerifier dhConfigVerifier) throws IOException;

    TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsDHConfig dhConfig) throws IOException;

    TlsKeyExchange createECDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException;

    TlsKeyExchange createECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException;

    public TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentity pskIdentity, TlsDHConfigVerifier dhConfigVerifier, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException;

    public TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentityManager pskIdentityManager, TlsDHConfig dhConfig, int[] namedCurves, short[] clientECPointFormats,
        short[] serverECPointFormats) throws IOException;

    TlsKeyExchange createRSAKeyExchange(Vector supportedSignatureAlgorithms) throws IOException;

    TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsSRPGroupVerifier groupVerifier, byte[] identity, byte[] password) throws IOException;

    TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms, byte[] identity,
        TlsSRPLoginParameters loginParameters) throws IOException;
}
