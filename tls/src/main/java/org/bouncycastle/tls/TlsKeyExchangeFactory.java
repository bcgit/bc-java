package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.crypto.params.DHParameters;

public interface TlsKeyExchangeFactory
{
    TlsKeyExchange createDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, DHParameters dhParameters)
        throws IOException;

    TlsKeyExchange createDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, DHParameters dhParameters)
        throws IOException;

    TlsKeyExchange createECDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException;

    TlsKeyExchange createECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException;

    TlsKeyExchange createPSKKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsPSKIdentity pskIdentity,
        TlsPSKIdentityManager pskIdentityManager, DHParameters dhParameters, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException;

    TlsKeyExchange createRSAKeyExchange(Vector supportedSignatureAlgorithms) throws IOException;

    TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms, TlsSRPGroupVerifier groupVerifier,
        byte[] identity, byte[] password) throws IOException;

    TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms, byte[] identity,
        TlsSRPLoginParameters loginParameters) throws IOException;
}
