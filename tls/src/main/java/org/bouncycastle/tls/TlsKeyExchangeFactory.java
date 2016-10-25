package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

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

    TlsKeyExchange createECDHKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, short[] clientECPointFormats, short[] serverECPointFormats)
        throws IOException;

    TlsKeyExchange createECDHKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfig ecConfig, short[] serverECPointFormats) throws IOException;

    TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, short[] clientECPointFormats, short[] serverECPointFormats)
        throws IOException;

    TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfig ecConfig, short[] serverECPointFormats) throws IOException;

    TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentity pskIdentity, TlsDHConfigVerifier dhConfigVerifier, TlsECConfigVerifier ecConfigVerifier,
        short[] clientECPointFormats, short[] serverECPointFormats) throws IOException;

    TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsPSKIdentityManager pskIdentityManager, TlsDHConfig dhConfig, TlsECConfig ecConfig,
        short[] serverECPointFormats) throws IOException;

    TlsKeyExchange createRSAKeyExchange(Vector supportedSignatureAlgorithms) throws IOException;

    TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsSRPConfigVerifier srpConfigVerifier, byte[] identity, byte[] password) throws IOException;

    TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, Vector supportedSignatureAlgorithms, byte[] identity,
        TlsSRPLoginParameters loginParameters) throws IOException;
}
