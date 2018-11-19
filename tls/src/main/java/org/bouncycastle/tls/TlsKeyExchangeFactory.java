package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

/**
 * Interface for a key exchange factory offering a variety of specific algorithms.
 */
public interface TlsKeyExchangeFactory
{
    TlsKeyExchange createDHKeyExchangeClient(int keyExchange) throws IOException;

    TlsKeyExchange createDHKeyExchangeServer(int keyExchange) throws IOException;

    TlsKeyExchange createDHanonKeyExchangeClient(int keyExchange, TlsDHConfigVerifier dhConfigVerifier)
        throws IOException;

    TlsKeyExchange createDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException;

    TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, TlsDHConfigVerifier dhConfigVerifier) throws IOException;

    TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException;

    TlsKeyExchange createECDHKeyExchangeClient(int keyExchange) throws IOException;

    TlsKeyExchange createECDHKeyExchangeServer(int keyExchange) throws IOException;

    TlsKeyExchange createECDHanonKeyExchangeClient(int keyExchange, TlsECConfigVerifier ecConfigVerifier)
        throws IOException;

    TlsKeyExchange createECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException;

    TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange, TlsECConfigVerifier ecConfigVerifier)
        throws IOException;

    TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException;

    TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, TlsPSKIdentity pskIdentity,
        TlsDHConfigVerifier dhConfigVerifier, TlsECConfigVerifier ecConfigVerifier) throws IOException;

    TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, TlsPSKIdentityManager pskIdentityManager,
        TlsDHConfig dhConfig, TlsECConfig ecConfig) throws IOException;

    TlsKeyExchange createRSAKeyExchange(int keyExchange) throws IOException;

    TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, TlsSRPIdentity srpIdentity,
        TlsSRPConfigVerifier srpConfigVerifier) throws IOException;

    TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, TlsSRPLoginParameters loginParameters)
        throws IOException;
}
