package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;

/**
 * Interface for a key exchange factory offering a variety of specific algorithms.
 */
public interface TlsKeyExchangeFactory
{
    TlsKeyExchange createDHKeyExchange(int keyExchange) throws IOException;

    TlsKeyExchange createDHanonKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
        throws IOException;

    TlsKeyExchange createDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException;

    TlsKeyExchange createDHEKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier) throws IOException;

    TlsKeyExchange createDHEKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig) throws IOException;

    TlsKeyExchange createECDHKeyExchange(int keyExchange) throws IOException;

    TlsKeyExchange createECDHanonKeyExchangeClient(int keyExchange) throws IOException;

    TlsKeyExchange createECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException;

    TlsKeyExchange createECDHEKeyExchangeClient(int keyExchange) throws IOException;

    TlsKeyExchange createECDHEKeyExchangeServer(int keyExchange, TlsECConfig ecConfig) throws IOException;

    TlsKeyExchange createPSKKeyExchangeClient(int keyExchange, TlsPSKIdentity pskIdentity,
        TlsDHGroupVerifier dhGroupVerifier) throws IOException;

    TlsKeyExchange createPSKKeyExchangeServer(int keyExchange, TlsPSKIdentityManager pskIdentityManager,
        TlsDHConfig dhConfig, TlsECConfig ecConfig) throws IOException;

    TlsKeyExchange createRSAKeyExchange(int keyExchange) throws IOException;

    TlsKeyExchange createSRPKeyExchangeClient(int keyExchange, TlsSRPIdentity srpIdentity,
        TlsSRPConfigVerifier srpConfigVerifier) throws IOException;

    TlsKeyExchange createSRPKeyExchangeServer(int keyExchange, TlsSRPLoginParameters loginParameters)
        throws IOException;

    /**
     * GMSSL ECC_SM4_SM3 suite key exchange
     *
     * @param keyExchange enum type
     * @return SM2 key exchange object
     * @throws IOException err
     */
    TlsKeyExchange createSM2KeyExchange(int keyExchange)
            throws IOException;
}
