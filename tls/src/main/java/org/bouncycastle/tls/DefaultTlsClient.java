package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCrypto;

public abstract class DefaultTlsClient
    extends AbstractTlsClient
{
    private static final int[] DEFAULT_CIPHER_SUITES = new int[]
    {
        // TODO[tls13]
//        /*
//         * TLS 1.3
//         */
//        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
//        CipherSuite.TLS_AES_128_GCM_SHA256,

        /*
         * pre-TLS 1.3
         */
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
    };

    public DefaultTlsClient(TlsCrypto crypto)
    {
        super(crypto);
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }
}
