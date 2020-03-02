package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;

public abstract class DefaultTlsServer
    extends AbstractTlsServer
{
    private static final int[] DEFAULT_CIPHER_SUITES = new int[]
    {
        // TODO[tls13]
//        /*
//         * TLS 1.3
//         */
//        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
//        CipherSuite.TLS_AES_256_GCM_SHA384,
//        CipherSuite.TLS_AES_128_GCM_SHA256,

        /*
         * pre-TLS 1.3
         */
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
    };

    public DefaultTlsServer(TlsCrypto crypto)
    {
        super(crypto);
    }

    protected TlsCredentialedSigner getDSASignerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected TlsCredentialedSigner getECDSASignerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected TlsCredentialedSigner getRSASignerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    public TlsCredentials getCredentials()
        throws IOException
    {
        int keyExchangeAlgorithm = context.getSecurityParametersHandshake().getKeyExchangeAlgorithm();

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
            return getDSASignerCredentials();

        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.ECDH_anon:
            return null;

        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            return getECDSASignerCredentials();

        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return getRSASignerCredentials();

        case KeyExchangeAlgorithm.RSA:
            return getRSAEncryptionCredentials();

        default:
            /* Note: internal error here; selected a key exchange we don't implement! */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
