package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;

public abstract class DefaultTlsServer
    extends AbstractTlsServer
{
    // TODO[tls] Perhaps not ideal to keep this in a writable array
    protected static final int[] BASE_CIPHER_SUITES = new int[]
    {
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

    // TODO[tls-ops] Need to restore a default constructor here

    protected int[] supportedCipherSuites;

    public DefaultTlsServer(TlsCrypto crypto)
    {
        super(crypto);
        this.supportedCipherSuites = TlsUtils.getSupportedCipherSuites(crypto, BASE_CIPHER_SUITES);
    }

    public DefaultTlsServer(TlsCrypto crypto, TlsKeyExchangeFactory keyExchangeFactory)
    {
        super(crypto, keyExchangeFactory);
        this.supportedCipherSuites = TlsUtils.getSupportedCipherSuites(crypto, BASE_CIPHER_SUITES);
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

    protected int[] getCipherSuites()
    {
        return Arrays.clone(supportedCipherSuites);
    }

    public TlsCredentials getCredentials()
        throws IOException
    {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

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

    public TlsKeyExchange getKeyExchange()
        throws IOException
    {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
            return createDHKeyExchange(keyExchangeAlgorithm);

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
            return createDHEKeyExchange(keyExchangeAlgorithm);

        case KeyExchangeAlgorithm.ECDH_anon:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
            return createECDHKeyExchange(keyExchangeAlgorithm);

        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return createECDHEKeyExchange(keyExchangeAlgorithm);

        case KeyExchangeAlgorithm.RSA:
            return createRSAKeyExchange();

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsKeyExchange createDHKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createDHKeyExchangeServer(keyExchange, supportedSignatureAlgorithms, selectDHConfig());
    }

    protected TlsKeyExchange createDHEKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createDHEKeyExchangeServer(keyExchange, supportedSignatureAlgorithms, selectDHConfig());
    }

    protected TlsKeyExchange createECDHKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createECDHKeyExchangeServer(keyExchange, supportedSignatureAlgorithms, selectECConfig(),
            serverECPointFormats);
    }

    protected TlsKeyExchange createECDHEKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createECDHEKeyExchangeServer(keyExchange, supportedSignatureAlgorithms, selectECConfig(),
            serverECPointFormats);
    }

    protected TlsKeyExchange createRSAKeyExchange() throws IOException
    {
        return keyExchangeFactory.createRSAKeyExchange(supportedSignatureAlgorithms);
    }
}
