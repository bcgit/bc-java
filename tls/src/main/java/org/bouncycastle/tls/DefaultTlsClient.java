package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;

public abstract class DefaultTlsClient
    extends AbstractTlsClient
{
    private static final int[] DEFAULT_CIPHER_SUITES = new int[]
    {
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

    protected TlsDHConfigVerifier dhConfigVerifier;

    public DefaultTlsClient(TlsCrypto crypto)
    {
        this(crypto, new DefaultTlsKeyExchangeFactory(), new DefaultTlsDHConfigVerifier());
    }

    public DefaultTlsClient(TlsCrypto crypto, TlsKeyExchangeFactory keyExchangeFactory, TlsDHConfigVerifier dhConfigVerifier)
    {
        super(crypto, keyExchangeFactory);
        this.dhConfigVerifier = dhConfigVerifier;
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(context.getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    public TlsKeyExchange getKeyExchange()
        throws IOException
    {
        int selectedCipherSuite = context.getSecurityParametersHandshake().getCipherSuite();
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
            return createDHanonKeyExchange(keyExchangeAlgorithm);

        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
            return createDHKeyExchange(keyExchangeAlgorithm);

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
            return createDHEKeyExchange(keyExchangeAlgorithm);

        case KeyExchangeAlgorithm.ECDH_anon:
            return createECDHanonKeyExchange(keyExchangeAlgorithm);

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
        return keyExchangeFactory.createDHKeyExchangeClient(keyExchange);
    }

    protected TlsKeyExchange createDHanonKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createDHanonKeyExchangeClient(keyExchange, dhConfigVerifier);
    }

    protected TlsKeyExchange createDHEKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createDHEKeyExchangeClient(keyExchange, dhConfigVerifier);
    }

    protected TlsKeyExchange createECDHKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createECDHKeyExchangeClient(keyExchange);
    }

    protected TlsKeyExchange createECDHanonKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createECDHanonKeyExchangeClient(keyExchange, createECConfigVerifier());
    }

    protected TlsKeyExchange createECDHEKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createECDHEKeyExchangeClient(keyExchange, createECConfigVerifier());
    }

    protected TlsKeyExchange createRSAKeyExchange() throws IOException
    {
        return keyExchangeFactory.createRSAKeyExchange();
    }
}
