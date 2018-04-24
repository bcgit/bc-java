package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;

public abstract class DefaultTlsClient
    extends AbstractTlsClient
{
    // TODO[tls] Perhaps not ideal to keep this in a writable array
    protected static final int[] BASE_CIPHER_SUITES = new int[]
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
    protected int[] supportedCipherSuites;

    // TODO[tls-ops] Need to restore a default constructor here

    public DefaultTlsClient(TlsCrypto crypto)
    {
        this(crypto, new DefaultTlsKeyExchangeFactory(), new DefaultTlsDHConfigVerifier());
    }

    public DefaultTlsClient(TlsCrypto crypto, TlsKeyExchangeFactory keyExchangeFactory, TlsDHConfigVerifier dhConfigVerifier)
    {
        super(crypto, keyExchangeFactory);
        this.dhConfigVerifier = dhConfigVerifier;
        this.supportedCipherSuites = TlsUtils.getSupportedCipherSuites(crypto, BASE_CIPHER_SUITES);
    }

    public int[] getCipherSuites()
    {
        return Arrays.clone(supportedCipherSuites);
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
        return keyExchangeFactory.createDHKeyExchangeClient(keyExchange, supportedSignatureAlgorithms, dhConfigVerifier);
    }

    protected TlsKeyExchange createDHEKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createDHEKeyExchangeClient(keyExchange, supportedSignatureAlgorithms, dhConfigVerifier);
    }

    protected TlsKeyExchange createECDHKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createECDHKeyExchangeClient(keyExchange, supportedSignatureAlgorithms,
            createECConfigVerifier(), clientECPointFormats, serverECPointFormats);
    }

    protected TlsKeyExchange createECDHEKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createECDHEKeyExchangeClient(keyExchange, supportedSignatureAlgorithms,
            createECConfigVerifier(), clientECPointFormats, serverECPointFormats);
    }

    protected TlsKeyExchange createRSAKeyExchange() throws IOException
    {
        return keyExchangeFactory.createRSAKeyExchange(supportedSignatureAlgorithms);
    }
}
