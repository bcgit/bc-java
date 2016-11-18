package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;

public class PSKTlsClient
    extends AbstractTlsClient
{
    // TODO[tls] Perhaps not ideal to keep this in a writable array
    protected static final int[] BASE_CIPHER_SUITES = new int[]
    {
        CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA
    };

    protected TlsDHConfigVerifier dhConfigVerifier;
    protected TlsPSKIdentity pskIdentity;
    protected int[] supportedCipherSuites;

    // TODO[tls-ops] Need to restore a single-arg constructor here

    public PSKTlsClient(TlsCrypto crypto, TlsPSKIdentity pskIdentity)
    {
        this(crypto, new DefaultTlsKeyExchangeFactory(), new DefaultTlsDHConfigVerifier(), pskIdentity);
    }

    public PSKTlsClient(TlsCrypto crypto, TlsKeyExchangeFactory keyExchangeFactory, TlsDHConfigVerifier dhConfigVerifier,
        TlsPSKIdentity pskIdentity)
    {
        super(crypto, keyExchangeFactory);

        this.dhConfigVerifier = dhConfigVerifier;
        this.pskIdentity = pskIdentity;
        this.supportedCipherSuites = TlsUtils.getSupportedCipherSuites(crypto, BASE_CIPHER_SUITES);
    }

    public int[] getCipherSuites()
    {
        return Arrays.clone(supportedCipherSuites);
    }

    public TlsKeyExchange getKeyExchange() throws IOException
    {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_PSK:
            return createPSKKeyExchange(keyExchangeAlgorithm, dhConfigVerifier, null);

        case KeyExchangeAlgorithm.ECDHE_PSK:
            return createPSKKeyExchange(keyExchangeAlgorithm, null, createECConfigVerifier());

        case KeyExchangeAlgorithm.PSK:
        case KeyExchangeAlgorithm.RSA_PSK:
            return createPSKKeyExchange(keyExchangeAlgorithm, null, null);

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        /*
         * Note: This method is not called unless a server certificate is sent, which may be the
         * case e.g. for RSA_PSK key exchange.
         */
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected TlsKeyExchange createPSKKeyExchange(int keyExchange, TlsDHConfigVerifier dhConfigVerifier,
        TlsECConfigVerifier ecConfigVerifier) throws IOException
    {
        return keyExchangeFactory.createPSKKeyExchangeClient(keyExchange, supportedSignatureAlgorithms, pskIdentity,
            dhConfigVerifier, ecConfigVerifier, clientECPointFormats, serverECPointFormats);
    }
}
