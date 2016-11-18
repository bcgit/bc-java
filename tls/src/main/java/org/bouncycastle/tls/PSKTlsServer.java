package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Arrays;

public class PSKTlsServer
    extends AbstractTlsServer
{
    // TODO[tls] Perhaps not ideal to keep this in a writable array
    public static final int[] BASE_CIPHER_SUITES = new int[]
    {
        CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
        CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
        CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA
    };

    protected TlsPSKIdentityManager pskIdentityManager;
    protected int[] supportedCipherSuites;

    // TODO[tls-ops] Need to restore a single-arg constructor here

    public PSKTlsServer(TlsCrypto crypto, TlsPSKIdentityManager pskIdentityManager)
    {
        this(crypto, new DefaultTlsKeyExchangeFactory(), pskIdentityManager);
    }

    public PSKTlsServer(TlsCrypto crypto, TlsKeyExchangeFactory keyExchangeFactory, TlsPSKIdentityManager pskIdentityManager)
    {
        super(crypto, keyExchangeFactory);
        this.pskIdentityManager = pskIdentityManager;
        this.supportedCipherSuites = TlsUtils.getSupportedCipherSuites(crypto, BASE_CIPHER_SUITES);
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected int[] getCipherSuites()
    {
        return Arrays.clone(supportedCipherSuites);
    }

    public TlsCredentials getCredentials() throws IOException
    {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_PSK:
        case KeyExchangeAlgorithm.ECDHE_PSK:
        case KeyExchangeAlgorithm.PSK:
            return null;

        case KeyExchangeAlgorithm.RSA_PSK:
            return getRSAEncryptionCredentials();

        default:
            /* Note: internal error here; selected a key exchange we don't implement! */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsKeyExchange getKeyExchange() throws IOException
    {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_PSK:
            return createPSKKeyExchange(keyExchangeAlgorithm, selectDHConfig(), null);

        case KeyExchangeAlgorithm.ECDHE_PSK:
            return createPSKKeyExchange(keyExchangeAlgorithm, null, selectECConfig());

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

    protected TlsKeyExchange createPSKKeyExchange(int keyExchange, TlsDHConfig dhConfig, TlsECConfig ecConfig) throws IOException
    {
        return keyExchangeFactory.createPSKKeyExchangeServer(keyExchange, supportedSignatureAlgorithms, pskIdentityManager,
            dhConfig, ecConfig, serverECPointFormats);
    }
}
