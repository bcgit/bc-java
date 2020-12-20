package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;

public class PSKTlsServer
    extends AbstractTlsServer
{
    private static final int[] DEFAULT_CIPHER_SUITES = new int[]
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

    public PSKTlsServer(TlsCrypto crypto, TlsPSKIdentityManager pskIdentityManager)
    {
        super(crypto);

        this.pskIdentityManager = pskIdentityManager;
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv12.downTo(ProtocolVersion.TLSv10);
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    /** @deprecated Unused; will be removed */
    public ProtocolVersion getMaximumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        int keyExchangeAlgorithm = context.getSecurityParametersHandshake().getKeyExchangeAlgorithm();

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

    public TlsPSKIdentityManager getPSKIdentityManager()
    {
        return pskIdentityManager;
    }
}
