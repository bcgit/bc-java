package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;

public class PSKTlsClient
    extends AbstractTlsClient
{
    private static final int[] DEFAULT_CIPHER_SUITES = new int[]
    {
        CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA
    };

    protected TlsPSKIdentity pskIdentity;

    public PSKTlsClient(TlsCrypto crypto, byte[] identity, byte[] psk)
    {
        this(crypto, new BasicTlsPSKIdentity(identity, psk));
    }

    public PSKTlsClient(TlsCrypto crypto, TlsPSKIdentity pskIdentity)
    {
        super(crypto);

        this.pskIdentity = pskIdentity;
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv12.downTo(ProtocolVersion.TLSv10);
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    public TlsPSKIdentity getPSKIdentity()
    {
        return pskIdentity;
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        /*
         * Note: This method is not called unless a server certificate is sent, which may be the
         * case e.g. for RSA_PSK key exchange.
         */
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
