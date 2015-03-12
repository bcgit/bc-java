package org.bouncycastle.crypto.tls;

import java.io.IOException;

public class PSKTlsClient
    extends AbstractTlsClient
{
    protected TlsPSKIdentity pskIdentity;

    public PSKTlsClient(TlsPSKIdentity pskIdentity)
    {
        this(new DefaultTlsCipherFactory(), pskIdentity);
    }

    public PSKTlsClient(TlsCipherFactory cipherFactory, TlsPSKIdentity pskIdentity)
    {
        super(cipherFactory);
        this.pskIdentity = pskIdentity;
    }

    public int[] getCipherSuites()
    {
        return new int[]
        {
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA
        };
    }

    public TlsKeyExchange getKeyExchange() throws IOException
    {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_PSK:
        case KeyExchangeAlgorithm.ECDHE_PSK:
        case KeyExchangeAlgorithm.PSK:
        case KeyExchangeAlgorithm.RSA_PSK:
            return createPSKKeyExchange(keyExchangeAlgorithm);

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

    protected TlsKeyExchange createPSKKeyExchange(int keyExchange)
    {
        return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, pskIdentity, null, null, namedCurves,
            clientECPointFormats, serverECPointFormats);
    }
}
