package org.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.params.DHParameters;

public class PSKTlsServer
    extends AbstractTlsServer
{
    protected TlsPSKIdentityManager pskIdentityManager;

    public PSKTlsServer(TlsPSKIdentityManager pskIdentityManager)
    {
        this(new DefaultTlsCipherFactory(), pskIdentityManager);
    }

    public PSKTlsServer(TlsCipherFactory cipherFactory, TlsPSKIdentityManager pskIdentityManager)
    {
        super(cipherFactory);
        this.pskIdentityManager = pskIdentityManager;
    }

    protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected DHParameters getDHParameters()
    {
        return DHStandardGroups.rfc3526_2048;
    }

    protected int[] getCipherSuites()
    {
        return new int[]
        {
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA
        };
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

    protected TlsKeyExchange createPSKKeyExchange(int keyExchange)
    {
        return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, null, pskIdentityManager,
            getDHParameters(), namedCurves, clientECPointFormats, serverECPointFormats);
    }
}
