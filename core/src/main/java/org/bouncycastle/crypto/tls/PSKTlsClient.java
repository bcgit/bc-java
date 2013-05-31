package org.bouncycastle.crypto.tls;

import java.io.IOException;

public abstract class PSKTlsClient
    extends AbstractTlsClient
{
    protected TlsPSKIdentity pskIdentity;

    public PSKTlsClient(TlsPSKIdentity pskIdentity)
    {
        super();
        this.pskIdentity = pskIdentity;
    }

    public PSKTlsClient(TlsCipherFactory cipherFactory, TlsPSKIdentity pskIdentity)
    {
        super(cipherFactory);
        this.pskIdentity = pskIdentity;
    }

    public int[] getCipherSuites()
    {
        return new int[]{CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA,
            CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA,
            CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_PSK_WITH_RC4_128_SHA,};
    }

    public TlsKeyExchange getKeyExchange()
        throws IOException
    {

        switch (selectedCipherSuite)
        {
        case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
            return createPSKKeyExchange(KeyExchangeAlgorithm.PSK);

        case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
            return createPSKKeyExchange(KeyExchangeAlgorithm.RSA_PSK);

        case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
            return createPSKKeyExchange(KeyExchangeAlgorithm.DHE_PSK);

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsCipher getCipher()
        throws IOException
    {

        switch (selectedCipherSuite)
        {
        case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm._3DES_EDE_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.RC4_128, MACAlgorithm.hmac_sha1);

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
        return new TlsPSKKeyExchange(keyExchange, supportedSignatureAlgorithms, pskIdentity);
    }
}
