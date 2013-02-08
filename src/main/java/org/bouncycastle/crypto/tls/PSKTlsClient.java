package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

public abstract class PSKTlsClient implements TlsClient
{
    protected TlsCipherFactory cipherFactory;
    protected TlsPSKIdentity pskIdentity;

    protected TlsClientContext context;

    protected int selectedCompressionMethod;
    protected int selectedCipherSuite;

    public PSKTlsClient(TlsPSKIdentity pskIdentity)
    {
        this(new DefaultTlsCipherFactory(), pskIdentity);
    }

    public PSKTlsClient(TlsCipherFactory cipherFactory, TlsPSKIdentity pskIdentity)
    {
        this.cipherFactory = cipherFactory;
        this.pskIdentity = pskIdentity;
    }

    public ProtocolVersion getClientVersion()
    {
        return ProtocolVersion.TLSv10;
    }

    public void init(TlsClientContext context)
    {
        this.context = context;
    }

    public int[] getCipherSuites()
    {
        return new int[] {
            CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA,
            CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA,
            CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_PSK_WITH_RC4_128_SHA,
        };
    }

    public Hashtable getClientExtensions() throws IOException
    {
        return null;
    }

    public short[] getCompressionMethods()
    {
        return new short[] { CompressionMethod.NULL };
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        if (!ProtocolVersion.TLSv10.equals(serverVersion))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    public void notifySessionID(byte[] sessionID)
    {
        // Currently ignored 
    }

    public void notifySelectedCipherSuite(int selectedCipherSuite)
    {
        this.selectedCipherSuite = selectedCipherSuite;
    }

    public void notifySelectedCompressionMethod(short selectedCompressionMethod)
    {
        this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
    {
        if (!secureRenegotiation)
        {
            /*
             * RFC 5746 3.4. If the extension is not present, the server does not support
             * secure renegotiation; set secure_renegotiation flag to FALSE. In this case,
             * some clients may want to terminate the handshake instead of continuing; see
             * Section 4.1 for discussion.
             */
//            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    public void processServerExtensions(Hashtable serverExtensions)
    {
    }

    public TlsKeyExchange getKeyExchange() throws IOException
    {
        switch (selectedCipherSuite)
        {
            case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
                return createPSKKeyExchange(KeyExchangeAlgorithm.PSK);

            case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
                return createPSKKeyExchange(KeyExchangeAlgorithm.RSA_PSK);

            case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
                return createPSKKeyExchange(KeyExchangeAlgorithm.DHE_PSK);

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected cipher suite was in the list of client-offered cipher
                 * suites, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsCompression getCompression() throws IOException
    {
        switch (selectedCompressionMethod)
        {
            case CompressionMethod.NULL:
                return new TlsNullCompression();

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected compression method was in the list of client-offered compression
                 * methods, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsCipher getCipher() throws IOException
    {
        switch (selectedCipherSuite)
        {
            case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
                return cipherFactory.createCipher(context, EncryptionAlgorithm._3DES_EDE_CBC,
                    DigestAlgorithm.SHA);

            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
                return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_128_CBC,
                    DigestAlgorithm.SHA);

            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
                return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_256_CBC,
                    DigestAlgorithm.SHA);

            case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
                return cipherFactory.createCipher(context, EncryptionAlgorithm.RC4_128,
                    DigestAlgorithm.SHA);

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected cipher suite was in the list of client-offered cipher
                 * suites, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsKeyExchange createPSKKeyExchange(int keyExchange)
    {
        return new TlsPSKKeyExchange(context, keyExchange, pskIdentity);
    }
}
