package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

public abstract class SRPTlsServer extends AbstractTlsServer
{
    
    /*
     * NOTE: The RSA and DSS cipher suites have NOT been tested. They may or may not work.
     * 
     * RFC 5054 section 2.7:
     * Implementations conforming to this specification MUST implement the
     * TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA cipher suite, SHOULD implement the
     * TLS_SRP_SHA_WITH_AES_128_CBC_SHA and TLS_SRP_SHA_WITH_AES_256_CBC_SHA
     * cipher suites, and MAY implement the remaining cipher suites.
     */
    protected static final int[] DEFAULT_CIPHER_SUITES = new int[]
            {
                CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA
            };

    protected byte[] clientSrpIdentity;
    
    public TlsCredentials getCredentials() throws IOException
    {
        // RSA and DSS cipher suites are not supported
        return null;
    }

    public TlsKeyExchange getKeyExchange() throws IOException
    {
        switch (selectedCipherSuite)
        {
        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            return createSRPKeyExchange(KeyExchangeAlgorithm.SRP);

        /*
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
            return createSRPKeyExchange(KeyExchangeAlgorithm.SRP_RSA);

        case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
            return createSRPKeyExchange(KeyExchangeAlgorithm.SRP_DSS);
        */

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsCipher getCipher() throws IOException
    {
        switch (selectedCipherSuite)
        {
        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
        //case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
        //case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm._3DES_EDE_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
        //case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
        //case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
        //case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
        //case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha1);

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    @Override
    protected int[] getCipherSuites()
    {
        return DEFAULT_CIPHER_SUITES;
    }
    
    @Override
    public void processClientExtensions(Hashtable clientExtensions)
            throws IOException
    {
        super.processClientExtensions(clientExtensions);
        clientSrpIdentity = TlsSRPUtils.getSRPExtension(clientExtensions);
    }

    protected TlsKeyExchange createSRPKeyExchange(int keyExchange)
    {
        SRPTlsParameters params = getClientParameters();
        return new TlsSRPKeyExchange(
                keyExchange,
                supportedSignatureAlgorithms,
                params.getVerifier(),
                params.getSalt(),
                params.getPrime(),
                params.getGenerator());
    }

    /**
     * Retrieves the client's TLS parameters based on the clientSrpIdentity.
     * The server should store all of these parameters and read them as
     * necessary, per RFC 5054 section 2.5.3.
     * @return
     */
    protected abstract SRPTlsParameters getClientParameters();
    
}
