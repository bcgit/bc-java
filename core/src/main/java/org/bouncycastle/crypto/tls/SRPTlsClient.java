package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.util.Arrays;

public abstract class SRPTlsClient
    extends AbstractTlsClient
{
    /**
     * @deprecated use TlsSRPUtils.EXT_SRP instead
     */
    public static final Integer EXT_SRP = TlsSRPUtils.EXT_SRP;

    protected byte[] identity;
    protected byte[] password;
    protected SRPPrimeVerifier primeVerifier;

    /**
     * Create a client with the given identity and password, and a
     * default cipher factory and prime verifier.
     * See {@link #SRPTlsClient(TlsCipherFactory, byte[], byte[], SRPPrimeVerifier)}
     * for notes on the parameters.
     * @param identity 
     * @param password
     */
    public SRPTlsClient(byte[] identity, byte[] password)
    {
        this(null, identity, password, null);
    }
    
    /**
     * Create a client with the given identity, password, prime verififer,
     * and a default cipher factory. See
     * {@link #SRPTlsClient(TlsCipherFactory, byte[], byte[], SRPPrimeVerifier)}
     * for notes on the parameters.
     * @param identity
     * @param password
     * @param primeVerifier
     */
    public SRPTlsClient(byte[] identity, byte[] password, SRPPrimeVerifier primeVerifier)
    {
        this(null, identity, password, primeVerifier);
    }

    /**
     * Create a client with the given identity, password, cipher factory, and a
     * default prime verifier. See
     * {@link #SRPTlsClient(TlsCipherFactory, byte[], byte[], SRPPrimeVerifier)}
     * for notes on the parameters.
     * @param cipherFactory
     * @param identity
     * @param password
     */
    public SRPTlsClient(TlsCipherFactory cipherFactory, byte[] identity, byte[] password)
    {
        this(cipherFactory, identity, password, new DefaultSRPPrimeVerifier());
    }
    
    /**
     * Create a client with the given identity, password, cipher factory, and prime verifier.<br>
     * <br>
     * Per RFC 5054 section 2.3, the supplied username and password
     * must be prepared with the RFC 4013 SASLprep profile (using e.g.
     * ICU4J's com.ibm.icu.text.StringPrep) and encoded with UTF-8.
     * @param cipherFactory
     * @param identity
     * @param password
     * @param primeVerifier
     */
    public SRPTlsClient(TlsCipherFactory cipherFactory, byte[] identity, byte[] password,
            SRPPrimeVerifier primeVerifier)
    {
        super(cipherFactory);
        this.identity = Arrays.clone(identity);
        this.password = Arrays.clone(password);
        if (primeVerifier == null)
        {
            primeVerifier = new DefaultSRPPrimeVerifier();
        }
        this.primeVerifier = primeVerifier;
    }

    public int[] getCipherSuites()
    {
        return new int[] { CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA };
    }

    public Hashtable getClientExtensions()
        throws IOException
    {
        Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
        TlsSRPUtils.addSRPExtension(clientExtensions, this.identity);
        return clientExtensions;
    }

    public void processServerExtensions(Hashtable serverExtensions)
        throws IOException
    {
        if (!TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsSRPUtils.EXT_SRP, AlertDescription.illegal_parameter))
        {
            // No explicit guidance in RFC 5054 here; we allow an optional empty extension from server
        }
    }

    public TlsKeyExchange getKeyExchange()
        throws IOException
    {

        switch (selectedCipherSuite)
        {
        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            return createSRPKeyExchange(KeyExchangeAlgorithm.SRP);

        case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
            return createSRPKeyExchange(KeyExchangeAlgorithm.SRP_RSA);

        case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
            return createSRPKeyExchange(KeyExchangeAlgorithm.SRP_DSS);

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
        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm._3DES_EDE_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
            return cipherFactory.createCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha1);

        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
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
    
    public TlsAuthentication getAuthentication() throws IOException
    {
        // default implementation that does nothing
        return new TlsAuthentication()
        {
            public void notifyServerCertificate(Certificate serverCertificate)
                    throws IOException
            {
                
            }
            
            public TlsCredentials getClientCredentials(
                    CertificateRequest certificateRequest) throws IOException
            {
                return null;
            }
        };
    }

    protected TlsKeyExchange createSRPKeyExchange(int keyExchange)
    {
        return new TlsSRPKeyExchange(keyExchange, supportedSignatureAlgorithms, primeVerifier,
                identity, password);
    }

}
