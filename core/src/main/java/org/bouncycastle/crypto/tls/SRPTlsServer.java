package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

public class SRPTlsServer
    extends AbstractTlsServer
{
    protected TlsSRPIdentityManager srpIdentityManager;

    protected byte[] srpIdentity = null;
    protected TlsSRPLoginParameters loginParameters = null;

    public SRPTlsServer(TlsSRPIdentityManager srpIdentityManager)
    {
        this(new DefaultTlsCipherFactory(), srpIdentityManager);
    }

    public SRPTlsServer(TlsCipherFactory cipherFactory, TlsSRPIdentityManager srpIdentityManager)
    {
        super(cipherFactory);
        this.srpIdentityManager = srpIdentityManager;
    }

    protected TlsSignerCredentials getDSASignerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected TlsSignerCredentials getRSASignerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected int[] getCipherSuites()
    {
        return new int[]
        {
            CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA
        };
    }

    public void processClientExtensions(Hashtable clientExtensions) throws IOException
    {
        super.processClientExtensions(clientExtensions);

        this.srpIdentity = TlsSRPUtils.getSRPExtension(clientExtensions);
    }

    public int getSelectedCipherSuite() throws IOException
    {
        int cipherSuite = super.getSelectedCipherSuite();

        if (TlsSRPUtils.isSRPCipherSuite(cipherSuite))
        {
            if (srpIdentity != null)
            {
                this.loginParameters = srpIdentityManager.getLoginParameters(srpIdentity);
            }

            if (loginParameters == null)
            {
                throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);
            }
        }

        return cipherSuite;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        switch (selectedCipherSuite)
        {
        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            return null;

        case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
            return getDSASignerCredentials();

        case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
            return getRSASignerCredentials();

        default:
            /* Note: internal error here; selected a key exchange we don't implement! */
            throw new TlsFatalAlert(AlertDescription.internal_error);
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

    protected TlsKeyExchange createSRPKeyExchange(int keyExchange)
    {
        return new TlsSRPKeyExchange(keyExchange, supportedSignatureAlgorithms, srpIdentity, loginParameters);
    }
}
