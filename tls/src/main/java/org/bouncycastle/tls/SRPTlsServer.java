package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;

public class SRPTlsServer
    extends AbstractTlsServer
{
    // TODO[tls] Perhaps not ideal to keep this in a writable array
    public static final int[] BASE_CIPHER_SUITES = new int[]
    {
        CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA
    };

    protected TlsSRPIdentityManager srpIdentityManager;
    protected int[] supportedCipherSuites;

    protected byte[] srpIdentity = null;
    protected TlsSRPLoginParameters loginParameters = null;

    // TODO[tls-ops] Need to restore a single-arg constructor here

    public SRPTlsServer(TlsCrypto crypto, TlsSRPIdentityManager srpIdentityManager)
    {
        this(crypto, new DefaultTlsKeyExchangeFactory(), srpIdentityManager);
    }

    public SRPTlsServer(TlsCrypto crypto, TlsKeyExchangeFactory keyExchangeFactory, TlsSRPIdentityManager srpIdentityManager)
    {
        super(crypto, keyExchangeFactory);
        this.srpIdentityManager = srpIdentityManager;
        this.supportedCipherSuites = TlsUtils.getSupportedCipherSuites(crypto, BASE_CIPHER_SUITES);
    }

    protected TlsCredentialedSigner getDSASignerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected TlsCredentialedSigner getRSASignerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected int[] getCipherSuites()
    {
        return Arrays.clone(supportedCipherSuites);
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
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.SRP:
            return null;

        case KeyExchangeAlgorithm.SRP_DSS:
            return getDSASignerCredentials();

        case KeyExchangeAlgorithm.SRP_RSA:
            return getRSASignerCredentials();

        default:
            /* Note: internal error here; selected a key exchange we don't implement! */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public TlsKeyExchange getKeyExchange()
        throws IOException
    {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.SRP:
        case KeyExchangeAlgorithm.SRP_DSS:
        case KeyExchangeAlgorithm.SRP_RSA:
            return createSRPKeyExchange(keyExchangeAlgorithm);

        default:
            /*
             * Note: internal error here; the TlsProtocol implementation verifies that the
             * server-selected cipher suite was in the list of client-offered cipher suites, so if
             * we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsKeyExchange createSRPKeyExchange(int keyExchange) throws IOException
    {
        return keyExchangeFactory.createSRPKeyExchangeServer(keyExchange, supportedSignatureAlgorithms, srpIdentity, loginParameters);
    }
}
