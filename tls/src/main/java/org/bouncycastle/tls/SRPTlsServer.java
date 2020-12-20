package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.tls.crypto.TlsCrypto;

public class SRPTlsServer
    extends AbstractTlsServer
{
    private static final int[] DEFAULT_CIPHER_SUITES = new int[]
    {
        CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA
    };

    protected TlsSRPIdentityManager srpIdentityManager;

    protected byte[] srpIdentity = null;
    protected TlsSRPLoginParameters srpLoginParameters = null;

    public SRPTlsServer(TlsCrypto crypto, TlsSRPIdentityManager srpIdentityManager)
    {
        super(crypto);

        this.srpIdentityManager = srpIdentityManager;
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
                this.srpLoginParameters = srpIdentityManager.getLoginParameters(srpIdentity);
            }

            if (srpLoginParameters == null)
            {
                throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);
            }
        }

        return cipherSuite;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        int keyExchangeAlgorithm = context.getSecurityParametersHandshake().getKeyExchangeAlgorithm();

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

    public TlsSRPLoginParameters getSRPLoginParameters() throws IOException
    {
        return srpLoginParameters;
    }
}
