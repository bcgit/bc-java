package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.tls.crypto.TlsCrypto;

public class SRPTlsClient
    extends AbstractTlsClient
{
    private static final int[] DEFAULT_CIPHER_SUITES = new int[]
    {
        CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
    };

    protected TlsSRPIdentity srpIdentity;

    public SRPTlsClient(TlsCrypto crypto, byte[] identity, byte[] password)
    {
        this(crypto, new BasicTlsSRPIdentity(identity, password));
    }

    public SRPTlsClient(TlsCrypto crypto, TlsSRPIdentity srpIdentity)
    {
        super(crypto);

        this.srpIdentity = srpIdentity;
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), DEFAULT_CIPHER_SUITES);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv12.downTo(ProtocolVersion.TLSv10);
    }

    protected boolean requireSRPServerExtension()
    {
        // No explicit guidance in RFC 5054; by default an (empty) extension from server is optional
        return false;
    }

    /** @deprecated Unused; will be removed */
    public ProtocolVersion getClientVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    public Hashtable getClientExtensions()
        throws IOException
    {
        Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
        TlsSRPUtils.addSRPExtension(clientExtensions, srpIdentity.getSRPIdentity());
        return clientExtensions;
    }

    public void processServerExtensions(Hashtable serverExtensions)
        throws IOException
    {
        if (!TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsSRPUtils.EXT_SRP,
            AlertDescription.illegal_parameter))
        {
            if (requireSRPServerExtension())
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

        super.processServerExtensions(serverExtensions);
    }

    public TlsSRPIdentity getSRPIdentity()
    {
        return srpIdentity;
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        /*
         * Note: This method is not called unless a server certificate is sent, which may be the
         * case e.g. for SRP_DSS or SRP_RSA key exchange.
         */
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
