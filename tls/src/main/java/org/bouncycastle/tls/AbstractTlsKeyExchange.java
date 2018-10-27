package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCertificate;

/**
 * Base class for supporting a TLS key exchange implementation.
 */
public abstract class AbstractTlsKeyExchange
    implements TlsKeyExchange
{
    protected int keyExchange;
    protected Vector supportedSignatureAlgorithms;

    protected TlsContext context;

    protected AbstractTlsKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms)
    {
        this.keyExchange = keyExchange;
        this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
    }

    protected TlsCertificate checkSigAlgOfServerCerts(Certificate serverCertificate) throws IOException
    {
        if (context.getPeerOptions().isCheckSigAlgOfPeerCerts())
        {
            for (int i = 0; i < serverCertificate.getLength(); ++i)
            {
                String sigAlgOID = serverCertificate.getCertificateAt(i).getSigAlgOID();
                SignatureAndHashAlgorithm sigAndHashAlg = TlsUtils.getCertSigAndHashAlg(sigAlgOID);

                boolean valid = false;
                if (null == sigAndHashAlg)
                {
                    // We don't recognize the 'signatureAlgorithm' of the certificate
                }
                else if (null == supportedSignatureAlgorithms)
                {
                    /*
                     * RFC 4346 7.4.2. Unless otherwise specified, the signing algorithm for the
                     * certificate MUST be the same as the algorithm for the certificate key.
                     */
                    int signatureAlgorithm = TlsUtils.getLegacySignatureAlgorithmServerCert(keyExchange);

                    valid = (signatureAlgorithm == sigAndHashAlg.getSignature()); 
                }
                else
                {
                    /*
                     * RFC 5246 7.4.2. If the client provided a "signature_algorithms" extension, then
                     * all certificates provided by the server MUST be signed by a hash/signature algorithm
                     * pair that appears in that extension.
                     */
                    valid = TlsUtils.containsSignatureAlgorithm(supportedSignatureAlgorithms, sigAndHashAlg);
                }

                if (!valid)
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }
            }
        }

        return serverCertificate.getCertificateAt(0);
    }

    public void init(TlsContext context)
    {
        this.context = context;

        ProtocolVersion clientVersion = context.getClientVersion(), serverVersion = context.getServerVersion();

        if (null == supportedSignatureAlgorithms)
        {
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
            {
                short signatureAlgorithm = TlsUtils.getLegacySignatureAlgorithmServerCert(keyExchange);

                this.supportedSignatureAlgorithms = TlsUtils.getDefaultSignatureAlgorithms(signatureAlgorithm);
            }
        }
        else
        {
            if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
            {
                throw new IllegalStateException("supported_signature_algorithms not allowed for " + clientVersion);
            }
            if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
            {
                this.supportedSignatureAlgorithms = null;
            }
        }
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public boolean requiresServerKeyExchange()
    {
        return false;
    }

    public byte[] generateServerKeyExchange()
        throws IOException
    {
        if (requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        return null;
    }

    public void skipServerKeyExchange()
        throws IOException
    {
        if (requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void processServerKeyExchange(InputStream input)
        throws IOException
    {
        if (!requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public short[] getClientCertificateTypes()
    {
        return null;
    }

    public void skipClientCredentials()
        throws IOException
    {
        if (TlsUtils.isStaticKeyAgreement(keyExchange))
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void processClientCertificate(Certificate clientCertificate)
        throws IOException
    {
    }

    public void processClientKeyExchange(InputStream input)
        throws IOException
    {
        // Key exchange implementation MUST support client key exchange
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public boolean requiresCertificateVerify()
    {
        return !TlsUtils.isStaticKeyAgreement(keyExchange);
    }
}
