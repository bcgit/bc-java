package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.encoders.Hex;

class TlsTestServerImpl
    extends DefaultTlsServer
{
    protected final TlsTestConfig config;

    protected int firstFatalAlertConnectionEnd = -1;
    protected short firstFatalAlertDescription = -1;

    byte[] tlsServerEndPoint = null;
    byte[] tlsUnique = null;

    TlsTestServerImpl(TlsTestConfig config)
    {
        super(new BcTlsCrypto(new SecureRandom()));

        this.config = config;
    }

    int getFirstFatalAlertConnectionEnd()
    {
        return firstFatalAlertConnectionEnd;
    }

    short getFirstFatalAlertDescription()
    {
        return firstFatalAlertDescription;
    }

    public boolean shouldCheckSigAlgOfPeerCerts()
    {
        return config.serverCheckSigAlgOfClientCerts;
    }

    public TlsCrypto getCrypto()
    {
        switch (config.serverCrypto)
        {
        case TlsTestConfig.CRYPTO_JCA:
            return TlsTestSuite.JCA_CRYPTO;
        default:
            return TlsTestSuite.BC_CRYPTO;
        }
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
        {
            firstFatalAlertConnectionEnd = ConnectionEnd.server;
            firstFatalAlertDescription = alertDescription;
        }

        if (TlsTestConfig.DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server raised alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
            if (message != null)
            {
                out.println("> " + message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
        {
            firstFatalAlertConnectionEnd = ConnectionEnd.client;
            firstFatalAlertDescription = alertDescription;
        }

        if (TlsTestConfig.DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server received alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
        }
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
        tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);

        if (TlsTestConfig.DEBUG)
        {
            System.out.println("TLS server reports 'tls-server-end-point' = " + hex(tlsServerEndPoint));
            System.out.println("TLS server reports 'tls-unique' = " + hex(tlsUnique));
        }
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = (null != config.serverNegotiateVersion)
            ?   config.serverNegotiateVersion
            :   super.getServerVersion();

        if (TlsTestConfig.DEBUG)
        {
            System.out.println("TLS server negotiated " + serverVersion);
        }

        return serverVersion;
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        if (config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
        {
            return null;
        }

        short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
            ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

        Vector serverSigAlgs = null;
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
        {
            serverSigAlgs = config.serverCertReqSigAlgs;
            if (serverSigAlgs == null)
            {
                serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
            }
        }

        Vector certificateAuthorities = new Vector();
//        certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-dsa.pem").getSubject());
//        certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-ecdsa.pem").getSubject());
//        certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-rsa.pem").getSubject());

        // All the CA certificates are currently configured with this subject
        certificateAuthorities.addElement(new X500Name("CN=BouncyCastle TLS Test CA"));

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    public void notifyClientCertificate(org.bouncycastle.tls.Certificate clientCertificate)
        throws IOException
    {
        boolean isEmpty = (clientCertificate == null || clientCertificate.isEmpty());

        if (isEmpty != (config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE))
        {
            throw new IllegalStateException();
        }
        if (isEmpty && (config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_MANDATORY))
        {
            short alertDescription = TlsUtils.isTLSv13(context)
                ?   AlertDescription.certificate_required
                :   AlertDescription.handshake_failure;

            throw new TlsFatalAlert(alertDescription);
        }

        TlsCertificate[] chain = clientCertificate.getCertificateList();

        if (TlsTestConfig.DEBUG)
        {
            System.out.println("TLS server received client certificate chain of length " + chain.length);
            for (int i = 0; i != chain.length; i++)
            {
                Certificate entry = Certificate.getInstance(chain[i].getEncoded());
                // TODO Create fingerprint based on certificate signature algorithm digest
                System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                    + entry.getSubject() + ")");
            }
        }

        if (!isEmpty && !TlsTestUtils.isCertificateOneOf(context.getCrypto(), chain[0],
            new String[]
            { "x509-client-dsa.pem", "x509-client-ecdh.pem", "x509-client-ecdsa.pem", "x509-client-ed25519.pem",
                "x509-client-rsa_pss_256.pem", "x509-client-rsa_pss_384.pem", "x509-client-rsa_pss_512.pem",
                "x509-client-rsa.pem" }))
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }
    }

    protected Vector getSupportedSignatureAlgorithms()
    {
        if (TlsUtils.isTLSv12(context) && config.serverAuthSigAlg != null)
        {
            Vector signatureAlgorithms = new Vector(1);
            signatureAlgorithms.addElement(config.serverAuthSigAlg);
            return signatureAlgorithms;
        }

        return context.getSecurityParametersHandshake().getClientSigAlgs();
    }

    protected TlsCredentialedSigner getDSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentialsServer(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.dsa);
    }

    protected TlsCredentialedSigner getECDSASignerCredentials() throws IOException
    {
        // TODO[RFC 8422] Code should choose based on client's supported sig algs?
        return TlsTestUtils.loadSignerCredentialsServer(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.ecdsa);
//        return TlsTestUtils.loadSignerCredentialsServer(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.ed25519);
//        return TlsTestUtils.loadSignerCredentialsServer(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.ed448);
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{ "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" },
            "x509-server-key-rsa-enc.pem");
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentialsServer(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.rsa);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        if (config.serverSupportedVersions != null)
        {
            return config.serverSupportedVersions;
        }

        return super.getSupportedVersions();
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }
}
