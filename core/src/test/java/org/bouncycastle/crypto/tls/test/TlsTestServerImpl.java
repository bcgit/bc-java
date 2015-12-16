package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Vector;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.ConnectionEnd;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsUtils;

class TlsTestServerImpl
    extends DefaultTlsServer
{
    protected final TlsTestConfig config;

    protected int firstFatalAlertConnectionEnd = -1;
    protected short firstFatalAlertDescription = -1;

    TlsTestServerImpl(TlsTestConfig config)
    {
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

    protected ProtocolVersion getMaximumVersion()
    {
        if (config.serverMaximumVersion != null)
        {
            return config.serverMaximumVersion;
        }

        return super.getMaximumVersion();
    }

    protected ProtocolVersion getMinimumVersion()
    {
        if (config.serverMinimumVersion != null)
        {
            return config.serverMinimumVersion;
        }

        return super.getMinimumVersion();
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

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

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
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
        {
            serverSigAlgs = config.serverCertReqSigAlgs;
            if (serverSigAlgs == null)
            {
                serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms();
            }
        }

        Vector certificateAuthorities = new Vector();
        certificateAuthorities.addElement(TlsTestUtils.loadCertificateResource("x509-ca.pem").getSubject());

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    public void notifyClientCertificate(org.bouncycastle.crypto.tls.Certificate clientCertificate)
        throws IOException
    {
        boolean isEmpty = (clientCertificate == null || clientCertificate.isEmpty());

        if (isEmpty != (config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE))
        {
            throw new IllegalStateException();
        }
        if (isEmpty && (config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_MANDATORY))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        Certificate[] chain = clientCertificate.getCertificateList();

        // TODO Cache test resources?
        if (!isEmpty && !(chain[0].equals(TlsTestUtils.loadCertificateResource("x509-client.pem"))
            || chain[0].equals(TlsTestUtils.loadCertificateResource("x509-client-dsa.pem"))
            || chain[0].equals(TlsTestUtils.loadCertificateResource("x509-client-ecdsa.pem"))))
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        if (TlsTestConfig.DEBUG)
        {
            System.out.println("TLS server received client certificate chain of length " + chain.length);
            for (int i = 0; i != chain.length; i++)
            {
                Certificate entry = chain[i];
                // TODO Create fingerprint based on certificate signature algorithm digest
                System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                    + entry.getSubject() + ")");
            }
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

        return supportedSignatureAlgorithms;
    }

    protected TlsSignerCredentials getDSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentials(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.dsa,
            "x509-server-dsa.pem", "x509-server-key-dsa.pem");
    }

    protected TlsSignerCredentials getECDSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentials(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.ecdsa,
            "x509-server-ecdsa.pem", "x509-server-key-ecdsa.pem");
    }

    protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{ "x509-server.pem", "x509-ca.pem" },
            "x509-server-key.pem");
    }

    protected TlsSignerCredentials getRSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentials(context, getSupportedSignatureAlgorithms(), SignatureAlgorithm.rsa,
            "x509-server.pem", "x509-server-key.pem");
    }
}