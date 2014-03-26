package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Vector;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.util.Arrays;

class MockTlsServer
    extends DefaultTlsServer
    implements ITestTlsServer
{
    byte[] receivedAppData;
    
    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS server raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
            + ")");
        if (message != null)
        {
            out.println("> " + message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS server received alert (AlertLevel." + alertLevel + ", AlertDescription."
            + alertDescription + ")");
    }

    protected int[] getCipherSuites()
    {
        return Arrays.concatenate(super.getCipherSuites(),
            new int[]
            {
                CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1,
                CipherSuite.TLS_ECDHE_RSA_WITH_SALSA20_SHA1,
                CipherSuite.TLS_RSA_WITH_ESTREAM_SALSA20_SHA1,
                CipherSuite.TLS_RSA_WITH_SALSA20_SHA1,
            });
    }

    protected ProtocolVersion getMaximumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS server negotiated " + serverVersion);

        return serverVersion;
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        Vector serverSigAlgs = null;

        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
        {
            short[] hashAlgorithms = new short[]{ HashAlgorithm.sha512, HashAlgorithm.sha384, HashAlgorithm.sha256,
                HashAlgorithm.sha224, HashAlgorithm.sha1 };
            short[] signatureAlgorithms = new short[]{ SignatureAlgorithm.rsa };

            serverSigAlgs = new Vector();
            for (int i = 0; i < hashAlgorithms.length; ++i)
            {
                for (int j = 0; j < signatureAlgorithms.length; ++j)
                {
                    serverSigAlgs.addElement(new SignatureAndHashAlgorithm(hashAlgorithms[i],
                        signatureAlgorithms[j]));
                }
            }
        }

        return new CertificateRequest(new short[]{ ClientCertificateType.rsa_sign }, serverSigAlgs, null);
    }

    public void notifyClientCertificate(org.bouncycastle.crypto.tls.Certificate clientCertificate)
        throws IOException
    {
        Certificate[] chain = clientCertificate.getCertificateList();
        System.out.println("TLS server received client certificate chain of length " + chain.length);
        for (int i = 0; i != chain.length; i++)
        {
            Certificate entry = chain[i];
            // TODO Create fingerprint based on certificate signature algorithm digest
            System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                + entry.getSubject() + ")");
        }
    }

    protected TlsEncryptionCredentials getRSAEncryptionCredentials()
        throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{"x509-server.pem", "x509-ca.pem"},
            "x509-server-key.pem");
    }

    protected TlsSignerCredentials getRSASignerCredentials()
        throws IOException
    {
        /*
         * TODO Note that this code fails to provide default value for the client supported
         * algorithms if it wasn't sent.
         */
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        Vector sigAlgs = supportedSignatureAlgorithms;
        if (sigAlgs != null)
        {
            for (int i = 0; i < sigAlgs.size(); ++i)
            {
                SignatureAndHashAlgorithm sigAlg = (SignatureAndHashAlgorithm)
                    sigAlgs.elementAt(i);
                if (sigAlg.getSignature() == SignatureAlgorithm.rsa)
                {
                    signatureAndHashAlgorithm = sigAlg;
                    break;
                }
            }

            if (signatureAndHashAlgorithm == null)
            {
                return null;
            }
        }

        return TlsTestUtils.loadSignerCredentials(context, new String[]{"x509-server.pem", "x509-ca.pem"},
            "x509-server-key.pem", signatureAndHashAlgorithm);
    }

    @Override
    public void notifyApplicationDataReceived(byte[] data)
    {
        receivedAppData = Arrays.concatenate(receivedAppData, data);
    }

    public byte[] getReceivedAppData()
    {
        return receivedAppData;
    }
}