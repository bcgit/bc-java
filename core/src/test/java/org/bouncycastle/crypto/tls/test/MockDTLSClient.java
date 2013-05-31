package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;

public class MockDTLSClient
    extends DefaultTlsClient
{

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS client raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
            + ")");
        if (message != null)
        {
            out.println(message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS client received alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
            + ")");
    }

    public ProtocolVersion getClientVersion()
    {
        return ProtocolVersion.DTLSv10;
    }

    public ProtocolVersion getMinimumVersion()
    {
        return ProtocolVersion.DTLSv10;
    }

    public TlsAuthentication getAuthentication()
        throws IOException
    {
        return new TlsAuthentication()
        {
            public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate)
                throws IOException
            {
                Certificate[] chain = serverCertificate.getCertificateList();
                System.out.println("Received server certificate chain of length " + chain.length);
                for (int i = 0; i != chain.length; i++)
                {
                    Certificate entry = chain[i];
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                        + entry.getSubject() + ")");
                }
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                throws IOException
            {
                short[] certificateTypes = certificateRequest.getCertificateTypes();
                if (certificateTypes != null)
                {
                    for (int i = 0; i < certificateTypes.length; ++i)
                    {
                        if (certificateTypes[i] == ClientCertificateType.rsa_sign)
                        {
                            // TODO Create a distinct client certificate for use here
                            return TlsTestUtils.loadSignerCredentials(context, new String[]{"x509-server.pem",
                                "x509-ca.pem"}, "x509-server-key.pem");
                        }
                    }
                }
                return null;
            }
        };
    }
}
