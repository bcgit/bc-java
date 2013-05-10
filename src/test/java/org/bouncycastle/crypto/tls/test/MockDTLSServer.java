package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.util.encoders.Hex;

public class MockDTLSServer extends DefaultTlsServer {

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause) {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS server raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
            + ")");
        if (message != null) {
            out.println(message);
        }
        if (cause != null) {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription) {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS server received alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
            + ")");
    }

    public CertificateRequest getCertificateRequest() {
        return new CertificateRequest(new short[]{ ClientCertificateType.rsa_sign }, null);
    }

    public void notifyClientCertificate(org.bouncycastle.crypto.tls.Certificate clientCertificate) throws IOException {
        Certificate[] chain = clientCertificate.getCertificateList();
        System.out.println("Received server certificate chain of length " + chain.length);
        for (Certificate entry : chain) {
            // TODO Create fingerprint based on certificate signature algorithm digest
            System.out.println("    fingerprint:SHA-256 " + fingerprint(entry) + " (" + entry.getSubject()
                + ")");
        }
    }

    protected ProtocolVersion getMaximumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    protected ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[] { "x509-server.pem", "x509-ca.pem" },
            "x509-server-key.pem");
    }

    protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
        return TlsTestUtils.loadSignerCredentials(context, new String[] { "x509-server.pem", "x509-ca.pem" },
            "x509-server-key.pem");
    }

    private static String fingerprint(Certificate c) throws IOException {
        byte[] der = c.getEncoded();
        byte[] sha1 = sha256DigestOf(der);
        byte[] hexBytes = Hex.encode(sha1);
        String hex = new String(hexBytes, "ASCII").toUpperCase();

        StringBuffer fp = new StringBuffer();
        int i = 0;
        fp.append(hex.substring(i, i + 2));
        while ((i += 2) < hex.length()) {
            fp.append(':');
            fp.append(hex.substring(i, i + 2));
        }
        return fp.toString();
    }

    private static byte[] sha256DigestOf(byte[] input) {
        SHA256Digest d = new SHA256Digest();
        d.update(input, 0, input.length);
        byte[] result = new byte[d.getDigestSize()];
        d.doFinal(result, 0);
        return result;
    }
}
