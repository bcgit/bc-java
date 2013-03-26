package org.bouncycastle.crypto.tls.test;

import java.io.IOException;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.util.encoders.Hex;

public class MockDTLSClient extends DefaultTlsClient {

    public ProtocolVersion getClientVersion() {
        return ProtocolVersion.DTLSv10;
    }

    public ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    public TlsAuthentication getAuthentication() throws IOException {
        return new ServerOnlyTlsAuthentication() {
            public void notifyServerCertificate(
                org.bouncycastle.crypto.tls.Certificate serverCertificate) throws IOException {
                Certificate[] chain = serverCertificate.getCertificateList();
                System.out.println("Received server certificate chain of length "
                    + chain.length);
                for (Certificate entry : chain) {
                    System.out.println("    fingerprint:SHA-256 " + fingerprint(entry) + " ("
                        + entry.getSubject() + ")");
                }
            }
        };
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