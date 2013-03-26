package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DTLSClientProtocol;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.UDPTransport;
import org.bouncycastle.util.encoders.Hex;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS server.
 * 
 * Please refer to GnuTLSSetup.txt or OpenSSLSetup.txt, and x509-*.pem files in this package for
 * help configuring an external DTLS server.
 */
public class DTLSClientTest {

    public static void main(String[] args) throws Exception {

        SecureRandom secureRandom = new SecureRandom();

        DatagramSocket socket = new DatagramSocket();
        socket.connect(InetAddress.getLocalHost(), 5556);

        int mtu = 1500;
        DatagramTransport transport = new UDPTransport(socket, mtu);

        transport = new UnreliableDatagramTransport(transport, secureRandom, 0, 0);

        transport = new LoggingDatagramTransport(transport, System.out);

        DTLSClientProtocol protocol = new DTLSClientProtocol(secureRandom);

        MyTlsClient client = new MyTlsClient();
        DatagramTransport dtls = protocol.connect(client, transport);

        System.out.println("Receive limit: " + dtls.getReceiveLimit());
        System.out.println("Send limit: " + dtls.getSendLimit());

        // Send and hopefully receive a packet back

        byte[] request = "Hello World!\n".getBytes("UTF-8");
        dtls.send(request, 0, request.length);

        byte[] response = new byte[dtls.getReceiveLimit()];
        int received = dtls.receive(response, 0, response.length, 30000);
        if (received >= 0) {
            System.out.println(new String(response, 0, received, "UTF-8"));
        }

        socket.close();
    }

    static class MyTlsClient extends DefaultTlsClient {

        public int[] getCipherSuites() {
            return new int[] { CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, };
        }

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
                        System.out.println("    SHA1 Fingerprint=" + fingerprint(entry) + " ("
                            + entry.getSubject() + ")");
                    }
                }
            };
        }

        private static String fingerprint(Certificate c) throws IOException {
            byte[] der = c.getEncoded();
            byte[] sha1 = sha1DigestOf(der);
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

        private static byte[] sha1DigestOf(byte[] input) {
            SHA1Digest d = new SHA1Digest();
            d.update(input, 0, input.length);
            byte[] result = new byte[d.getDigestSize()];
            d.doFinal(result, 0);
            return result;
        }
    }
}
