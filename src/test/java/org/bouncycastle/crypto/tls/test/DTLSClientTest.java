package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DTLSProtocolHandler;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.UDPTransport;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS server.
 * 
 * Please refer to GnuTLSSetup.txt or OpenSSLSetup.txt, and x509-*.pem files in this package for
 * help configuring an external DTLS server.
 */
public class DTLSClientTest {

    public static void main(String[] args) throws Exception {

        DatagramSocket socket = new DatagramSocket();
        socket.connect(InetAddress.getLocalHost(), 5556);

        int mtu = 1500;
        DatagramTransport transport = new UDPTransport(socket, mtu);

        transport = new LoggingDatagramTransport(transport, System.out);

        SecureRandom secureRandom = new SecureRandom();
        DTLSProtocolHandler protocol = new DTLSProtocolHandler(secureRandom);

        DTLSClient client = new DTLSClient();
        DatagramTransport dtls = protocol.connect(client, transport);

        System.out.println("Receive limit: " + dtls.getReceiveLimit());
        System.out.println("Send limit: " + dtls.getSendLimit());

        // Send and hopefully receive a packet backet

        byte[] request = "Hello World!\n".getBytes("UTF-8");
        dtls.send(request, 0, request.length);

        byte[] response = new byte[dtls.getReceiveLimit()];
        int received = dtls.receive(response, 0, response.length, 30000);
        if (received >= 0) {
            System.out.println(new String(response, 0, received, "UTF-8"));
        }

        socket.close();
    }

    static class DTLSClient extends DefaultTlsClient {

        public int[] getCipherSuites() {
            return new int[] { CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, };
        }

        public ProtocolVersion getClientVersion() {
            return ProtocolVersion.DTLSv10;
        }

        public TlsAuthentication getAuthentication() throws IOException {
            return new ServerOnlyTlsAuthentication() {
                public void notifyServerCertificate(
                    org.bouncycastle.crypto.tls.Certificate serverCertificate) throws IOException {
                    Certificate[] chain = serverCertificate.getCerts();
                    System.out.println("Received server certificate chain of length "
                        + chain.length);
                    for (Certificate entry : chain) {
                        System.out.println("    " + entry.getSubject());
                    }
                }
            };
        }

        public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
            if (!ProtocolVersion.DTLSv10.equals(serverVersion)) {
                throw new TlsFatalAlert(AlertDescription.protocol_version);
            }
        }
    }
}
