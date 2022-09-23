package org.bouncycastle.tls.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientProtocol;

/**
 * A simple test designed to conduct a TLS handshake with an external TLS server.
 *
 * openssl genpkey -out ed25519.priv -algorithm ed25519
 * openssl pkey -in ed25519.priv -pubout -out ed25519.pub
 * gnutls-serv --http --debug 10 --priority NORMAL:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK --rawpkkeyfile ed25519.priv --rawpkfile ed25519.pub
 */
public class TlsClientRawKeysTest
{
    public static void main(String[] args)
        throws Exception
    {
        InetAddress address = InetAddress.getLoopbackAddress();
        int port = 5556;

        runTest(address, port, ProtocolVersion.TLSv12);
        runTest(address, port, ProtocolVersion.TLSv13);
    }

    static void runTest(InetAddress address, int port, ProtocolVersion tlsVersion) throws Exception
    {
        MockRawKeysTlsClient client = new MockRawKeysTlsClient(
                CertificateType.RawPublicKey,
                CertificateType.RawPublicKey,
                new short[] {CertificateType.RawPublicKey},
                new short[] {CertificateType.RawPublicKey},
                new Ed25519PrivateKeyParameters(new SecureRandom()),
                tlsVersion);
        TlsClientProtocol protocol = openTlsConnection(address, port, client);

        OutputStream output = protocol.getOutputStream();
        output.write("GET / HTTP/1.1\r\n\r\n".getBytes("UTF-8"));
        output.flush();

        InputStream input = protocol.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        String line;
        while ((line = reader.readLine()) != null)
        {
            System.out.println(">>> " + line);
        }

        protocol.close();
    }

    static TlsClientProtocol openTlsConnection(InetAddress address, int port, TlsClient client) throws IOException
    {
        Socket s = new Socket(address, port);
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
        protocol.connect(client);
        return protocol;
    }
}
