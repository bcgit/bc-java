package org.bouncycastle.tls.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.TlsClientProtocol;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.*;

/**
 * Test GMSSL's client connection status
 *
 * @author cliven
 * @since 2021-03-05 11:31:29
 */
public class GMSSLClientTest
{

    public static void main(String[] args)
            throws Exception {
        final BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        Security.addProvider(new BouncyCastleJsseProvider());

        InetAddress host = InetAddress.getByName("localhost");
        int port = 443;
//        jsse(host, port);
        bc(host, port);
    }

    private static void bc(InetAddress HOST, int port) throws IOException
    {
        final MockGMSSLClient client = new MockGMSSLClient();
        Socket s = new Socket("localhost", port,null, 2333);
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
        protocol.connect(client);


        OutputStream out = protocol.getOutputStream();
        String req = "GET / HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Connection: close\r\n\r\n";

        out.write(req.getBytes("UTF-8"));
        out.flush();
        InputStream in = protocol.getInputStream();
        byte[] buffer = new byte[2048];
        in.read(buffer);
        System.out.println(new String(buffer));

        out.close();
        in.close();

    }

    private static void jsse(InetAddress HOST, int port) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, KeyManagementException
    {
        SSLContext clientContext = SSLContext.getInstance("GMSSL", BouncyCastleJsseProvider.PROVIDER_NAME);
        clientContext.init(new KeyManager[]{}, new TrustManager[]{}, new SecureRandom());
        SSLSocketFactory fact = clientContext.getSocketFactory();
        SSLSocket cSock = (SSLSocket) fact.createSocket(HOST, port);

        OutputStream out = cSock.getOutputStream();
        String req = "GET / HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Connection: close\r\n\r\n";

        out.write(req.getBytes("UTF-8"));
        out.flush();
        InputStream in = cSock.getInputStream();
        byte[] buffer = new byte[2048];
        in.read(buffer);
        System.out.println(new String(buffer));

        out.close();
        in.close();
    }
}
