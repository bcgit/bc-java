package org.bouncycastle.tls.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.provider.gm.GMSimpleSSLClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.util.io.Streams;

import javax.net.ssl.*;
import java.io.IOException;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.*;

/**
 * Test GMSSL's client connection status
 *
 *
 * @since 2021-03-05 11:31:29
 */
public class GMSSLClientTest
{

    public static void main(String[] args)
            throws Exception {
        final BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        Security.addProvider(new BouncyCastleJsseProvider());

//        String host = "localhost";
//        int port = 5557;
        String host = "sm2test.ovssl.cn";
        int port = 443;
//        bc(host, port);
        jsse(host, port);
    }

    private static void bc(String host, int port) throws IOException
    {
        final GMSimpleSSLClient client = new GMSimpleSSLClient();
        Socket s = new Socket(host, port);
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
        protocol.connect(client);


        OutputStream out = protocol.getOutputStream();
        String req = "GET / HTTP/1.1\r\n" +
                "Host: "+ host + "\r\n" +
                "Connection: close\r\n\r\n";

        out.write(req.getBytes("UTF-8"));
        out.flush();
        Streams.pipeAll(protocol.getInputStream(), System.out);
        out.close();
    }

    private static void jsse(String host, int port) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, KeyManagementException
    {
        SSLContext clientContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
        clientContext.init(new KeyManager[]{}, new TrustManager[]{}, new SecureRandom());
        SSLSocketFactory fact = clientContext.getSocketFactory();
        SSLSocket cSock = (SSLSocket) fact.createSocket(host, port);

        OutputStream out = cSock.getOutputStream();
        String req = "GET / HTTP/1.1\r\n" +
                "Host: "+host+"\r\n" +
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
