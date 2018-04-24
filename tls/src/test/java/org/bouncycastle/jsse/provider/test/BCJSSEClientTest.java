package org.bouncycastle.jsse.provider.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * A simple test designed to conduct a TLS handshake with an external TLS server,
 * using the BC and BCJSSE providers.
 */
public class BCJSSEClientTest
{
    public static void main(String[] args)
        throws Exception
    {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        /*
         * TEST CODE ONLY. If writing your own code based on this test case, you should configure
         * your trust manager(s) using a proper TrustManagerFactory, or else the server will be
         * completely unauthenticated.
         */
        TrustManager tm = new X509TrustManager()
        {
            public X509Certificate[] getAcceptedIssuers()
            {
                return new X509Certificate[0];
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
            {
                if (chain == null || chain.length < 1 || authType == null || authType.length() < 1)
                {
                    throw new IllegalArgumentException();
                }

                String subject = chain[0].getSubjectX500Principal().getName();
                System.out.println("Auto-trusted server certificate chain for: " + subject);
            }

            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
            {
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
        sslContext.init(null, new TrustManager[]{ tm }, new SecureRandom());

        String host = "localhost";
        int port = 8443;

        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket)sslSocketFactory.createSocket(host, port);

        OutputStream output = sslSocket.getOutputStream();
        writeUTF8Line(output, "GET / HTTP/1.1");
        writeUTF8Line(output, "Host: " + host + ":" + port);
        writeUTF8Line(output, "");
        output.flush();

        System.out.println("---");

        InputStream input = sslSocket.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        String line;
        while ((line = reader.readLine()) != null)
        {
            System.out.println("<<< " + line);

            /*
             * TEST CODE ONLY. This is not a robust way of parsing the result!
             */
            if (line.toUpperCase().contains("</HTML>"))
            {
                break;
            }
        }

        System.out.flush();

        sslSocket.close();
    }

    private static void writeUTF8Line(OutputStream output, String line)
        throws IOException
    {
        output.write((line + "\r\n").getBytes("UTF-8"));
        System.out.println(">>> " + line);
    }
}
