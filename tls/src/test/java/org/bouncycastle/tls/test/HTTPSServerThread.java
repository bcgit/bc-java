package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Vector;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class HTTPSServerThread
    extends Thread
{
    private static final int PORT_NO = 12001;
    private static final char[] SERVER_PASSWORD = "serverPassword".toCharArray();

    /**
     * Read a HTTP request
     */
    private void readRequest(
        InputStream in)
        throws IOException
    {
        int ch = 0;
        int lastCh = 0;
        while ((ch = in.read()) >= 0 && (ch != '\n' && lastCh != '\n'))
        {
            if (ch != '\r')
            {
                lastCh = ch;
            }
        }
    }

    /**
     * Send a response
     */
    private void sendResponse(
        OutputStream out)
    {
        PrintWriter pWrt = new PrintWriter(new OutputStreamWriter(out));
        pWrt.print("HTTP/1.1 200 OK\r\n");
        pWrt.print("Content-Type: text/html\r\n");
        pWrt.print("\r\n");
        pWrt.print("<html>\r\n");
        pWrt.print("<body>\r\n");
        pWrt.print("Hello World!\r\n");
        pWrt.print("</body>\r\n");
        pWrt.print("</html>\r\n");
        pWrt.flush();
    }

    SSLContext createSSLContext()
        throws Exception
    {
        JcaTlsCrypto crypto = (JcaTlsCrypto)new JcaTlsCryptoProvider().create(new SecureRandom());
        X509Certificate certificate = ((JcaTlsCertificate)TlsTestUtils.loadCertificateResource(crypto,
            "x509-server-rsa-sign.pem")).getX509Certificate();
        PrivateKey privateKey = TlsTestUtils.loadJcaPrivateKeyResource(crypto, "x509-server-key-rsa-sign.pem");

        KeyStore serverStore = KeyStore.getInstance("JKS");
        serverStore.load(null, null);
        serverStore.setKeyEntry("server", privateKey, SERVER_PASSWORD, new X509Certificate[]{ certificate });

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);

        KeyManagerFactory mgrFact = TlsTestUtils.getSunX509KeyManagerFactory();
        mgrFact.init(serverStore, SERVER_PASSWORD);

        TrustManagerFactory trustFact = TlsTestUtils.getSunX509TrustManagerFactory();
        trustFact.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS","SunJSSE");
        sslContext.init(mgrFact.getKeyManagers(), trustFact.getTrustManagers(), null);
        return sslContext;
    }

    void disableRSAKeyExchange(SSLSocket s)
    {
        String[] cipherSuites = s.getEnabledCipherSuites();

        Vector v = new Vector();
        for (int i = 0; i != cipherSuites.length; i++)
        {
            String cipherSuite = cipherSuites[i];

            if (!cipherSuite.regionMatches(true, 0, "SSL_RSA_", 0, "SSL_RSA_".length()) &&
                !cipherSuite.regionMatches(true, 0, "TLS_RSA_", 0, "TLS_RSA_".length()))
            {
                v.addElement(cipherSuite);
            }
        }

        s.setEnabledCipherSuites((String[])v.toArray(new String[0]));
    }

    public void run()
    {
        try
        {
            SSLContext sslContext = createSSLContext();
            SSLServerSocketFactory fact = sslContext.getServerSocketFactory();

            SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(PORT_NO);
            SSLSocket sslSock = (SSLSocket)sSock.accept();
            disableRSAKeyExchange(sslSock);
            sslSock.setUseClientMode(false);

            readRequest(sslSock.getInputStream());

//            SSLSession session =
            sslSock.getSession();

            sendResponse(sslSock.getOutputStream());

            sslSock.close();
            sSock.close();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
}
