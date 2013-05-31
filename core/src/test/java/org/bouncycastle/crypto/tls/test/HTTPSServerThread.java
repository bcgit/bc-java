package org.bouncycastle.crypto.tls.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class HTTPSServerThread
    extends Thread
{
    private static final int PORT_NO = 8003;
    private static final char[] SERVER_PASSWORD = "serverPassword".toCharArray();
    private static final char[] TRUST_STORE_PASSWORD = "trustPassword".toCharArray();

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
        KeyManagerFactory mgrFact = KeyManagerFactory.getInstance("SunX509");
        KeyStore serverStore = KeyStore.getInstance("JKS");

        serverStore.load(new ByteArrayInputStream(KeyStores.server), SERVER_PASSWORD);

        mgrFact.init(serverStore, SERVER_PASSWORD);

        // set up a trust manager so we can recognize the server
        TrustManagerFactory trustFact = TrustManagerFactory.getInstance("SunX509");
        KeyStore trustStore = KeyStore.getInstance("JKS");

        trustStore.load(new ByteArrayInputStream(KeyStores.trustStore), TRUST_STORE_PASSWORD);

        trustFact.init(trustStore);

        // create a context and set up a socket factory
        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(mgrFact.getKeyManagers(), trustFact.getTrustManagers(), null);

        return sslContext;
    }

    public void run()
    {
        try
        {
            SSLContext sslContext = createSSLContext();
            SSLServerSocketFactory fact = sslContext.getServerSocketFactory();

            SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(PORT_NO);
            SSLSocket sslSock = (SSLSocket)sSock.accept();

            sslSock.startHandshake();

            readRequest(sslSock.getInputStream());

            SSLSession session = sslSock.getSession();

            sendResponse(sslSock.getOutputStream());

            sslSock.close();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
}
