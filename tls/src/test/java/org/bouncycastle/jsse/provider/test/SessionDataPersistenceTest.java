package org.bouncycastle.jsse.provider.test;

import java.security.Security;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import junit.framework.TestCase;

/**
 * Test to verify that application data stored in handshake session
 * persists to the final session after handshake completion.
 */
public class SessionDataPersistenceTest extends TestCase
{
    static
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCJSSE") == null)
        {
            Security.addProvider(new BouncyCastleJsseProvider());
        }
    }

    public void testHandshakeSessionDataPersistence() throws Exception
    {
        SSLContext ctx = SSLContext.getInstance("TLS", "BCJSSE");
        ctx.init(null, new TrustManager[]{new TestTrustManager()}, null);
        
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket("www.google.com", 443);
        socket.startHandshake();
        
        // Verify that data stored during handshake is available in final session
        String result = (String) socket.getSession().getValue("test-data");
        assertNotNull("Handshake session data should persist to final session", result);
        assertEquals("test-value", result);
        
        socket.close();
    }
    
    private static class TestTrustManager extends X509ExtendedTrustManager
    {
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, java.net.Socket socket)
        {
            // Store test data in handshake session
            if (socket instanceof SSLSocket)
            {
                ((SSLSocket) socket).getHandshakeSession().putValue("test-data", "test-value");
            }
        }
        
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) {}
        
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) {}
        
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, java.net.Socket socket) {}
        
        @Override
        public X509Certificate[] getAcceptedIssuers() 
        {
            return new X509Certificate[0];
        }
    }
}