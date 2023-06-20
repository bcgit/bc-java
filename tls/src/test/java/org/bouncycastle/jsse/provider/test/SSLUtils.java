package org.bouncycastle.jsse.provider.test;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

class SSLUtils
{
    static void enableAll(SSLServerSocket ss)
    {
        ss.setEnabledCipherSuites(ss.getSupportedCipherSuites());
        ss.setEnabledProtocols(ss.getSupportedProtocols());
    }

    static void restrictKeyExchange(SSLSocket s, String keyExchange)
    {
        ArrayList<String> enabled = new ArrayList<String>();
        for (String suite : s.getSupportedCipherSuites())
        {
            if (suite.startsWith("TLS_" + keyExchange + "_WITH"))
            {
                enabled.add(suite);
            }
        }
        // some JSSE don't use TLS_
        if (enabled.isEmpty())
        {
            for (String suite : s.getSupportedCipherSuites())
            {
                if (suite.startsWith("SSL_" + keyExchange + "_WITH"))
                {
                    enabled.add(suite);
                }
            }
        }
        s.setEnabledCipherSuites(enabled.toArray(new String[enabled.size()]));
    }

    static void startServer(final KeyStore keyStore, final char[] password, final KeyStore serverStore)
    {
        startServer(keyStore, password, serverStore, false, 8888);
    }

    static void startServer(final KeyStore keyStore, final char[] password, final KeyStore serverStore, final boolean needClientAuth,
        final int port)
    {
        final CountDownLatch latch = new CountDownLatch(1);

        Runnable serverTask = new Runnable()
        {
            public void run()
            {
                try
                {
                    boolean isJdk15 = System.getProperty("java.version").indexOf("1.5.") == 0;

                    KeyManagerFactory keyManagerFactory = isJdk15 ?
                        KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE) :
                        KeyManagerFactory.getInstance("PKIX");

                    keyManagerFactory.init(keyStore, password);

                    TrustManagerFactory trustManagerFactory = isJdk15 ?
                        TrustManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE) :
                        TrustManagerFactory.getInstance("PKIX");

                    trustManagerFactory.init(serverStore);

                    SSLContext context = isJdk15 ?
                        SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE) :
                        SSLContext.getInstance("TLS");

                    context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

                    SSLServerSocketFactory sslSocketFactory = context.getServerSocketFactory();

                    SSLServerSocket ss = (SSLServerSocket)sslSocketFactory.createServerSocket(port);

                    enableAll(ss);

                    ss.setNeedClientAuth(needClientAuth);

                    latch.countDown();

                    SSLSocket s = (SSLSocket)ss.accept();
                    s.setUseClientMode(false);

                    s.getInputStream().read();

                    s.getOutputStream().write('!');

                    s.close();

                    ss.close();
                }
                catch (Throwable e)
                {
                    Thread.currentThread().interrupt();
                    latch.countDown();
                }
            }
        };

        Thread t = new Thread(serverTask);
        t.setDaemon(true);
        t.start();

        try
        {
            latch.await();
        }
        catch (InterruptedException e)
        {
              e.printStackTrace();
        }
    }
}
