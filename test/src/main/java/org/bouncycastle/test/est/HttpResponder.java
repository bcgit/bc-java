package org.bouncycastle.test.est;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Accept a connection and responds with a pre baked message.
 */
public class HttpResponder
    implements Runnable
{
    private CountDownLatch finished = new CountDownLatch(1);
    private CountDownLatch ready = new CountDownLatch(1);
    private CountDownLatch close = new CountDownLatch(1);


    private int port;
    private byte[] response;
    private String tlsProtocol = null;
    ServerSocket serverSocket = null;

    List<String> lineBuffer = null;

    private String[] cipherSuites;

    Object[] creds = null;

    public HttpResponder(byte[] response, List<String> lineBuffer)
    {
        this.response = response;
        this.lineBuffer = lineBuffer;
    }

    public HttpResponder(byte[] response)
    {
        this.response = response;
    }

    public HttpResponder(List<String> lineBuffer)
    {
        this.lineBuffer = lineBuffer;
    }

    public HttpResponder()
    {
    }

    public void run()
    {
        Random rand = new Random();
        Socket sock = null;
        try
        {
            int t = 10;
            for (; t >= 0; t--)
            {
                port = 8000 + rand.nextInt(1000);

                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(null, "password".toCharArray());
                if (creds == null)
                {
                    creds = readCertAndKey(ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem"));
                    ks.setKeyEntry("server", KeyFactory.getInstance("EC").generatePrivate(((PKCS8EncodedKeySpec)creds[1])), "password".toCharArray(), new Certificate[]{(Certificate)creds[0]});
                }
                else
                {
                    ks.setKeyEntry("server", (Key)creds[1], "password".toCharArray(), new Certificate[]{(Certificate)creds[0]});
                }

                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(ks, "password".toCharArray());

                SSLContext sslContext = SSLContext.getInstance("TLS");

                sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());

                SSLServerSocketFactory fact = sslContext.getServerSocketFactory();

                serverSocket = sslContext.getServerSocketFactory().createServerSocket();

//                for (String s : ((SSLServerSocket)serverSocket).getSupportedCipherSuites())
//                {
//                    if (s.contains("_DES"))
//                    {
//                        System.out.println(s);
//                    }
//                }

                if (cipherSuites != null)
                {
                    ((SSLServerSocket)serverSocket).setEnabledCipherSuites(cipherSuites);
                }


                if (tlsProtocol != null)
                {
                    ((SSLServerSocket)serverSocket).setEnabledProtocols(new String[]{tlsProtocol});
                }
                try
                {
                    serverSocket.bind(new InetSocketAddress(port));
                }
                catch (IOException ioex)
                {
                    continue;
                }
                break;
            }

            if (t <= 0)
            {
                throw new RuntimeException("Could not open test server socket.");
            }
            ready.countDown();
            sock = serverSocket.accept();

            if (lineBuffer != null)
            {
                BufferedReader bin = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                String line = null;
                while ((line = bin.readLine()) != null && line.length() > 0)
                {
                    lineBuffer.add(line);
                }
            }


            if (response != null)
            {
                OutputStream os = sock.getOutputStream();
                os.write(response);
                os.flush();
                close.await(60, TimeUnit.SECONDS);
                os.close();
                sock.close();
            }


        }
        catch (InterruptedException ie)
        {
            try
            {
                sock.close();

            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        finally
        {
            try
            {
                serverSocket.close();
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }

            finished.countDown();
        }
    }

    public int open(byte[] response)
        throws Exception
    {
        this.response = response;
        Thread t = new Thread(this);
        t.setPriority(Thread.MIN_PRIORITY);
        t.setDaemon(true);
        t.start();
        ready.await(5, TimeUnit.SECONDS);
        return port;
    }

    public void close()
    {
        close.countDown();
    }


    public String[] getSupportedCipherSuites()
    {
        return ((SSLServerSocket)serverSocket).getSupportedCipherSuites();
    }

    public String[] getEnabledSuites()
    {
        return ((SSLServerSocket)serverSocket).getEnabledCipherSuites();
    }

    public void setCipherSuites(String[] cipherSuites)
    {
        this.cipherSuites = cipherSuites;
    }

    public CountDownLatch getFinished()
    {
        return finished;
    }

    public HttpResponder withTlsProtocol(String prot)
    {
        this.tlsProtocol = prot;
        return this;
    }

    public Object[] readCertAndKey(File path)
        throws Exception
    {

        Object[] out = new Object[2];
        FileReader fr = new FileReader(path);
        PemReader reader = new PemReader(fr);
        out[0] = toJavaX509Certificate(new X509CertificateHolder(reader.readPemObject().getContent()));
        out[1] = new PKCS8EncodedKeySpec(reader.readPemObject().getContent());
        reader.close();
        fr.close();
        return out;
    }

    public HttpResponder withCreds(java.security.cert.X509Certificate cert, PrivateKey aPrivate)
    {
        this.creds = new Object[]{cert, aPrivate};

        return this;
    }


    public java.security.cert.X509Certificate toJavaX509Certificate(Object o)
        throws Exception
    {
        CertificateFactory fac = CertificateFactory.getInstance("X509");
        if (o instanceof X509CertificateHolder)
        {
            return (java.security.cert.X509Certificate)fac.generateCertificate(new ByteArrayInputStream(((X509CertificateHolder)o).getEncoded()));
        }
        else if (o instanceof X509Certificate)
        {
            return (java.security.cert.X509Certificate)fac.generateCertificate(new ByteArrayInputStream(((X509Certificate)o).getEncoded()));
        }
        else if (o instanceof java.security.cert.X509Certificate)
        {
            return (java.security.cert.X509Certificate)o;
        }
        throw new IllegalArgumentException("Object not X509CertificateHolder, javax..X509Certificate or java...X509Certificate");
    }


}
