package org.bouncycastle.tls.test;


import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jsse.provider.gm.GMSimpleSSLSocketFactory;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

public class GMSimpleSSLSocketFactoryTest
{
    static final int port = 5558;

    public static void main(String[] args) throws IOException, InterruptedException
    {

        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
        final Certificate certList = new Certificate(new TlsCertificate[]{
                TlsTestUtils.loadCertificateResource(crypto, "x509-server-sm2-sign.pem"),
                TlsTestUtils.loadCertificateResource(crypto, "x509-server-sm2-enc.pem"),
                });
        final AsymmetricKeyParameter signKey = TlsTestUtils.loadBcPrivateKeyResource("x509-server-key-sm2-sign.pem");
        final AsymmetricKeyParameter encKey = TlsTestUtils.loadBcPrivateKeyResource("x509-server-key-sm2-enc.pem");


        bootServer(port, certList, signKey, encKey);

//        bootClient("localhost", port);

    }

    private static void bootServer(int port, Certificate certList, AsymmetricKeyParameter signKey, AsymmetricKeyParameter encKey)
    {
        ServerSocket ss = null;
        try
        {
            final GMSimpleSSLSocketFactory socketFactory = GMSimpleSSLSocketFactory.ServerFactory(certList, signKey, encKey);
            ss = new ServerSocket(port, 16);

            while (true)
            {
                Socket s = ss.accept();
                System.out.println("--------------------------------------------------------------------------------");
                System.out.println("Accepted " + s);
                s = socketFactory.createSocket(s, "", 0, true);
                new Thread(new ServerThread(s)).start();
            }
        } catch (IOException e)
        {
            e.printStackTrace();
        } finally
        {
            try
            {
                if(ss != null)
                {
                    ss.close();
                }
            } catch (IOException e)
            {
            }
        }
    }

    private static void bootClient(String host, int port) throws IOException
    {
        final GMSimpleSSLSocketFactory socketFactory = GMSimpleSSLSocketFactory.ClientFactory();
        final Socket cSock = socketFactory.createSocket(host, port);
        OutputStream out = cSock.getOutputStream();
        String req = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Connection: close\r\n\r\n";

        out.write(req.getBytes("UTF-8"));
        out.flush();
        InputStream in = cSock.getInputStream();
        Streams.pipeAll(in, System.out);
        out.close();
        in.close();
    }

    static class ServerThread implements Runnable
    {
        private final Socket socket;

        public ServerThread(Socket s)
        {
            this.socket = s;
        }

        public void run()
        {
            try
            {
                InputStreamReader isr = new InputStreamReader(socket.getInputStream());
                BufferedReader br = new BufferedReader(isr);
                System.out.println(">> Request:\n");
                String lineContent = null;
                while ((lineContent = br.readLine()) != null)
                {
                    if(lineContent.length() == 0)
                    {
                        break;
                    }
                    System.out.println("> " + lineContent);
                }
                System.out.println();

                OutputStream outputStream = socket.getOutputStream();
                String resp = "HTTP/1.1 200 OK\r\n" + "Content-Length: 6\r\n" + "Content-Type: text/plain; charset=utf-8\r\n" + "\r\n" + "hello\n";
                outputStream.write(resp.getBytes("UTF-8"));
                outputStream.flush();
                socket.close();
                System.out.println(">> Responded");
            } catch (IOException e)
            {
                if(e instanceof EOFException)
                {
                    return;
                }
                e.printStackTrace();
            } finally
            {
                try
                {
                    socket.close();
                } catch (IOException e)
                {

                }
            }
        }
    }

}