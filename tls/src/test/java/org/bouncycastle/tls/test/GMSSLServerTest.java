package org.bouncycastle.tls.test;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jsse.provider.gm.GMSimpleSSLServer;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.*;
import java.net.*;
import java.security.SecureRandom;

/**
 * A simple test designed to conduct a GMSSL handshake with an external GMSSL client.
 *
 * @author Cliven
 * @since 2021-03-16 09:57:58
 */
public class GMSSLServerTest
{
    static BcTlsCrypto crypto;
    static AsymmetricKeyParameter signKey;
    static AsymmetricKeyParameter encKey;
    static Certificate certList;

    public static void main(String[] args) throws Exception
    {

        int port = 5559;
        ServerSocket ss = new ServerSocket(port, 16);

        crypto = new BcTlsCrypto(new SecureRandom());

        certList = new Certificate(new TlsCertificate[]{
                TlsTestUtils.loadCertificateResource(crypto, "x509-server-sm2-sign.pem"),
                TlsTestUtils.loadCertificateResource(crypto, "x509-server-sm2-enc.pem"),
        });

        signKey = TlsTestUtils.loadBcPrivateKeyResource("x509-server-key-sm2-sign.pem");
        encKey = TlsTestUtils.loadBcPrivateKeyResource("x509-server-key-sm2-enc.pem");

        try
        {
            while (true)
            {
                Socket s = ss.accept();
                System.out.println("--------------------------------------------------------------------------------");
                System.out.println("Accepted " + s);
                ServerThread t = new ServerThread(s);
                t.start();
            }
        } finally
        {
            ss.close();
        }
    }

    static class ServerThread extends Thread
    {
        private final Socket s;

        ServerThread(Socket s)
        {
            this.s = s;
        }

        public void run()
        {
            try
            {
                GMSimpleSSLServer server = new GMSimpleSSLServer(crypto, certList, signKey, encKey);
                TlsServerProtocol serverProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream());
                serverProtocol.accept(server);

                final InputStream in = serverProtocol.getInputStream();
                InputStreamReader isr = new InputStreamReader(in);
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

                OutputStream outputStream = serverProtocol.getOutputStream();
                String resp = "HTTP/1.1 200 OK\r\n" + "Content-Length: 6\r\n" + "Content-Type: text/plain; charset=utf-8\r\n" + "\r\n" + "hello\n";
                outputStream.write(resp.getBytes("UTF-8"));
                outputStream.flush();
                serverProtocol.close();
                System.out.println(">> Responded");
            } catch (Exception e)
            {
                if(e instanceof EOFException)
                {
                    return;
                }
                throw new RuntimeException(e);
            } finally
            {
                try
                {
                    s.close();
                } catch (IOException e)
                {
                } finally
                {
                }
            }
        }
    }
}
