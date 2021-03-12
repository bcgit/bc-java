package org.bouncycastle.tls.test;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.*;
import java.net.*;
import java.security.SecureRandom;

/**
 * A simple test designed to conduct a GMSSL handshake with an external GMSSL client.
 * <p>
 *
 * </p>
 */
public class GMSSLServerTest
{
    public static void main(String[] args) throws Exception
    {

        int port = 5557;

        ServerSocket ss = new ServerSocket(port, 16);
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
            byte[] buff = new byte[2028];
            try
            {
                MockGMSSLServer server = new MockGMSSLServer();
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
                String resp = "HTTP/1.1 200 OK\r\n"
                        + "Content-Length: 6\r\n"
                        + "Content-Type: text/plain; charset=utf-8\r\n"
                        + "\r\n"
                        + "hello\n";
                outputStream.write(resp.getBytes("UTF-8"));
                outputStream.flush();
                serverProtocol.close();
                System.out.println(">> Responded");
            } catch (Exception e)
            {
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
