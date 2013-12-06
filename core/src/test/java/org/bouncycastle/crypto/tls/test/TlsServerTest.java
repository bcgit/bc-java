package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

import org.bouncycastle.crypto.tls.TlsServerProtocol;

/**
 * A simple test designed to conduct a TLS handshake with an external TLS client.
 * <p/>
 * Please refer to GnuTLSSetup.txt or OpenSSLSetup.txt, and x509-*.pem files in this package for
 * help configuring an external TLS client.
 */
public class TlsServerTest
{
    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args)
        throws Exception
    {
        InetAddress address = InetAddress.getLocalHost();
        int port = 5556;

        ServerSocket ss = new ServerSocket(port, 16, address);
        while (true)
        {
            Socket s = ss.accept();
            System.out.println("--------------------------------------------------------------------------------");
            System.out.println("Accepted " + s);
            ServerThread t = new ServerThread(s);
            t.start();
        }
    }

    static class ServerThread
        extends Thread
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
                long time1 = System.currentTimeMillis();

                MockTlsServer server = new MockTlsServer();
                TlsServerProtocol serverProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream(), secureRandom);
                serverProtocol.accept(server);
                // Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();

                long time2 = System.currentTimeMillis();
                System.out.println("Elapsed 1: " + (time2 - time1) + "ms");
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
            finally
            {
                try
                {
                    s.close();
                }
                catch (IOException e)
                {
                }
                finally
                {
                }
            }
        }
    }
}
