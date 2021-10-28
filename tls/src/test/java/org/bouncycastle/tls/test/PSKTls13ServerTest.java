package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.io.TeeOutputStream;

public class PSKTls13ServerTest
{
    public static void main(String[] args)
        throws Exception
    {
        InetAddress address = InetAddress.getLocalHost();
        int port = 5556;

        ServerSocket ss = new ServerSocket(port, 16, address);
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
        }
        finally
        {
            ss.close();
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
                MockPSKTls13Server server = new MockPSKTls13Server();
                TlsServerProtocol serverProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream());
                serverProtocol.accept(server);
                OutputStream log = new TeeOutputStream(serverProtocol.getOutputStream(), System.out);
                Streams.pipeAll(serverProtocol.getInputStream(), log);
                serverProtocol.close();
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
            }
        }
    }
}
