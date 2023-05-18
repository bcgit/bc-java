package org.bouncycastle.tls.test;

import java.security.SecureRandom;

import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSRequest;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DTLSVerifier;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import junit.framework.TestCase;

public class DTLSProtocolTest
    extends TestCase
{
    public void testClientServer() throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        clientTransport = new UnreliableDatagramTransport(clientTransport, secureRandom, 0, 0);

        clientTransport = new LoggingDatagramTransport(clientTransport, System.out);

        MockDTLSClient client = new MockDTLSClient(null);

        DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);

        for (int i = 1; i <= 10; ++i)
        {
            byte[] data = new byte[i];
            Arrays.fill(data, (byte)i);
            dtlsClient.send(data, 0, data.length);
        }

        byte[] buf = new byte[dtlsClient.getReceiveLimit()];
        while (dtlsClient.receive(buf, 0, buf.length, 100) >= 0)
        {
        }

        dtlsClient.close();

        serverThread.shutdown();
    }

    static class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;

        ServerThread(DTLSServerProtocol serverProtocol, DatagramTransport serverTransport)
        {
            this.serverProtocol = serverProtocol;
            this.serverTransport = serverTransport;
        }

        public void run()
        {
            try
            {
                MockDTLSServer server = new MockDTLSServer();

                DTLSRequest request = null;

                // Use DTLSVerifier to require a HelloVerifyRequest cookie exchange before accepting
                {
                    DTLSVerifier verifier = new DTLSVerifier(server.getCrypto());

                    // NOTE: Test value only - would typically be the client IP address
                    byte[] clientID = Strings.toUTF8ByteArray("MockDtlsClient");

                    int receiveLimit = serverTransport.getReceiveLimit();
                    int dummyOffset = server.getCrypto().getSecureRandom().nextInt(16) + 1;
                    byte[] transportBuf = new byte[dummyOffset + serverTransport.getReceiveLimit()];

                    do
                    {
                        if (isShutdown)
                            return;

                        int length = serverTransport.receive(transportBuf, dummyOffset, receiveLimit, 1000);
                        if (length > 0)
                        {
                            request = verifier.verifyRequest(clientID, transportBuf, dummyOffset, length,
                                serverTransport);
                        }
                    }
                    while (request == null);
                }

                DTLSTransport dtlsServer = serverProtocol.accept(server, serverTransport, request);                
                byte[] buf = new byte[dtlsServer.getReceiveLimit()];
                while (!isShutdown)
                {
                    int length = dtlsServer.receive(buf, 0, buf.length, 1000);
                    if (length >= 0)
                    {
                        dtlsServer.send(buf, 0, length);
                    }
                }
                dtlsServer.close();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }

        void shutdown()
            throws InterruptedException
        {
            if (!isShutdown)
            {
                isShutdown = true;
                this.join();
            }
        }
    }
}
