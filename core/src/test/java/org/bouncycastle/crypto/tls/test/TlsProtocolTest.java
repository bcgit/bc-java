package org.bouncycastle.crypto.tls.test;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.agreement.srp.SRP6GroupParameters;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.tls.SRPTlsParameters;
import org.bouncycastle.crypto.tls.TlsClient;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsServer;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class TlsProtocolTest
    extends TestCase
{
    public void testClientServer() throws Exception
    {
        clientServer(new MockTlsClient(null), new MockTlsServer());
    }
    
    public void testSRPClientServer() throws Exception
    {
        Charset utf8 = Charset.forName("UTF-8");
        
        // test vectors from RFC 5054 appendix B
        byte[] identity = "alice".getBytes(utf8);
        byte[] password = "password123".getBytes(utf8);
        byte[] salt = Hex.decode("BEB25379D1A8581EB5A727673A2441EE");
        BigInteger prime = SRP6GroupParameters.PRIME_1024;
        BigInteger generator = SRP6GroupParameters.GENERATOR_1024;

        SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
        verifierGenerator.init(prime, generator, new SHA1Digest());
        BigInteger verifier = verifierGenerator.generateVerifier(salt, identity, password);
        
        MockSRPTlsClient client = new MockSRPTlsClient(identity, password);
        MockSRPTlsServer server = new MockSRPTlsServer(new SRPTlsParameters(verifier, salt, prime, generator));
        
        clientServer(client, server);
    }
    
    private void clientServer(TlsClient client, TlsServer server)
        throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();

        PipedInputStream clientRead = new PipedInputStream();
        PipedInputStream serverRead = new PipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite, secureRandom);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite, secureRandom);

        ServerThread serverThread = new ServerThread(serverProtocol, server);
        serverThread.start();

        clientProtocol.connect(client);

        // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
        int length = 1000;

        byte[] data = new byte[length];
        secureRandom.nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echo = new byte[data.length];
        int count = Streams.readFully(clientProtocol.getInputStream(), echo);

        assertEquals(count, data.length);
        assertTrue(Arrays.areEqual(data, echo));

        output.close();

        serverThread.join();
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;
        private final TlsServer server;

        ServerThread(TlsServerProtocol serverProtocol, TlsServer server)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
        }

        public void run()
        {
            try
            {
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
//                throw new RuntimeException(e);
            }
        }
    }
}
