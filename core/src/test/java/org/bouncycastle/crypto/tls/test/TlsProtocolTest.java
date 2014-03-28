package org.bouncycastle.crypto.tls.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.tls.SRPTlsParameters;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsProtocol;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class TlsProtocolTest
    extends TestCase
{
    
    public void testClientServerNonBlocking() throws Exception
    {
        clientServerNonBlocking(new MockTlsServer(), new MockTlsClient(null));
    }
    
    public void testSRPClientServer() throws Exception
    {
        Charset utf8 = Charset.forName("UTF-8");
        
        // test vectors from RFC 5054 appendix B
        byte[] identity = "alice".getBytes(utf8);
        byte[] password = "password123".getBytes(utf8);
        byte[] salt = Hex.decode("BEB25379D1A8581EB5A727673A2441EE");
        BigInteger prime = new BigInteger(1, Hex.decode(
                "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813"
                + "D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885"
                + "C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"));
        BigInteger generator = BigInteger.valueOf(2);
        
        SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
        verifierGenerator.init(prime, generator, new SHA1Digest());
        BigInteger verifier = verifierGenerator.generateVerifier(salt, identity, password);
        
        MockSRPTlsClient client = new MockSRPTlsClient(identity, password);
        MockSRPTlsServer server = new MockSRPTlsServer(new SRPTlsParameters(verifier, salt, prime, generator));
        
        clientServerNonBlocking(server, client);
    }
    
    private void clientServerNonBlocking(ITestTlsServer server, ITestTlsClient client) throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        
        ByteArrayOutputStream clientWrite = new ByteArrayOutputStream();
        ByteArrayOutputStream serverWrite = new ByteArrayOutputStream();
        
        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientWrite, secureRandom);
        clientProtocol.connect(client);
        
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverWrite, secureRandom);
        serverProtocol.accept(server);
        
        // pump handshake
        ByteBuffer clientRead = ByteBuffer.wrap(new byte[0]);
        ByteBuffer serverRead = ByteBuffer.wrap(new byte[0]);
        while (true)
        {
            serverRead = pumpData(clientProtocol, clientRead, clientWrite);
            clientRead = pumpData(serverProtocol, serverRead, serverWrite);
            
            if (serverRead.limit() == 0 && clientRead.limit() == 0)
            {
                break;
            }
        }
        
        byte[] data = new byte[1000];
        secureRandom.nextBytes(data);
        
        // send data from client to server
        serverRead = write(clientProtocol, data, clientWrite);
        pumpData(serverProtocol, serverRead, serverWrite);
        assertTrue(Arrays.areEqual(data, server.getReceivedAppData()));
        
        // send data from server to client
        clientRead = write(serverProtocol, data, serverWrite);
        pumpData(clientProtocol, clientRead, clientWrite);
        assertTrue(Arrays.areEqual(data, client.getReceivedAppData()));
        
        // shut down the connection
        clientProtocol.getOutputStream().close();
        serverRead = ByteBuffer.wrap(clientWrite.toByteArray());
        pumpData(serverProtocol, serverRead, serverWrite);
        
        // attempting to send or receive any data on either side should throw an exception now
        checkClosed(clientProtocol);
        checkClosed(serverProtocol);
    }
    
    private static ByteBuffer pumpData(TlsProtocol protocol, ByteBuffer read, ByteArrayOutputStream write) throws IOException
    {
        while (read.hasRemaining())
        {
            protocol.offerInput(read);
        }
        ByteBuffer written = ByteBuffer.wrap(write.toByteArray());
        write.reset();
        return written;
    }
    
    private static ByteBuffer write(TlsProtocol protocol, byte[] data, ByteArrayOutputStream write) throws IOException
    {
        protocol.getOutputStream().write(data);
        ByteBuffer written = ByteBuffer.wrap(write.toByteArray());
        write.reset();
        return written;
    }
    
    private static void checkClosed(TlsProtocol protocol)
    {
        try
        {
            protocol.offerInput(ByteBuffer.allocate(1));
            fail("Input was accepted after close");
        }
        catch (Exception e)
        {
        }
        try
        {
            protocol.getOutputStream().write(1);
            fail("Output was accepted after close");
        }
        catch (Exception e)
        {
        }
    }
    
    public void testClientServer()
        throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();

        PipedInputStream clientRead = new PipedInputStream();
        PipedInputStream serverRead = new PipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite, secureRandom);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite, secureRandom);

        ServerThread serverThread = new ServerThread(serverProtocol);
        serverThread.start();

        MockTlsClient client = new MockTlsClient(null);
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

        ServerThread(TlsServerProtocol serverProtocol)
        {
            this.serverProtocol = serverProtocol;
        }

        public void run()
        {
            try
            {
                MockTlsServer server = new MockTlsServer();
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
