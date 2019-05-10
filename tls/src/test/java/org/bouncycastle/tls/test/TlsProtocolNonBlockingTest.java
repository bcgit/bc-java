package org.bouncycastle.tls.test;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;

public class TlsProtocolNonBlockingTest
    extends TestCase
{
    public void testClientServerFragmented() throws IOException
    {
        // tests if it's really non-blocking when partial records arrive
        testClientServer(true);
    }

    public void testClientServerNonFragmented() throws IOException
    {
        testClientServer(false);
    }

    private static void testClientServer(boolean fragment) throws IOException
    {
        SecureRandom secureRandom = new SecureRandom();

        TlsClientProtocol clientProtocol = new TlsClientProtocol();
        TlsServerProtocol serverProtocol = new TlsServerProtocol();

        clientProtocol.connect(new MockTlsClient(null));
        serverProtocol.accept(new MockTlsServer());

        // pump handshake
        boolean hadDataFromServer = true;
        boolean hadDataFromClient = true;
        while (hadDataFromServer || hadDataFromClient)
        {
            hadDataFromServer = pumpData(serverProtocol, clientProtocol, fragment);
            hadDataFromClient = pumpData(clientProtocol, serverProtocol, fragment);
        }

        // send data in both directions
        byte[] data = new byte[1024];
        secureRandom.nextBytes(data);
        writeAndRead(clientProtocol, serverProtocol, data, fragment);
        writeAndRead(serverProtocol, clientProtocol, data, fragment);

        // close the connection
        clientProtocol.close();
        pumpData(clientProtocol, serverProtocol, fragment);
        serverProtocol.closeInput();
        checkClosed(serverProtocol);
        checkClosed(clientProtocol);
    }

    private static void writeAndRead(TlsProtocol writer, TlsProtocol reader, byte[] data, boolean fragment)
        throws IOException
    {
        int dataSize = data.length;
        writer.writeApplicationData(data, 0, dataSize);
        pumpData(writer, reader, fragment);

        assertEquals(dataSize, reader.getAvailableInputBytes());
        byte[] readData = new byte[dataSize];
        reader.readInput(readData, 0, dataSize);
        assertArrayEquals(data, readData);
    }

    private static boolean pumpData(TlsProtocol from, TlsProtocol to, boolean fragment) throws IOException
    {
        int byteCount = from.getAvailableOutputBytes();
        if (byteCount == 0)
        {
            return false;
        }

        if (fragment)
        {
            byte[] buffer = new byte[1];
            while (from.getAvailableOutputBytes() > 0)
            {
                from.readOutput(buffer, 0, 1);
                to.offerInput(buffer);
            }
        }
        else
        {
            byte[] buffer = new byte[byteCount];
            from.readOutput(buffer, 0, buffer.length);
            to.offerInput(buffer);
        }

        return true;
    }

    private static void checkClosed(TlsProtocol protocol)
    {
        assertTrue(protocol.isClosed());

        try
        {
            protocol.offerInput(new byte[10]);
            fail("Input was accepted after close");
        }
        catch (IOException e)
        {
        }

        try
        {
            protocol.writeApplicationData(new byte[10], 0, 10);
            fail("Output was accepted after close");
        }
        catch (IOException e)
        {
        }
    }

    private static void assertArrayEquals(byte[] a, byte[] b)
    {
        assertTrue(Arrays.areEqual(a, b));
    }
}
