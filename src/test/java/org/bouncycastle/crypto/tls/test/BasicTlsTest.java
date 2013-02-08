package org.bouncycastle.crypto.tls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.tls.AlwaysValidVerifyer;
import org.bouncycastle.crypto.tls.TlsProtocolHandler;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class BasicTlsTest
    extends TestCase
{
    private static final int PORT_NO = 8003;
//    private static final String CLIENT = "client";
//    private static final char[] CLIENT_PASSWORD = "clientPassword".toCharArray();
//    private static final char[] SERVER_PASSWORD = "serverPassword".toCharArray();
//    private static final char[] TRUST_STORE_PASSWORD = "trustPassword".toCharArray();

    public void testConnection()
        throws Exception
    {
        Thread server = new HTTPSServerThread();

        server.start();

        Thread.yield();
        
        AlwaysValidVerifyer verifyer = new AlwaysValidVerifyer();
        Socket s = null;

        for (int i = 0; s == null && i != 3; i++)
        {
            Thread.sleep(1000);

            try
            {
                s = new Socket("localhost", PORT_NO);
            }
            catch (IOException e)
            {
                // ignore
            }
        }

        if (s == null)
        {
            throw new IOException("unable to connect");
        }
        
//        long time = System.currentTimeMillis();
        TlsProtocolHandler handler = new TlsProtocolHandler(s.getInputStream(), s.getOutputStream());
        handler.connect(verifyer);
        InputStream is = handler.getInputStream();
        OutputStream os = handler.getOutputStream();

        os.write("GET / HTTP/1.1\r\n\r\n".getBytes());

//        time = System.currentTimeMillis();
        byte[] buf = new byte[4096];
        int read = 0;
        int total = 0;

        while ((read = is.read(buf, total, buf.length - total)) > 0)
        {
            total += read;
        }

        is.close();

        byte[] expected = Hex.decode("485454502f312e3120323030204f4b0d0a436f6e74656e742d547970653a20746578742f68"
             + "746d6c0d0a0d0a3c68746d6c3e0d0a3c626f64793e0d0a48656c6c6f20576f726c64210d0a3c2f626f64793e0d0a3c2f"
             + "68746d6c3e0d0a");
       assertEquals(total, expected.length);

        byte[] tmp = new byte[expected.length];
        System.arraycopy(buf, 0, tmp, 0, total);
        assertTrue(Arrays.areEqual(expected, tmp));
    }

    public static TestSuite suite()
    {
        return new TestSuite(BasicTlsTest.class);
    }

    public static void main (String[] args)
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }
}
