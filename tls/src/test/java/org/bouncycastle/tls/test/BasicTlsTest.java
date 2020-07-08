package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;
import junit.framework.TestSuite;

public class BasicTlsTest
    extends TestCase
{
    private static final int PORT_NO = 12001;

    protected boolean isSufficientVMVersion(String vmVersion)
    {
        if (vmVersion == null)
        {
            return false;
        }
        String[] parts = vmVersion.split("\\.");
        if (parts == null || parts.length < 1)
        {
            return false;
        }
        try
        {
            int major = Integer.parseInt(parts[0]);
            if (major != 1)
            {
                return major > 1;
            }
            if (parts.length < 2)
            {
                return false;
            }
            int minor = Integer.parseInt(parts[1]);
            return minor >= 7;
        }
        catch (NumberFormatException e)
        {
            return false;
        }
    }

    public void testConnection()
        throws Exception
    {
        String vmVersion = System.getProperty("java.specification.version");
        if (!isSufficientVMVersion(vmVersion))
        {
            return; // only works on later VMs.
        }

        Thread server = new HTTPSServerThread();

        server.start();

        Thread.yield();

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

        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
        protocol.connect(new MyTlsClient(new ServerOnlyTlsAuthentication()
        {
            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException
            {
                // NOTE: In production code this MUST verify the certificate!
            }
        }));

        InputStream is = protocol.getInputStream();
        OutputStream os = protocol.getOutputStream();

        os.write("GET / HTTP/1.1\r\n\r\n".getBytes());

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

    public static void main(String[] args)
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }

    static class MyTlsClient
        extends DefaultTlsClient
    {
        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client raised alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
            if (message != null)
            {
                out.println("> " + message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }

        public void notifyAlertReceived(short alertLevel, short alertDescription)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
        }

        private final TlsAuthentication authentication;

        MyTlsClient(TlsAuthentication authentication)
        {
            super(new BcTlsCrypto(new SecureRandom()));

            this.authentication = authentication;

            this.supportedSignatureAlgorithms = new Vector();
            this.supportedSignatureAlgorithms.addElement(new SignatureAndHashAlgorithm(HashAlgorithm.md5, SignatureAlgorithm.rsa));
            this.supportedSignatureAlgorithms.addElement(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa));
            this.supportedSignatureAlgorithms.addElement(new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa));
        }

        public TlsAuthentication getAuthentication()
            throws IOException
        {
            return authentication;
        }
    }
}
