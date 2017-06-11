package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.security.SecureRandom;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientContext;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsKeyExchange;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;
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
        if (parts == null || parts.length != 2)
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

    public void testRSAConnectionClient()
        throws Exception
    {
        MyTlsClient client = new MyTlsClient(null);

        checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, TlsTestUtils.rsaCertData);
        checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, TlsTestUtils.rsaCertData);
        checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, TlsTestUtils.rsaCertData);
        checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_RC4_128_SHA, TlsTestUtils.rsaCertData);

        try
        {
            checkConnectionClient(client, CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, TlsTestUtils.dudRsaCertData);

            fail("dud certificate not caught");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.certificate_unknown, e.getAlertDescription());
        }

        try
        {
            checkConnectionClient(client, CipherSuite.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, TlsTestUtils.rsaCertData);

            fail("wrong certificate not caught");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
    }

    private void checkConnectionClient(TlsClient client, int cipherSuite, byte[] encCert)
        throws Exception
    {
        TlsCrypto crypto = client.getCrypto();

        client.notifySelectedCipherSuite(cipherSuite);

        TlsKeyExchange keyExchange = client.getKeyExchange();
        keyExchange.init(new MyTlsClientContext(crypto));

        keyExchange
            .processServerCertificate(new Certificate(
                new TlsCertificate[]{ crypto.createCertificate(encCert) }));
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
                out.println(message);
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
        }

        public TlsAuthentication getAuthentication()
            throws IOException
        {
            return authentication;
        }
    }

    static class MyTlsClientContext
        implements TlsClientContext
    {
        TlsCrypto crypto;

        MyTlsClientContext(TlsCrypto crypto)
        {
            this.crypto = crypto;
        }

        public TlsCrypto getCrypto()
        {
            return crypto;
        }

        public TlsNonceGenerator getNonceGenerator()
        {
            throw new UnsupportedOperationException();
        }

        public SecureRandom getSecureRandom()
        {
            throw new UnsupportedOperationException();
        }

        public SecurityParameters getSecurityParameters()
        {
            throw new UnsupportedOperationException();
        }

        public boolean isServer()
        {
            return false;
        }

        public ProtocolVersion getClientVersion()
        {
            return ProtocolVersion.TLSv12;
        }

        public ProtocolVersion getServerVersion()
        {
            return ProtocolVersion.TLSv12;
        }

        public TlsSession getResumableSession()
        {
            return null;
        }

        public TlsSession getSession()
        {
            return null;
        }

        public Object getUserObject()
        {
            throw new UnsupportedOperationException();
        }

        public void setUserObject(Object userObject)
        {
            throw new UnsupportedOperationException();
        }

        public byte[] exportChannelBinding(int channelBinding)
        {
            throw new UnsupportedOperationException();
        }

        public byte[] exportKeyingMaterial(String asciiLabel, byte[] context_value, int length)
        {
            throw new UnsupportedOperationException();
        }
    }
}
