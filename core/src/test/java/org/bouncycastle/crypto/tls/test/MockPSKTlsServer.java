package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.PSKTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsPSKIdentityManager;
import org.bouncycastle.util.Strings;

class MockPSKTlsServer
    extends PSKTlsServer
{
    MockPSKTlsServer()
    {
        super(new MyIdentityManager());
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-PSK server raised alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
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
        out.println("TLS-PSK server received alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        byte[] pskIdentity = context.getSecurityParameters().getPSKIdentity();
        if (pskIdentity != null)
        {
            String name = Strings.fromUTF8ByteArray(pskIdentity);
            System.out.println("TLS-PSK server completed handshake for PSK identity: " + name);
        }
    }

    protected int[] getCipherSuites()
    {
        return new int[]{ CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA };
    }

    protected ProtocolVersion getMaximumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    protected ProtocolVersion getMinimumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS-PSK server negotiated " + serverVersion);

        return serverVersion;
    }

    protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{ "x509-server.pem", "x509-ca.pem" },
            "x509-server-key.pem");
    }

    static class MyIdentityManager
        implements TlsPSKIdentityManager
    {
        public byte[] getHint()
        {
            return Strings.toUTF8ByteArray("hint");
        }

        public byte[] getPSK(byte[] identity)
        {
            if (identity != null)
            {
                String name = Strings.fromUTF8ByteArray(identity);
                if (name.equals("client"))
                {
                    return new byte[16];
                }
            }
            return null;
        }
    }
}
