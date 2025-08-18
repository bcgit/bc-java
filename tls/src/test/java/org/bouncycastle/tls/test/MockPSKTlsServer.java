package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.tls.PSKTlsServer;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

class MockPSKTlsServer
    extends PSKTlsServer
{
    MockPSKTlsServer()
    {
        this(false);
    }

    MockPSKTlsServer(boolean badKey)
    {
        super(new BcTlsCrypto(), new MyIdentityManager(badKey));
    }

    protected Vector getProtocolNames()
    {
        Vector protocolNames = new Vector();
        protocolNames.addElement(ProtocolName.HTTP_2_TLS);
        protocolNames.addElement(ProtocolName.HTTP_1_1);
        return protocolNames;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-PSK server raised alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
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
        out.println("TLS-PSK server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS-PSK server negotiated " + serverVersion);

        return serverVersion;
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
        if (protocolName != null)
        {
            System.out.println("Server ALPN: " + protocolName.getUtf8Decoding());
        }

        byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
        System.out.println("Server 'tls-server-end-point': " + hex(tlsServerEndPoint));

        byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
        System.out.println("Server 'tls-unique': " + hex(tlsUnique));

        byte[] pskIdentity = context.getSecurityParametersConnection().getPSKIdentity();
        if (pskIdentity != null)
        {
            String name = Strings.fromUTF8ByteArray(pskIdentity);
            System.out.println("TLS-PSK server completed handshake for PSK identity: " + name);
        }
    }

    public void processClientExtensions(Hashtable clientExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getClientRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        super.processClientExtensions(clientExtensions);
    }

    public Hashtable getServerExtensions() throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return super.getServerExtensions();
    }

    public void getServerExtensionsForConnection(Hashtable serverExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        super.getServerExtensionsForConnection(serverExtensions);
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{ "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" },
            "x509-server-key-rsa-enc.pem");
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv12.only();
    }

    static class MyIdentityManager
        implements TlsPSKIdentityManager
    {
        private final boolean badKey;

        MyIdentityManager(boolean badKey)
        {
            this.badKey = badKey;
        }

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
                    return TlsTestUtils.getPSKPasswordUTF8(badKey);
                }
            }
            return null;
        }
    }
}
