package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.AbstractTlsServer;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.BasicTlsPSKExternal;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.PskIdentity;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsPSKExternal;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Strings;

class MockPSKTls13Server
    extends AbstractTlsServer
{
    private final boolean badKey;

    MockPSKTls13Server()
    {
        this(false);
    }

    MockPSKTls13Server(boolean badKey)
    {
        super(new BcTlsCrypto());

        this.badKey = badKey;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        return null;
    }

    protected Vector getProtocolNames()
    {
        Vector protocolNames = new Vector();
        protocolNames.addElement(ProtocolName.HTTP_2_TLS);
        protocolNames.addElement(ProtocolName.HTTP_1_1);
        return protocolNames;
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(),
            new int[]{ CipherSuite.TLS_AES_128_CCM_8_SHA256, CipherSuite.TLS_AES_128_CCM_SHA256,
                CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_CHACHA20_POLY1305_SHA256 });
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv13.only();
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS 1.3 PSK server negotiated " + serverVersion);

        return serverVersion;
    }

    public TlsPSKExternal getExternalPSK(Vector identities)
    {
        byte[] identity = Strings.toUTF8ByteArray("client");
        long obfuscatedTicketAge = 0L;

        PskIdentity matchIdentity = new PskIdentity(identity, obfuscatedTicketAge);

        for (int i = 0, count = identities.size(); i < count; ++i)
        {
            if (matchIdentity.equals(identities.elementAt(i)))
            {
                TlsSecret key = getCrypto().createSecret(TlsTestUtils.getPSKPasswordUTF8(badKey));
                int prfAlgorithm = PRFAlgorithm.tls13_hkdf_sha256;

                return new BasicTlsPSKExternal(identity, key, prfAlgorithm);
            }
        }
        return null;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS 1.3 PSK server raised alert: " + AlertLevel.getText(alertLevel)
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
        out.println("TLS 1.3 PSK server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
        if (protocolName != null)
        {
            System.out.println("Server ALPN: " + protocolName.getUtf8Decoding());
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
}
