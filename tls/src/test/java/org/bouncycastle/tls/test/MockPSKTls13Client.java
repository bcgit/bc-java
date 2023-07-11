package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.AbstractTlsClient;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.BasicTlsPSKExternal;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsPSK;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Strings;

class MockPSKTls13Client
    extends AbstractTlsClient
{
    MockPSKTls13Client()
    {
        super(new BcTlsCrypto());
    }

//    public Vector getEarlyKeyShareGroups()
//    {
//        return null;
//    }

//    public short[] getPskKeyExchangeModes()
//    {
//        return new short[] { PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke };
//    }

    protected Vector getProtocolNames()
    {
        Vector protocolNames = new Vector();
        protocolNames.addElement(ProtocolName.HTTP_1_1);
        protocolNames.addElement(ProtocolName.HTTP_2_TLS);
        return protocolNames;
    }

    protected int[] getSupportedCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(getCrypto(), new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 });
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv13.only();
    }

    public Vector getExternalPSKs()
    {
        byte[] identity = Strings.toUTF8ByteArray("client");
        TlsSecret key = getCrypto().createSecret(Strings.toUTF8ByteArray("TLS_TEST_PSK"));
        int prfAlgorithm = PRFAlgorithm.tls13_hkdf_sha256;

        return TlsUtils.vectorOfOne(new BasicTlsPSKExternal(identity, key, prfAlgorithm));
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS 1.3 PSK client raised alert: " + AlertLevel.getText(alertLevel)
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
        out.println("TLS 1.3 PSK client received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public void notifySelectedPSK(TlsPSK selectedPSK) throws IOException
    {
        if (null == selectedPSK)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        super.notifyServerVersion(serverVersion);

        System.out.println("TLS 1.3 PSK client negotiated " + serverVersion);
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
        if (protocolName != null)
        {
            System.out.println("Client ALPN: " + protocolName.getUtf8Decoding());
        }
    }

    public Hashtable getClientExtensions() throws IOException
    {
        if (context.getSecurityParametersHandshake().getClientRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return super.getClientExtensions();
    }

    public void processServerExtensions(Hashtable serverExtensions) throws IOException
    {
        if (context.getSecurityParametersHandshake().getServerRandom() == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        super.processServerExtensions(serverExtensions);
    }
}
