package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PrintStream;

import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;

public class MockDTLSServer extends DefaultTlsServer {

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause) {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS server raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
            + ")");
        if (message != null) {
            out.println(message);
        }
        if (cause != null) {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription) {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS server received alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
            + ")");
    }

    protected ProtocolVersion getMaximumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    protected ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[] { "x509-server.pem", "x509-ca.pem" },
            "x509-server-key.pem");
    }

    protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
        return TlsTestUtils.loadSignerCredentials(context, new String[] { "x509-server.pem", "x509-ca.pem" },
            "x509-server-key.pem");
    }
}
