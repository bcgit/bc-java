package org.bouncycastle.crypto.tls.test;

import java.io.IOException;

import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;

public class MockDTLSServer extends DefaultTlsServer {

    protected ProtocolVersion getMaximumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    protected ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[] { "x509-server.pem",
            "x509-ca.pem" }, "x509-server-key.pem");
    }

    protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
        return TlsTestUtils.loadSignerCredentials(context, new String[] { "x509-server.pem",
            "x509-ca.pem" }, "x509-server-key.pem");
    }
}
