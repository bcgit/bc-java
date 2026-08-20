package org.bouncycastle.tls;

import java.util.Hashtable;
import java.util.Vector;

import junit.framework.TestCase;

import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

/**
 * What {@link AbstractTlsServer#notifyHandshakeBeginning()} has to clear before the next handshake on
 * a reused server.
 * <p/>
 * {@link AbstractTlsServer#processClientExtensions} assigns "status_request_v2" and "trusted_ca_keys"
 * only when the ClientHello carried extensions at all, so a field left standing from the previous
 * handshake is a field the next one inherits. That matters because the server decides whether to echo
 * from these fields: echoing an extension the client did not offer has it abort with
 * unsupported_extension (RFC 5246 sec. 7.4.1.4). "status_request" was already cleared here; its two
 * neighbours were not.
 */
public class AbstractTlsServerResetTest
    extends TestCase
{
    public void testStatusRequestExtensionsAreClearedBetweenHandshakes()
        throws Exception
    {
        MockServer server = new MockServer();

        server.processClientExtensions(statusRequestExtensions());

        assertNotNull("the test should have offered status_request", server.certificateStatusRequest);
        assertNotNull("the test should have offered status_request_v2", server.statusRequestV2);

        server.notifyHandshakeBeginning();

        assertNull("status_request should not survive into the next handshake",
            server.certificateStatusRequest);
        assertNull("status_request_v2 should not survive into the next handshake",
            server.statusRequestV2);
    }

    public void testTrustedCAKeysIsClearedBetweenHandshakes()
        throws Exception
    {
        MockServer server = new MockServer();

        Hashtable clientExtensions = new Hashtable();
        TlsExtensionsUtils.addTrustedCAKeysExtensionClient(clientExtensions, new Vector());

        server.processClientExtensions(clientExtensions);

        assertNotNull("the test should have offered trusted_ca_keys", server.trustedCAKeys);

        server.notifyHandshakeBeginning();

        assertNull("trusted_ca_keys should not survive into the next handshake", server.trustedCAKeys);
    }

    /**
     * The case the reset exists for: a second ClientHello with no extensions at all leaves
     * processClientExtensions with nothing to assign, so anything not cleared is still the first
     * handshake's.
     */
    public void testExtensionlessClientHelloInheritsNothing()
        throws Exception
    {
        MockServer server = new MockServer();

        server.processClientExtensions(statusRequestExtensions());

        server.notifyHandshakeBeginning();
        server.processClientExtensions(null);

        assertNull("an extensionless ClientHello must not inherit status_request_v2",
            server.statusRequestV2);
        assertNull("an extensionless ClientHello must not inherit status_request",
            server.certificateStatusRequest);
        assertNull("an extensionless ClientHello must not inherit trusted_ca_keys",
            server.trustedCAKeys);
    }

    private static Hashtable statusRequestExtensions()
        throws Exception
    {
        OCSPStatusRequest ocspStatusRequest = new OCSPStatusRequest(null, null);

        Hashtable clientExtensions = new Hashtable();
        TlsExtensionsUtils.addStatusRequestExtension(clientExtensions,
            new CertificateStatusRequest(CertificateStatusType.ocsp, ocspStatusRequest));

        Vector statusRequestV2 = new Vector();
        statusRequestV2.addElement(new CertificateStatusRequestItemV2(CertificateStatusType.ocsp_multi,
            ocspStatusRequest));
        TlsExtensionsUtils.addStatusRequestV2Extension(clientExtensions, statusRequestV2);

        return clientExtensions;
    }

    private static class MockServer
        extends AbstractTlsServer
    {
        MockServer()
        {
            super(new BcTlsCrypto());
        }

        public TlsCredentials getCredentials()
        {
            throw new UnsupportedOperationException();
        }

        protected int[] getSupportedCipherSuites()
        {
            return new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 };
        }
    }
}
