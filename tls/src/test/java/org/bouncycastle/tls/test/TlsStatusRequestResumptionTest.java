package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;

import org.bouncycastle.tls.CertificateStatusRequest;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.util.io.Streams;

/**
 * What a server puts in an abbreviated handshake's ServerHello, where "status_request" is concerned.
 * <p/>
 * A session stores the extensions the server sent when it was established, and a resumed handshake
 * replays them - but the status_request echo announces a CertificateStatus message, and an
 * abbreviated handshake sends neither a Certificate nor a CertificateStatus. Replaying it hands the
 * client an extension answering nothing, and one the resuming ClientHello need not even have offered:
 * RFC 5246 sec. 7.4.1.4 has a client abort with unsupported_extension over an extension it did not
 * request.
 * <p/>
 * Observed through {@link org.bouncycastle.tls.TlsServer#getServerExtensionsForConnection}, which the
 * protocol hands the very Hashtable it is about to send.
 */
public class TlsStatusRequestResumptionTest
    extends TestCase
{
    public void testResumedHandshakeDropsTheStatusRequestEcho()
        throws Exception
    {
        StatusRequestTlsServer server = new StatusRequestTlsServer();

        // a full handshake, with the client asking - so the echo goes into the session
        TlsSession session = runHandshake(server, null, true);

        assertNotNull("no resumable session was established", session);
        assertFalse("the first handshake should not have resumed", server.wasResumed(0));
        assertTrue("the full handshake should have echoed status_request",
            server.sentExtension(0, TlsExtensionsUtils.EXT_status_request));

        /*
         * The resuming client does not ask this time, which is what makes the replay an unsolicited
         * extension rather than merely a useless one.
         */
        runHandshake(server, session, false);

        assertTrue("the second handshake did not resume", server.wasResumed(1));
        assertFalse("a resumed ServerHello must not echo status_request",
            server.sentExtension(1, TlsExtensionsUtils.EXT_status_request));
        assertFalse("a resumed ServerHello must not echo status_request_v2",
            server.sentExtension(1, TlsExtensionsUtils.EXT_status_request_v2));
    }

    private TlsSession runHandshake(StatusRequestTlsServer server, TlsSession sessionToResume,
        boolean offerStatusRequest)
        throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        StatusRequestTlsClient client = new StatusRequestTlsClient(sessionToResume, offerStatusRequest);

        TlsProtocolTest.ServerThread serverThread = new TlsProtocolTest.ServerThread(serverProtocol,
            server);
        serverThread.start();

        clientProtocol.connect(client);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(new byte[]{ '!' });

        byte[] echo = new byte[1];
        Streams.readFully(clientProtocol.getInputStream(), echo);
        assertEquals('!', echo[0]);

        output.close();

        serverThread.join();

        return client.session;
    }

    /**
     * Pinned to TLS 1.2: the abbreviated handshake this is about is a TLS 1.2 mechanism, where TLS 1.3
     * resumes with a pre-shared key instead and carries no such echo.
     */
    private static class StatusRequestTlsClient
        extends MockTlsClient
    {
        private final boolean offerStatusRequest;

        StatusRequestTlsClient(TlsSession session, boolean offerStatusRequest)
        {
            super(session);

            this.offerStatusRequest = offerStatusRequest;
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv12.only();
        }

        protected CertificateStatusRequest getCertificateStatusRequest()
        {
            return offerStatusRequest ? super.getCertificateStatusRequest() : null;
        }
    }

    /**
     * A server that answers status requests - which is all it takes for the echo to be sent and
     * stored - and that keeps one session, so a second handshake has something to resume. It records
     * the extensions it sends per handshake for the test to read back.
     */
    private static class StatusRequestTlsServer
        extends MockTlsServer
    {
        private final List<Set<Integer>> sentExtensions = new ArrayList<Set<Integer>>();
        private final List<Boolean> resumed = new ArrayList<Boolean>();

        private TlsSession session = null;

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv12.only();
        }

        protected boolean allowCertificateStatus()
        {
            return true;
        }

        public byte[] getNewSessionID()
        {
            // AbstractTlsServer issues none by default, and without one there is nothing to resume
            byte[] sessionID = new byte[32];
            context.getCrypto().getSecureRandom().nextBytes(sessionID);
            return sessionID;
        }

        /**
         * Kept from here rather than from notifySession, which the protocol calls while the session
         * still has no parameters attached and so is not yet resumable.
         */
        public void notifyHandshakeComplete()
            throws IOException
        {
            super.notifyHandshakeComplete();

            TlsSession newSession = context.getSession();
            if (null != newSession && newSession.isResumable())
            {
                this.session = newSession;
            }
        }

        public TlsSession getSessionToResume(byte[] sessionID)
        {
            return null != session && org.bouncycastle.util.Arrays.areEqual(sessionID,
                session.getSessionID()) ? session : null;
        }

        public void getServerExtensionsForConnection(Hashtable serverExtensions)
            throws IOException
        {
            super.getServerExtensionsForConnection(serverExtensions);

            Set<Integer> keys = new HashSet<Integer>();
            for (Enumeration e = serverExtensions.keys(); e.hasMoreElements();)
            {
                keys.add((Integer)e.nextElement());
            }

            synchronized (this)
            {
                sentExtensions.add(keys);
                resumed.add(Boolean.valueOf(context.getSecurityParametersHandshake().isResumedSession()));
            }
        }

        synchronized boolean sentExtension(int handshake, Integer extensionType)
        {
            return sentExtensions.get(handshake).contains(extensionType);
        }

        synchronized boolean wasResumed(int handshake)
        {
            return resumed.get(handshake).booleanValue();
        }
    }
}
