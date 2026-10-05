package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * RFC 9147 7: ACK records travel in their own content type, are delivered to the handshake rather than to
 * the application, and a malformed ACK is discarded rather than failing the connection.
 */
public class DTLSAckTransportTest
    extends TestCase
{
    static class RecordingAckListener
        implements DTLSAckListener
    {
        final Vector received = new Vector();

        public void receivedAck(Vector recordNumbers) throws IOException
        {
            received.addElement(recordNumbers);
        }
    }

    public void testAckRoundTripsBetweenTwoRecordLayers() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(2, 0));
        recordNumbers.addElement(new DTLSRecordNumber(2, 3));

        DTLSRecordNumber sent = support.client.recordLayer.sendAck(recordNumbers);
        assertNotNull("the ACK must report its own record number", sent);

        // the ACK is not application data: receive must not surface it, but the listener must see it
        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals(1, listener.received.size());
        Vector got = (Vector)listener.received.elementAt(0);
        assertEquals(2, got.size());
        assertEquals(new DTLSRecordNumber(2, 0), got.elementAt(0));
        assertEquals(new DTLSRecordNumber(2, 3), got.elementAt(1));
    }

    public void testEmptyAckIsDelivered() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        support.client.recordLayer.sendAck(new Vector());

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals(1, listener.received.size());
        assertEquals(0, ((Vector)listener.received.elementAt(0)).size());
    }

    public void testAckWithNoListenerIsDiscarded() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        support.client.recordLayer.sendAck(new Vector());

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        // and the connection still works
        byte[] data = new byte[]{ 1, 2, 3 };
        support.client.recordLayer.send(data, 0, data.length);
        int n = support.server.recordLayer.receive(buf, 0, buf.length, 1000);
        assertEquals(3, n);
        assertTrue(Arrays.areEqual(data, Arrays.copyOf(buf, 3)));
    }

    public void testMalformedAckBodyIsDiscarded() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        // a body whose declared length does not match its contents
        byte[] bad = new byte[]{ 0, 32, 0, 0 };
        support.client.recordLayer.sendRecordForTest(ContentType.ack, bad, 0, bad.length);

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals("a malformed ACK must be discarded, not delivered", 0, listener.received.size());

        byte[] data = new byte[]{ 9 };
        support.client.recordLayer.send(data, 0, data.length);
        assertEquals(1, support.server.recordLayer.receive(buf, 0, buf.length, 1000));
    }

    /**
     * RFC 9147 7. An ACK is sent at an epoch equal to or higher than the records it acknowledges, so a
     * record number naming a higher epoch than the ACK that carried it is discarded on receipt.
     * <p>
     * Epoch 0 is unauthenticated and DTLS sequence numbers are predictable, so without this an off-path
     * attacker who can spoof the peer's address could forge a plaintext ACK naming the protected epochs,
     * retire fragments that were never delivered and stall the handshake.
     * </p>
     */
    public void testAckRecordNumbersAboveTheAckEpochAreDiscarded() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        int ackEpoch = support.server.recordLayer.getReadEpoch();

        // one record number at the ACK's own epoch, one above it
        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(ackEpoch, 7));
        recordNumbers.addElement(new DTLSRecordNumber(ackEpoch + 1, 0));

        byte[] body = DTLSAck.encode(recordNumbers);
        support.client.recordLayer.sendRecordForTest(ContentType.ack, body, 0, body.length);

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals("the ACK is still delivered", 1, listener.received.size());

        Vector got = (Vector)listener.received.elementAt(0);
        assertEquals("only the record number at or below the ACK's epoch survives", 1, got.size());
        assertEquals(new DTLSRecordNumber(ackEpoch, 7), got.elementAt(0));
    }

    /** The same rule on the sending side: rather than emit a non-compliant ACK, send none. */
    public void testAckIsNotSentBelowTheEpochOfTheRecordsItAcknowledges() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256);

        RecordingAckListener listener = new RecordingAckListener();
        support.server.recordLayer.setAckListener(listener);

        Vector recordNumbers = new Vector();
        recordNumbers.addElement(new DTLSRecordNumber(support.client.recordLayer.getReadEpoch() + 1, 0));

        assertNull("no ACK is sent below the epoch it covers",
            support.client.recordLayer.sendAck(recordNumbers));

        byte[] buf = new byte[support.server.recordLayer.getReceiveLimit()];
        assertTrue(support.server.recordLayer.receive(buf, 0, buf.length, 500) < 0);

        assertEquals("nothing reached the peer", 0, listener.received.size());
    }

    public void testSendAckRequiresDTLS13() throws Exception
    {
        DTLSRecordLayer13TestSupport support = new DTLSRecordLayer13TestSupport();
        DTLSRecordLayer layer = support.setUpLegacyLayer();

        try
        {
            layer.sendAck(new Vector());
            fail("expected internal_error for an ACK outside DTLS 1.3");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.internal_error, e.getAlertDescription());
        }
    }
}
