package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;

import junit.framework.TestCase;

/**
 * RFC 9147 5.8.4 and 7: the post-handshake owner. Post-handshake handshake messages are reassembled,
 * dispatched by type and acknowledged one ACK per record - including records whose message was discarded as a
 * duplicate, which is the opposite of the handshake-time rule - and the owner outlives the RFC 9147 5.8.1
 * retransmit timeout.
 * <p>
 * Everything here runs over the paired record layers of {@link DTLSRecordLayer13TestSupport}, so the records
 * are protected, put on a transport and deprotected by the peer exactly as in a live connection, and the ACKs
 * asserted on are the ones that reached the other side's ACK listener off the wire.
 * </p>
 */
public class DTLS13PostHandshakeTest
    extends TestCase
{
    private static final int MAX_HANDSHAKE_MESSAGE_SIZE = 1 << 14;

    /** Collects the ACKs that arrive at one side, in the order they were received. */
    private static class AckCollector
        implements DTLSAckListener
    {
        final Vector acks = new Vector();

        public void receivedAck(Vector recordNumbers)
        {
            acks.addElement(recordNumbers);
        }
    }

    private DTLSRecordLayer13TestSupport support;
    private DTLSRecordLayer13TestSupport.Side client, server;
    private AckCollector clientAcks;

    private void setUpPair(int nextReceiveSeq) throws IOException
    {
        setUpPair(nextReceiveSeq, null);
    }

    /**
     * @param serverRetransmit the RFC 9147 5.8.1 final-flight hook the server completes its handshake with,
     *                         or null for a server that retains nothing.
     */
    private void setUpPair(int nextReceiveSeq, DTLSHandshakeRetransmit serverRetransmit) throws IOException
    {
        support = new DTLSRecordLayer13TestSupport();
        support.setUpPair(CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, null, serverRetransmit);
        client = support.client;
        server = support.server;

        server.recordLayer.initPostHandshake(0, nextReceiveSeq, MAX_HANDSHAKE_MESSAGE_SIZE);
        client.recordLayer.initPostHandshake(0, 0, MAX_HANDSHAKE_MESSAGE_SIZE);

        // replace the client's own owner as the ACK listener, so the server's ACKs can be asserted on
        clientAcks = new AckCollector();
        client.recordLayer.setAckListener(clientAcks);
    }

    private static byte[] handshakeMessage(short msgType, int messageSeq, int length, int fragmentOffset,
        int fragmentLength)
    {
        byte[] message = new byte[DTLSReliableHandshake.MESSAGE_HEADER_LENGTH + fragmentLength];
        TlsUtils.writeUint8(msgType, message, 0);
        TlsUtils.writeUint24(length, message, 1);
        TlsUtils.writeUint16(messageSeq, message, 4);
        TlsUtils.writeUint24(fragmentOffset, message, 6);
        TlsUtils.writeUint24(fragmentLength, message, 9);
        return message;
    }

    /** Send one post-handshake handshake record from the client, at the application epoch. */
    private DTLSRecordNumber send(byte[] message) throws IOException
    {
        return client.recordLayer.sendRecordForTest(ContentType.handshake, message, 0, message.length);
    }

    /** Let the server process whatever is waiting for it; a post-handshake record never returns data. */
    private void serverReceives() throws IOException
    {
        assertNull(DTLSRecordLayer13TestSupport.receive(server, 1000));
    }

    /** Let the client process the server's ACK, which likewise returns no data. */
    private void clientReceives() throws IOException
    {
        assertNull(DTLSRecordLayer13TestSupport.receive(client, 1000));
    }

    private void assertAck(int index, DTLSRecordNumber expected)
    {
        assertTrue("expected at least " + (index + 1) + " ACKs, got " + clientAcks.acks.size(),
            clientAcks.acks.size() > index);

        Vector recordNumbers = (Vector)clientAcks.acks.elementAt(index);
        assertEquals("one record number per post-handshake ACK", 1, recordNumbers.size());
        assertEquals(expected, recordNumbers.elementAt(0));
    }

    /**
     * RFC 9147 5.8.4. A NewSessionTicket is received and acknowledged. It is then discarded - resumption is
     * not supported - but the peer's state machine only stops retransmitting on the ACK.
     */
    public void testNewSessionTicketIsAcknowledgedAndDiscarded() throws Exception
    {
        setUpPair(0);

        DTLSRecordNumber sent = send(handshakeMessage(HandshakeType.new_session_ticket, 0, 64, 0, 64));
        serverReceives();
        clientReceives();

        assertAck(0, sent);

        DTLS13PostHandshake postHandshake = server.recordLayer.getPostHandshake();
        assertEquals(1, postHandshake.getNewSessionTicketCount());
        assertEquals("the message_seq space advances", 1, postHandshake.getNextReceiveSeq());
    }

    /**
     * RFC 9147 7. "ACKs SHOULD be sent once for each received and processed handshake record ... This
     * includes records containing messages which are discarded because a previous copy has been received."
     * <p>
     * This is the inverse of the handshake-time rule asserted by
     * {@link DTLS13AckGenerationTest#testDuplicateOfACompleteMessageDoesNotTriggerAnAck}, and both are
     * correct in their own phase: during the handshake the flight's own timer will ACK, while after it the
     * peer is waiting on exactly this ACK and will otherwise retransmit for as long as its timer runs.
     * </p>
     */
    public void testDuplicateOfACompleteMessageIsStillAcknowledged() throws Exception
    {
        setUpPair(0);

        byte[] message = handshakeMessage(HandshakeType.new_session_ticket, 0, 64, 0, 64);

        DTLSRecordNumber first = send(message);
        serverReceives();

        DTLSRecordNumber second = send(message);
        serverReceives();

        clientReceives();
        clientReceives();

        assertEquals("one ACK per record, the duplicate included", 2, clientAcks.acks.size());
        assertAck(0, first);
        assertAck(1, second);

        assertEquals("the duplicate is not processed twice", 1,
            server.recordLayer.getPostHandshake().getNewSessionTicketCount());
    }

    /**
     * RFC 9147 5.8.3. A NewSessionTicket routinely exceeds an MTU, so post-handshake messages are reassembled
     * from fragments. Each record is acknowledged as it arrives; the message is delivered once.
     */
    public void testFragmentedNewSessionTicketIsReassembled() throws Exception
    {
        setUpPair(0);

        DTLSRecordNumber first = send(handshakeMessage(HandshakeType.new_session_ticket, 0, 200, 0, 120));
        serverReceives();

        assertEquals("not delivered until complete", 0,
            server.recordLayer.getPostHandshake().getNewSessionTicketCount());

        DTLSRecordNumber second = send(handshakeMessage(HandshakeType.new_session_ticket, 0, 200, 120, 80));
        serverReceives();

        clientReceives();
        clientReceives();

        assertEquals(2, clientAcks.acks.size());
        assertAck(0, first);
        assertAck(1, second);

        assertEquals("delivered exactly once", 1,
            server.recordLayer.getPostHandshake().getNewSessionTicketCount());
    }

    /**
     * RFC 9147 5.8.1 bounds the final-flight hook at twice the MSL; nothing bounds the post-handshake owner,
     * which has to answer a KeyUpdate arriving hours into a connection. The timeout is expired through the
     * record layer's own code path here, so what is asserted is that the real expiry leaves the owner alone.
     */
    public void testOwnerSurvivesTheRetransmitTimeout() throws Exception
    {
        DTLSHandshakeRetransmit retransmit = new DTLSHandshakeRetransmit()
        {
            public void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
            {
            }
        };

        setUpPair(0, retransmit);

        assertEquals("the handshake epoch is retained to begin with", 2, server.recordLayer.getLiveReadEpochs().size());

        server.recordLayer.expireRetransmitTimeoutForTest();

        // a receive with nothing waiting: enough for the retransmit timeout to be noticed and acted on
        assertNull(DTLSRecordLayer13TestSupport.receive(server, 1));

        assertEquals("the retained handshake epoch is gone", 1, server.recordLayer.getLiveReadEpochs().size());

        DTLSRecordNumber sent = send(handshakeMessage(HandshakeType.new_session_ticket, 0, 64, 0, 64));
        serverReceives();
        clientReceives();

        assertAck(0, sent);
        assertEquals(1, server.recordLayer.getPostHandshake().getNewSessionTicketCount());
    }

    /**
     * RFC 9147 5.8.4 lists the post-handshake categories; nothing else is legal here. Connection ID messages
     * and post-handshake client authentication are only legal once negotiated, and neither is supported.
     */
    public void testUnexpectedPostHandshakeMessageIsFatal() throws Exception
    {
        setUpPair(0);

        send(handshakeMessage(HandshakeType.certificate_request, 0, 4, 0, 4));

        try
        {
            serverReceives();
            fail("expected a fatal alert for a handshake message that is not a post-handshake message");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.unexpected_message, e.getAlertDescription());
        }
    }

    /**
     * RFC 9147 5.8.4 and 6.1. Post-handshake messages continue the handshake's own message_seq space, so a
     * message numbered from where the handshake left off is the next one, and one numbered from zero is a
     * message already seen: discarded, but still acknowledged.
     */
    public void testMessageSeqContinuesTheHandshakeSpace() throws Exception
    {
        setUpPair(7);

        DTLSRecordNumber next = send(handshakeMessage(HandshakeType.new_session_ticket, 7, 64, 0, 64));
        serverReceives();

        DTLSRecordNumber old = send(handshakeMessage(HandshakeType.new_session_ticket, 0, 64, 0, 64));
        serverReceives();

        clientReceives();
        clientReceives();

        assertAck(0, next);
        assertAck(1, old);

        DTLS13PostHandshake postHandshake = server.recordLayer.getPostHandshake();
        assertEquals("only the message at the expected seq is processed", 1,
            postHandshake.getNewSessionTicketCount());
        assertEquals(8, postHandshake.getNextReceiveSeq());
    }

    /**
     * RFC 9147 7.2. The post-handshake owner takes over the record layer's ACK listener, so an ACK arriving
     * after the handshake retires the fragments it names instead of being decoded and dropped.
     */
    public void testPostHandshakeAckRetiresAnOutstandingMessage() throws Exception
    {
        setUpPair(0);

        DTLS13PostHandshake postHandshake = server.recordLayer.getPostHandshake();

        DTLSRecordNumber outstanding = new DTLSRecordNumber(3, 41);
        postHandshake.getFlightTracker().register(outstanding, 7, 0, 1);
        assertFalse(postHandshake.getFlightTracker().isComplete());

        Vector recordNumbers = new Vector();
        recordNumbers.addElement(outstanding);
        client.recordLayer.sendAck(recordNumbers);

        serverReceives();

        assertTrue("the ACK reached the post-handshake owner",
            postHandshake.getFlightTracker().isComplete());
    }

    /**
     * RFC 8446 4.6.3. "Implementations that receive a KeyUpdate message prior to receiving a Finished message
     * MUST terminate the connection with an "unexpected_message" alert."
     */
    public void testKeyUpdateBeforeTheHandshakeCompletesIsFatal() throws Exception
    {
        DTLS13HandshakeTestSupport handshakeSupport = new DTLS13HandshakeTestSupport();
        handshakeSupport.begin(500);

        handshakeSupport.deliverHandshakeRecord(0L, HandshakeType.key_update, 0, 1, 0, 1);

        try
        {
            handshakeSupport.receiveMessage();
            fail("expected a fatal alert for a KeyUpdate before the handshake completed");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.unexpected_message, e.getAlertDescription());
        }
    }

    /**
     * RFC 8446 4.6.3. The body is one KeyUpdateRequest; anything else is a decode error rather than something
     * to be interpreted.
     */
    public void testKeyUpdateWithAMalformedBodyIsFatal() throws Exception
    {
        setUpPair(0);

        send(handshakeMessage(HandshakeType.key_update, 0, 2, 0, 2));

        try
        {
            serverReceives();
            fail("expected a fatal alert for a KeyUpdate whose body is not one byte");
        }
        catch (TlsFatalAlert e)
        {
            assertEquals(AlertDescription.decode_error, e.getAlertDescription());
        }
    }

    /**
     * RFC 9147 6.1. A handshake record below epoch 3 after the handshake has completed is a retransmission of
     * the peer's final flight, which belongs to the RFC 9147 5.8.1 hook. The post-handshake owner must not
     * take it, or a replayed handshake record would advance the post-handshake message_seq space.
     */
    public void testRecordBelowTheApplicationEpochIsNotTakenByTheOwner() throws Exception
    {
        setUpPair(0);

        DTLS13PostHandshake postHandshake = server.recordLayer.getPostHandshake();

        byte[] message = handshakeMessage(HandshakeType.new_session_ticket, 0, 64, 0, 64);
        postHandshake.receivedHandshakeRecord(DTLS13PostHandshake.MIN_EPOCH - 1, message, 0, message.length);

        assertEquals(0, postHandshake.getNewSessionTicketCount());
        assertEquals(0, postHandshake.getNextReceiveSeq());
    }
}
