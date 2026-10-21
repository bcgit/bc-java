package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import junit.framework.TestCase;

/**
 * RFC 9147 7.1: the receiving side of the reliable handshake sends an ACK when a flight is disrupted.
 * <p>
 * Every DTLS 1.3 record here is protected and arrives at the handshake traffic epoch, which is where a real
 * handshake's records arrive, so what is covered is the live path rather than a simplified one.
 * </p>
 * <p>
 * Every assertion here is made on the records the transport actually received, with the ACK bodies decoded
 * by {@link DTLSAck}, so what is tested is the wire output rather than any internal state.
 * </p>
 */
public class DTLS13AckGenerationTest
    extends TestCase
{
    // every DTLS 1.3 handshake message after ServerHello arrives at the handshake traffic epoch (RFC 9147 6.1)
    private static final short INBOUND_TYPE = HandshakeType.certificate;

    private static final int HANDSHAKE_EPOCH = 2;

    private static final int BODY_LENGTH = 32;

    private DTLS13HandshakeTestSupport support;

    public void setUp()
    {
        support = new DTLS13HandshakeTestSupport();
    }

    public void testOutOfOrderFragmentTriggersAnAck() throws IOException
    {
        support.begin(500);
        assertEquals("delivered at the handshake traffic epoch", HANDSHAKE_EPOCH, support.getReadEpoch());

        // message_seq 3 while message_seq 0 is expected
        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 3, BODY_LENGTH, 0, BODY_LENGTH);

        support.receiveUntilTimeout();

        Vector acks = support.getAcksSent();
        assertEquals("exactly one ACK", 1, acks.size());
        assertRecordNumbers(new long[]{ 0L }, (Vector)acks.elementAt(0));
    }

    public void testPartialFlightTriggersAnAckAfterTheQuarterTimer() throws IOException
    {
        support.begin(900);

        // the first half of a two fragment message: in order, but the flight is incomplete
        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 0, 200, 0, 100);

        support.receiveUntilTimeout();

        Vector acks = support.getAcksSent();
        assertEquals("exactly one ACK", 1, acks.size());
        assertRecordNumbers(new long[]{ 0L }, (Vector)acks.elementAt(0));
    }

    public void testAckListIsClearedAtAFlightBoundary() throws IOException
    {
        support.begin(1200);

        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 0, BODY_LENGTH, 0, BODY_LENGTH);
        assertNotNull(support.receiveMessage());

        // our own flight ends the inbound flight the record above belonged to
        support.sendMessage();

        support.deliverHandshakeRecord(1L, INBOUND_TYPE, 4, BODY_LENGTH, 0, BODY_LENGTH);

        support.receiveUntilTimeout();

        Vector acks = support.getAcksSent();
        assertEquals("exactly one ACK", 1, acks.size());

        // record 0 belonged to the previous flight and must not appear
        assertRecordNumbers(new long[]{ 1L }, (Vector)acks.elementAt(0));
    }

    public void testNoAckIsSentInDTLS12() throws IOException
    {
        support.beginDTLS12(500);

        support.deliverHandshakeRecord(0L, HandshakeType.certificate, 3, BODY_LENGTH, 0, BODY_LENGTH);

        support.receiveUntilTimeout();

        assertTrue("no ACK in DTLS 1.2", support.getAcksSent().isEmpty());
    }

    public void testAckCoversOnlyProcessedRecords() throws IOException
    {
        support.begin(500);

        // beyond the receive-ahead window, so it is discarded rather than buffered
        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 20, BODY_LENGTH, 0, BODY_LENGTH);

        // within the window, but out of order, which is what triggers the ACK
        support.deliverHandshakeRecord(1L, INBOUND_TYPE, 3, BODY_LENGTH, 0, BODY_LENGTH);

        support.receiveUntilTimeout();

        Vector acks = support.getAcksSent();
        assertEquals("exactly one ACK", 1, acks.size());
        assertRecordNumbers(new long[]{ 1L }, (Vector)acks.elementAt(0));
    }

    public void testFinalFlightIsAcknowledged() throws IOException
    {
        support.begin(5000);

        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 0, BODY_LENGTH, 0, BODY_LENGTH);
        assertNotNull(support.receiveMessage());

        support.finish();

        Vector acks = support.getAcksSent();
        assertEquals("the final flight is acknowledged explicitly", 1, acks.size());
        assertRecordNumbers(new long[]{ 0L }, (Vector)acks.elementAt(0));

        assertEquals("no handshake fragments are sent", 0, support.countRecordsSent());
    }

    /**
     * The ordinary loss case: the first fragment of a message never arrives, so the first one that does
     * begins past offset 0. That is out of order and must be acknowledged at once, not left to the timer.
     */
    public void testAFragmentPastTheStartOfAMessageTriggersAnAckWithoutTheQuarterTimer() throws IOException
    {
        // shorter than a quarter of the 1000ms resend timer, so only the out-of-order trigger can fire
        support.begin(100);

        // the second half of a two fragment message, arriving first
        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 0, 200, 100, 100);

        support.receiveUntilTimeout();

        Vector acks = support.getAcksSent();
        assertEquals("exactly one ACK", 1, acks.size());
        assertRecordNumbers(new long[]{ 0L }, (Vector)acks.elementAt(0));
    }

    /**
     * RFC 9147 7.1 includes "records containing messages which are discarded because a previous copy has
     * been received". A duplicate contributes nothing, but it was processed, so its record is acknowledged.
     */
    public void testRecordCarryingADuplicateFragmentIsAcknowledged() throws IOException
    {
        support.begin(900);

        // the first half of a 200 byte message
        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 0, 200, 0, 100);

        // the very same fragment again
        support.deliverHandshakeRecord(1L, INBOUND_TYPE, 0, 200, 0, 100);

        support.receiveUntilTimeout();

        Vector acks = support.getAcksSent();
        assertEquals("exactly one ACK", 1, acks.size());

        // both records are acknowledged, so the peer stops retransmitting the fragment we already hold
        assertRecordNumbers(new long[]{ 0L, 1L }, (Vector)acks.elementAt(0));
    }

    /**
     * RFC 9147 7.1 only allows a record to be acknowledged once its content was processed or buffered. A
     * fragment the reassembler rejects (here because it redeclares the message length) was neither, and
     * unlike a duplicate it is not covered by the "discarded because a previous copy has been received" case.
     */
    public void testRecordRejectedByTheReassemblerIsNotAcknowledged() throws IOException
    {
        support.begin(900);

        // the first half of a 200 byte message
        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 0, 200, 0, 100);

        // the same message_seq, but a different declared length, so the reassembler discards it
        support.deliverHandshakeRecord(1L, INBOUND_TYPE, 0, 100, 0, 100);

        support.receiveUntilTimeout();

        Vector acks = support.getAcksSent();
        assertEquals("exactly one ACK", 1, acks.size());

        // record 1 contributed nothing, so acknowledging it would stop a retransmission we still need
        assertRecordNumbers(new long[]{ 0L }, (Vector)acks.elementAt(0));
    }

    /**
     * Delivery itself, stated outright: a protected record arriving at the handshake traffic epoch is
     * accepted and its message handed to the caller. Every other test here depends on that.
     */
    public void testProtectedHandshakeRecordIsDelivered() throws IOException
    {
        support.begin(2000);
        assertEquals("the read epoch is the handshake traffic epoch", HANDSHAKE_EPOCH, support.getReadEpoch());

        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 0, BODY_LENGTH, 0, BODY_LENGTH);

        DTLSReliableHandshake.Message message = support.receiveMessage();
        assertNotNull(message);
        assertEquals(INBOUND_TYPE, message.getType());
        assertEquals(BODY_LENGTH, message.getBody().length);
    }

    /**
     * A fragment of a message that is already complete is a duplicate, not evidence of loss. It is still
     * acknowledged eventually, but it must not force an ACK of its own: a peer replaying one fragment N
     * times would otherwise draw N ACKs, the k'th of them listing k record numbers.
     */
    public void testDuplicateOfACompleteMessageDoesNotTriggerAnAck() throws IOException
    {
        support.begin(2000);

        // one record carrying a complete message and then the very same fragment again, so the second copy
        // meets a reassembler that is already complete
        support.deliverRepeatedHandshakeRecord(0L, INBOUND_TYPE, 0, BODY_LENGTH, 0, BODY_LENGTH);

        assertNotNull("the message is still delivered", support.receiveMessage());

        assertTrue("a duplicate of a complete message must not force an ACK", support.getAcksSent().isEmpty());
    }

    /**
     * RFC 9147 7.1: an ACK includes as many received records as fit into the ACK record. However many
     * records arrive, the encoded ACK body must still fit in one datagram, or the ACK that is meant to stop
     * the peer retransmitting is itself fragmented or dropped.
     */
    public void testAnAckBodyNeverExceedsTheTransportSendLimit() throws IOException
    {
        support.begin(1500);

        int sendLimit = support.getSendLimit();

        // far more records than can fit: even one record number each, 400 of them are 6402 encoded bytes
        int records = 400;
        assertTrue("the run must overflow one ACK", 2 + 16 * records > sendLimit);

        support.deliverHandshakeRecord(0L, INBOUND_TYPE, 0, BODY_LENGTH, 0, BODY_LENGTH);
        assertNotNull(support.receiveMessage());

        // each replay is a duplicate of a delivered message, so it is accumulated without forcing an ACK
        for (int recordSeq = 1; recordSeq <= records; ++recordSeq)
        {
            support.deliverHandshakeRecord(recordSeq, INBOUND_TYPE, 0, BODY_LENGTH, 0, BODY_LENGTH);
        }

        support.receiveUntilTimeout();

        Vector acks = support.getAcksSent();
        assertFalse("the quarter timer sends an ACK", acks.isEmpty());

        for (int i = 0; i < acks.size(); ++i)
        {
            Vector ack = (Vector)acks.elementAt(i);
            assertTrue("an ACK must fit in one datagram",
                DTLSAck.encode(ack).length <= sendLimit);
        }

        // and it is bounded by the send limit, not by having stopped acknowledging early
        Vector last = (Vector)acks.elementAt(acks.size() - 1);
        assertTrue("the ACK is filled to what fits", DTLSAck.encode(last).length + 16 > sendLimit);
    }

    private void assertRecordNumbers(long[] expectedSequenceNumbers, Vector recordNumbers)
    {
        assertEquals("record number count", expectedSequenceNumbers.length, recordNumbers.size());

        for (int i = 0; i < expectedSequenceNumbers.length; ++i)
        {
            assertEquals("record number " + i, support.inboundRecordNumber(expectedSequenceNumbers[i]),
                recordNumbers.elementAt(i));
        }
    }
}
