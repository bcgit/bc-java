package org.bouncycastle.tls;

import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Integers;

import junit.framework.TestCase;

/**
 * RFC 9147 5.8.1 and 7.2: a timeout retransmits only the handshake fragments that have not been
 * acknowledged, and a fully acknowledged flight is not retransmitted at all.
 */
public class DTLS13RetransmissionTest
    extends TestCase
{
    public void testOutstandingShrinksAsAcksArrive()
    {
        DTLS13FlightTracker tracker = new DTLS13FlightTracker();

        // a flight of three fragments across two messages
        tracker.register(new DTLSRecordNumber(2, 10), 3, 0, 200);
        tracker.register(new DTLSRecordNumber(2, 11), 3, 200, 200);
        tracker.register(new DTLSRecordNumber(2, 12), 4, 0, 36);

        Vector partial = new Vector();
        partial.addElement(new DTLSRecordNumber(2, 10));
        partial.addElement(new DTLSRecordNumber(2, 12));
        tracker.acknowledge(partial);

        Vector outstanding = tracker.getOutstanding();
        assertEquals("only the unacknowledged middle fragment is resent", 1, outstanding.size());

        DTLS13FlightTracker.Fragment only = (DTLS13FlightTracker.Fragment)outstanding.elementAt(0);
        assertEquals(3, only.getMessageSeq());
        assertEquals(200, only.getFragmentOffset());
        assertEquals(200, only.getFragmentLength());
        assertFalse(tracker.isComplete());

        tracker.acknowledge(DTLS13RetransmissionTest.ackOf(new DTLSRecordNumber(2, 11)));
        assertTrue(tracker.isComplete());
        assertEquals(0, tracker.getOutstanding().size());
    }

    static Vector ackOf(DTLSRecordNumber recordNumber)
    {
        Vector v = new Vector();
        v.addElement(recordNumber);
        return v;
    }

    public void testResendAfterPartialAckWritesOnlyTheMissingFragment() throws Exception
    {
        DTLS13HandshakeTestSupport support = new DTLS13HandshakeTestSupport();
        support.begin();

        // a flight of three fragments
        support.writeFlight(new int[]{ 200, 200, 36 });
        Vector sentNumbers = support.getSentRecordNumbers();
        assertEquals(3, sentNumbers.size());

        int datagramsAfterFlight = support.transport.datagrams.size();
        assertTrue("the flight is packed, not one datagram per fragment",
            datagramsAfterFlight < 3);

        // the peer acknowledges the first and third
        Vector ack = new Vector();
        ack.addElement(sentNumbers.elementAt(0));
        ack.addElement(sentNumbers.elementAt(2));
        support.deliverAck(ack);

        support.transport.datagrams.removeAllElements();
        support.timeoutAndResend();

        assertEquals("exactly one fragment is retransmitted", 1, support.countRecordsSent());
        assertEquals(200, support.lastFragmentOffsetSent());
    }

    public void testFullyAcknowledgedFlightHasNothingOutstandingToResend() throws Exception
    {
        DTLS13HandshakeTestSupport support = new DTLS13HandshakeTestSupport();
        support.begin();

        support.writeFlight(new int[]{ 50, 50 });
        support.deliverAck(support.getSentRecordNumbers());

        support.transport.datagrams.removeAllElements();
        support.timeoutAndResend();

        assertEquals("an acknowledged fragment is never among the outstanding ones", 0,
            support.countRecordsSent());
    }

    public void testFullyAcknowledgedFlightIsNotRetransmitted() throws Exception
    {
        // a short handshake timeout so the real receive loop runs to its end rather than for a minute
        DTLS13HandshakeTestSupport support = new DTLS13HandshakeTestSupport();
        support.begin(300);

        support.writeFlight(new int[]{ 50, 50 });
        support.deliverAck(support.getSentRecordNumbers());

        support.transport.datagrams.removeAllElements();

        // end-to-end property: against a silent peer, the real receive loop emits nothing until timeout
        try
        {
            support.receiveUntilHandshakeTimeout();
            fail("expected the handshake to time out waiting for the peer");
        }
        catch (TlsTimeoutException e)
        {
            // expected: the peer never answers, and we must have waited rather than retransmitted
        }

        assertEquals("a fully acknowledged flight must not be retransmitted", 0,
            support.countRecordsSent());
    }

    public void testUnacknowledgedFlightIsRetransmittedByTheReceiveLoop() throws Exception
    {
        // the counterpart of the test above: same loop, same silence from the peer, but nothing acknowledged
        DTLS13HandshakeTestSupport support = new DTLS13HandshakeTestSupport();
        support.begin(300);

        support.writeFlight(new int[]{ 50, 50 });

        support.transport.datagrams.removeAllElements();

        try
        {
            support.receiveUntilHandshakeTimeout();
            fail("expected the handshake to time out waiting for the peer");
        }
        catch (TlsTimeoutException e)
        {
            // expected
        }

        assertTrue("an unacknowledged flight must be retransmitted when nothing arrives",
            support.countRecordsSent() > 0);
    }

    /*
     * RFC 9147 5.8.1. The server answers a retransmission of the peer's final flight with another ACK, so what
     * counts as a retransmission of that flight decides what can draw an ACK out of a completed server. Epoch
     * 0 is unauthenticated, so a record from there must never qualify.
     */

    private static final int FINISHED_LENGTH = 32;
    private static final int FINAL_FLIGHT_SEQ = 1;

    private static Hashtable finalFlightOfOneFinished()
    {
        DTLSReassembler reassembler = new DTLSReassembler(HandshakeType.finished, FINISHED_LENGTH);
        reassembler.contributeFragment(HandshakeType.finished, FINISHED_LENGTH, new byte[FINISHED_LENGTH], 0, 0,
            FINISHED_LENGTH);

        Hashtable inboundFlight = new Hashtable();
        inboundFlight.put(Integers.valueOf(FINAL_FLIGHT_SEQ), reassembler);

        return DTLSReliableHandshake.summarizeFlight(inboundFlight);
    }

    private static byte[] handshakeRecord(short msgType, int length, int messageSeq, int fragmentOffset,
        int fragmentLength)
    {
        byte[] record = new byte[DTLSReliableHandshake.MESSAGE_HEADER_LENGTH + fragmentLength];
        TlsUtils.writeUint8(msgType, record, 0);
        TlsUtils.writeUint24(length, record, 1);
        TlsUtils.writeUint16(messageSeq, record, 4);
        TlsUtils.writeUint24(fragmentOffset, record, 6);
        TlsUtils.writeUint24(fragmentLength, record, 9);
        return record;
    }

    public void testRetransmissionOfTheFinalFlightIsRecognised()
    {
        Hashtable flight = finalFlightOfOneFinished();

        byte[] record = handshakeRecord(HandshakeType.finished, FINISHED_LENGTH, FINAL_FLIGHT_SEQ, 0,
            FINISHED_LENGTH);

        assertTrue("a retransmission of the final flight must be answered",
            DTLSReliableHandshake.matchesFlight(flight, 2, 2, record, 0, record.length));

        byte[] firstHalf = handshakeRecord(HandshakeType.finished, FINISHED_LENGTH, FINAL_FLIGHT_SEQ, 0,
            FINISHED_LENGTH / 2);

        assertTrue("a fragment of the final flight must be answered",
            DTLSReliableHandshake.matchesFlight(flight, 2, 2, firstHalf, 0, firstHalf.length));
    }

    public void testUnauthenticatedEpochIsNotTakenForTheFinalFlight()
    {
        Hashtable flight = finalFlightOfOneFinished();

        byte[] record = handshakeRecord(HandshakeType.finished, FINISHED_LENGTH, FINAL_FLIGHT_SEQ, 0,
            FINISHED_LENGTH);

        assertFalse("epoch 0 is unauthenticated and carries none of the final flight",
            DTLSReliableHandshake.matchesFlight(flight, 2, 0, record, 0, record.length));
        assertFalse("the application epoch carries no handshake flight",
            DTLSReliableHandshake.matchesFlight(flight, 2, 3, record, 0, record.length));

        assertFalse("with no epoch retired there is nothing to recognise",
            DTLSReliableHandshake.matchesFlight(flight, -1, -1, record, 0, record.length));
    }

    public void testForeignHandshakeRecordIsNotTakenForTheFinalFlight()
    {
        Hashtable flight = finalFlightOfOneFinished();

        byte[] otherSeq = handshakeRecord(HandshakeType.finished, FINISHED_LENGTH, FINAL_FLIGHT_SEQ + 1, 0,
            FINISHED_LENGTH);
        assertFalse("a message_seq the flight never contained",
            DTLSReliableHandshake.matchesFlight(flight, 2, 2, otherSeq, 0, otherSeq.length));

        byte[] otherType = handshakeRecord(HandshakeType.key_update, FINISHED_LENGTH, FINAL_FLIGHT_SEQ, 0,
            FINISHED_LENGTH);
        assertFalse("a different message under the flight's message_seq",
            DTLSReliableHandshake.matchesFlight(flight, 2, 2, otherType, 0, otherType.length));

        byte[] otherLength = handshakeRecord(HandshakeType.finished, FINISHED_LENGTH + 1, FINAL_FLIGHT_SEQ, 0,
            FINISHED_LENGTH + 1);
        assertFalse("a different length under the flight's message_seq",
            DTLSReliableHandshake.matchesFlight(flight, 2, 2, otherLength, 0, otherLength.length));

        byte[] record = handshakeRecord(HandshakeType.finished, FINISHED_LENGTH, FINAL_FLIGHT_SEQ, 0,
            FINISHED_LENGTH);
        assertFalse("a truncated record",
            DTLSReliableHandshake.matchesFlight(flight, 2, 2, record, 0, record.length - 1));
        assertFalse("a record too short to hold a message header",
            DTLSReliableHandshake.matchesFlight(flight, 2, 2, record, 0, 4));

        byte[] pair = new byte[record.length + otherSeq.length];
        System.arraycopy(record, 0, pair, 0, record.length);
        System.arraycopy(otherSeq, 0, pair, record.length, otherSeq.length);
        assertFalse("one fragment of the flight does not excuse a foreign one beside it",
            DTLSReliableHandshake.matchesFlight(flight, 2, 2, pair, 0, pair.length));
    }

    public void testUnacknowledgedFlightStillRetransmitsEverything() throws Exception
    {
        DTLS13HandshakeTestSupport support = new DTLS13HandshakeTestSupport();
        support.begin();

        support.writeFlight(new int[]{ 50, 50 });

        support.transport.datagrams.removeAllElements();
        support.timeoutAndResend();

        assertEquals("with no ACK, the whole flight goes again", 2, support.countRecordsSent());
    }
}
