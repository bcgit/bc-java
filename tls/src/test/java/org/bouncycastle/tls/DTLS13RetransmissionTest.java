package org.bouncycastle.tls;

import java.util.Vector;

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
