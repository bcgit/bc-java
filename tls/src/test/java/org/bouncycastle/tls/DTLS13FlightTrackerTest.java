package org.bouncycastle.tls;

import java.util.Vector;

import junit.framework.TestCase;

/**
 * RFC 9147 7.2: an ACK retires the handshake fragments carried by the acknowledged records, retransmission
 * covers only what is left, and a fragment counts as acknowledged if any record carrying it was ACKed.
 */
public class DTLS13FlightTrackerTest
    extends TestCase
{
    private DTLS13FlightTracker tracker;

    public void setUp()
    {
        tracker = new DTLS13FlightTracker();
    }

    private static Vector ackOf(DTLSRecordNumber a)
    {
        Vector v = new Vector();
        v.addElement(a);
        return v;
    }

    public void testEmptyTracker()
    {
        assertTrue(tracker.isEmpty());
        assertFalse("nothing registered is not a complete flight", tracker.isComplete());
        assertEquals(0, tracker.getOutstanding().size());
    }

    public void testRegisteredFragmentsAreOutstandingUntilAcknowledged()
    {
        tracker.register(new DTLSRecordNumber(2, 0), 1, 0, 100);
        tracker.register(new DTLSRecordNumber(2, 1), 1, 100, 50);
        tracker.register(new DTLSRecordNumber(2, 2), 2, 0, 10);

        assertFalse(tracker.isEmpty());
        assertFalse(tracker.isComplete());
        assertEquals(3, tracker.getOutstanding().size());

        tracker.acknowledge(ackOf(new DTLSRecordNumber(2, 1)));

        Vector outstanding = tracker.getOutstanding();
        assertEquals(2, outstanding.size());
        assertFalse(tracker.isComplete());

        DTLS13FlightTracker.Fragment first = (DTLS13FlightTracker.Fragment)outstanding.elementAt(0);
        assertEquals(1, first.getMessageSeq());
        assertEquals(0, first.getFragmentOffset());
        assertEquals(100, first.getFragmentLength());

        DTLS13FlightTracker.Fragment second = (DTLS13FlightTracker.Fragment)outstanding.elementAt(1);
        assertEquals(2, second.getMessageSeq());
        assertEquals(0, second.getFragmentOffset());
        assertEquals(10, second.getFragmentLength());
    }

    public void testFlightBecomesCompleteWhenEverythingIsAcknowledged()
    {
        tracker.register(new DTLSRecordNumber(2, 0), 1, 0, 10);
        tracker.register(new DTLSRecordNumber(2, 1), 2, 0, 10);

        Vector ack = new Vector();
        ack.addElement(new DTLSRecordNumber(2, 0));
        ack.addElement(new DTLSRecordNumber(2, 1));
        tracker.acknowledge(ack);

        assertTrue(tracker.isComplete());
        assertEquals(0, tracker.getOutstanding().size());
    }

    public void testAcknowledgingAnyCarrierRetiresTheFragment()
    {
        // the same fragment sent twice, in two different records
        tracker.register(new DTLSRecordNumber(2, 0), 1, 0, 10);
        tracker.register(new DTLSRecordNumber(2, 5), 1, 0, 10);
        assertEquals("the fragment is listed once, not once per carrier", 1, tracker.getOutstanding().size());

        tracker.acknowledge(ackOf(new DTLSRecordNumber(2, 5)));

        assertTrue(tracker.isComplete());
        assertEquals(0, tracker.getOutstanding().size());
    }

    public void testUnknownAndRepeatedAcknowledgementsAreIgnored()
    {
        tracker.register(new DTLSRecordNumber(2, 0), 1, 0, 10);

        tracker.acknowledge(ackOf(new DTLSRecordNumber(9, 9)));
        assertEquals(1, tracker.getOutstanding().size());
        assertFalse(tracker.isComplete());

        tracker.acknowledge(ackOf(new DTLSRecordNumber(2, 0)));
        tracker.acknowledge(ackOf(new DTLSRecordNumber(2, 0)));
        assertTrue(tracker.isComplete());
        assertEquals(0, tracker.getOutstanding().size());
    }

    public void testAcknowledgeEmptyListChangesNothing()
    {
        tracker.register(new DTLSRecordNumber(2, 0), 1, 0, 10);
        tracker.acknowledge(new Vector());
        assertEquals(1, tracker.getOutstanding().size());
        assertFalse(tracker.isComplete());
    }

    public void testResetClearsTheFlight()
    {
        tracker.register(new DTLSRecordNumber(2, 0), 1, 0, 10);
        tracker.reset();

        assertTrue(tracker.isEmpty());
        assertFalse(tracker.isComplete());
        assertEquals(0, tracker.getOutstanding().size());

        // a stale ACK for the previous flight must not resurrect state
        tracker.acknowledge(ackOf(new DTLSRecordNumber(2, 0)));
        assertTrue(tracker.isEmpty());
        assertFalse(tracker.isComplete());
    }
}
