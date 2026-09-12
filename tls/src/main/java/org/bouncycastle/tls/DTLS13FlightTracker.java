package org.bouncycastle.tls;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

/**
 * RFC 9147 7.2. Tracks which record carried which handshake fragment of the current outbound flight, so
 * that an ACK retires exactly the fragments it covers and a retransmission resends only what is left.
 * <p>
 * A fragment may be registered more than once, under a different record number each time it is sent. It
 * is acknowledged as soon as any one of those records is acknowledged.
 * </p>
 */
class DTLS13FlightTracker
{
    /** One handshake fragment of the current outbound flight. */
    static final class Fragment
    {
        private final int messageSeq;
        private final int fragmentOffset;
        private final int fragmentLength;

        boolean acknowledged = false;

        Fragment(int messageSeq, int fragmentOffset, int fragmentLength)
        {
            this.messageSeq = messageSeq;
            this.fragmentOffset = fragmentOffset;
            this.fragmentLength = fragmentLength;
        }

        int getMessageSeq()
        {
            return messageSeq;
        }

        int getFragmentOffset()
        {
            return fragmentOffset;
        }

        int getFragmentLength()
        {
            return fragmentLength;
        }

        private String key()
        {
            return messageSeq + ":" + fragmentOffset + ":" + fragmentLength;
        }
    }

    // record number -> Fragment
    private Hashtable carriers = new Hashtable();
    // fragment key -> Fragment, so the same fragment sent twice is one entry
    private Hashtable fragments = new Hashtable();
    // fragments in registration order, for deterministic retransmission
    private Vector order = new Vector();

    void reset()
    {
        carriers = new Hashtable();
        fragments = new Hashtable();
        order = new Vector();
    }

    void register(DTLSRecordNumber recordNumber, int messageSeq, int fragmentOffset, int fragmentLength)
    {
        Fragment fragment = new Fragment(messageSeq, fragmentOffset, fragmentLength);
        String key = fragment.key();

        Fragment existing = (Fragment)fragments.get(key);
        if (null == existing)
        {
            fragments.put(key, fragment);
            order.addElement(fragment);
            existing = fragment;
        }

        if (null != recordNumber)
        {
            carriers.put(recordNumber, existing);
        }
    }

    void acknowledge(Vector recordNumbers)
    {
        for (int i = 0; i < recordNumbers.size(); ++i)
        {
            Fragment fragment = (Fragment)carriers.get(recordNumbers.elementAt(i));
            if (null != fragment)
            {
                fragment.acknowledged = true;
            }
        }
    }

    boolean isEmpty()
    {
        return order.isEmpty();
    }

    /**
     * @return true if fragments were registered and every one of them has been acknowledged.
     */
    boolean isComplete()
    {
        if (order.isEmpty())
        {
            return false;
        }

        Enumeration e = order.elements();
        while (e.hasMoreElements())
        {
            if (!((Fragment)e.nextElement()).acknowledged)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @return the fragments not yet acknowledged, in the order they were first registered.
     */
    Vector getOutstanding()
    {
        Vector outstanding = new Vector();

        Enumeration e = order.elements();
        while (e.hasMoreElements())
        {
            Fragment fragment = (Fragment)e.nextElement();
            if (!fragment.acknowledged)
            {
                outstanding.addElement(fragment);
            }
        }

        return outstanding;
    }
}
