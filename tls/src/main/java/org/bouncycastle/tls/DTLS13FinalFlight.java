package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

/**
 * RFC 9147 5.8.1. The WAITING state of the side that sent the final flight of the handshake, kept running
 * after that side has otherwise completed.
 * <p>
 * Every other flight is implicitly acknowledged by the flight that answers it, but nothing answers the last
 * one except an ACK (RFC 9147 5.7 and 7.1: "the client's final flight ... must be acknowledged with an ACK
 * message"), so its sender has to keep its retransmit timer running until that ACK arrives. Of the four exits
 * from WAITING in section 5.8.1, three apply here. The timer expires, and what is still outstanding of the
 * flight is retransmitted. An ACK arrives, which retires the records it names and, once nothing is
 * outstanding, cancels all retransmission (section 7.2); as during the handshake, a partial ACK retires what
 * it covers and leaves the timer to resend the rest. Or the peer's own final flight is read again, which
 * "suggests that part of one's previous flight was lost" and is answered with an immediate retransmission.
 * </p>
 * <p>
 * That third exit is what makes this state machine necessary rather than merely conforming. Once the peer
 * has been acknowledged for part of its flight it retransmits only the rest (section 7.2), so a sender that
 * waited to see the peer's whole flight again before answering - the DTLS 1.2 rule, and the only safe one
 * while the record carrying the flight may be unauthenticated plaintext - would wait forever, with the peer
 * retransmitting into silence until its handshake timed out. Here a record counts only when it was protected
 * at the handshake epoch, which the peer's keys authenticate; the peer's ServerHello sits at the
 * unauthenticated epoch 0 and is not a trigger, and the timer covers it.
 * </p>
 * <p>
 * Retransmission stops, without an error, once the record layer no longer holds the epoch the flight was
 * sent at: the handshake epoch is retained for twice the MSL (RFC 9147 5.8.1), which bounds this state
 * machine exactly as it bounds the peer's duty to answer a retransmission. A peer that has not acknowledged
 * the flight by then has long since timed out its own handshake, and there is no one left to tell.
 * </p>
 * <p>
 * Thread safety: reached from the record layer's receive path, through {@link DTLS13PostHandshake} for the
 * timer and the ACKs and through the RFC 9147 5.8.1 retransmit hook for the peer's flight, so every method
 * is synchronized on this object. LOCK ORDER: this monitor is taken after the post-handshake owner's (when
 * that is the caller) and before the record layer's write lock, which the retransmission takes.
 * </p>
 */
class DTLS13FinalFlight
{
    private final DTLSRecordLayer recordLayer;

    /** The messages of the flight (DTLSReliableHandshake.Message), the source of every retransmitted byte. */
    private final Vector messages;

    /** RFC 9147 7.2. Which records carried which fragments, and which of those have been acknowledged. */
    private final DTLS13FlightTracker flightTracker;

    /** The peer's final flight, as {@link DTLSReliableHandshake#summarizeFlight(Hashtable)} describes it. */
    private final Hashtable peerFlight;

    /** The handshake epoch the peer's final flight was protected under, or -1 if none was retired. */
    private final int peerFlightEpoch;

    private int resendMillis;
    private Timeout resendTimeout;
    private boolean outstanding = true;

    DTLS13FinalFlight(DTLSRecordLayer recordLayer, Vector messages, DTLS13FlightTracker flightTracker,
        Hashtable peerFlight, int peerFlightEpoch, int resendMillis)
    {
        this.recordLayer = recordLayer;
        this.messages = messages;
        this.flightTracker = flightTracker;
        this.peerFlight = peerFlight;
        this.peerFlightEpoch = peerFlightEpoch;
        this.resendMillis = resendMillis;
        this.resendTimeout = new Timeout(resendMillis);
    }

    /** @return true until the flight has been acknowledged in full or retransmission has been given up. */
    synchronized boolean isOutstanding()
    {
        return outstanding;
    }

    /** Bound a wait by the retransmit timer, which is null once nothing is outstanding. */
    synchronized int constrainWaitMillis(int waitMillis, long currentTimeMillis)
    {
        return Timeout.constrainWaitMillis(waitMillis, resendTimeout, currentTimeMillis);
    }

    /**
     * RFC 9147 5.8.1 (exit 2) and 7.2. An ACK retires the fragments it names; once every fragment of the
     * flight has been acknowledged, all retransmission of it is cancelled.
     */
    synchronized void receivedAck(Vector recordNumbers)
    {
        if (!outstanding)
        {
            return;
        }

        flightTracker.acknowledge(recordNumbers);

        if (!flightTracker.hasOutstanding())
        {
            end();
        }
    }

    /**
     * RFC 9147 5.8.1 (exit 1). Driven from the record layer's receive loop: when the timer has expired, what
     * is still outstanding of the flight is retransmitted and the timer is backed off and re-armed.
     */
    synchronized void checkTimeouts(long currentTimeMillis) throws IOException
    {
        if (outstanding && Timeout.hasExpired(resendTimeout, currentTimeMillis))
        {
            resend(currentTimeMillis);
        }
    }

    /**
     * RFC 9147 5.8.1 (exit 3). A handshake record read after the handshake completed is a retransmission of
     * the peer's final flight if it arrived at the epoch that flight was protected under and every fragment
     * in it belongs to a message of that flight - the test
     * {@link DTLSReliableHandshake#matchesFlight(Hashtable, int, int, byte[], int, int)} makes, and the same
     * one the other side applies before answering with an ACK. The peer only retransmits because it has not
     * received our flight, or not all of it, so what is outstanding of ours goes back out at once.
     */
    synchronized void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len) throws IOException
    {
        if (outstanding && DTLSReliableHandshake.matchesFlight(peerFlight, peerFlightEpoch, epoch, buf, off, len))
        {
            resend(System.currentTimeMillis());
        }
    }

    private void resend(long currentTimeMillis) throws IOException
    {
        Vector fragments = flightTracker.getOutstanding();
        if (fragments.isEmpty())
        {
            // Nothing is outstanding, so nothing is waiting to be acknowledged either
            end();
            return;
        }

        /*
         * Each fragment goes back out at the epoch it was first sent at, which is the only epoch the peer can
         * read while it is still waiting for this flight (RFC 9147 5.8.1). The record layer holds that epoch
         * for twice the MSL and then drops it; retransmission ends with it, because a flight the peer has not
         * acknowledged by then is one it has given up on, and a write at a dropped epoch is an error.
         */
        for (int i = 0; i < fragments.size(); ++i)
        {
            DTLS13FlightTracker.Fragment fragment = (DTLS13FlightTracker.Fragment)fragments.elementAt(i);
            if (!recordLayer.isEpochHeldForRetransmit(fragment.getEpoch()))
            {
                end();
                return;
            }
        }

        for (int i = 0; i < fragments.size(); ++i)
        {
            DTLS13FlightTracker.Fragment fragment = (DTLS13FlightTracker.Fragment)fragments.elementAt(i);

            DTLSReliableHandshake.Message message = getMessage(fragment.getMessageSeq());
            if (null == message)
            {
                // A tracked fragment always has a message; the tracker and the flight were filled together
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            byte[] encoded = DTLSReliableHandshake.encodeFragment(message, fragment.getFragmentOffset(),
                fragment.getFragmentLength());

            DTLSRecordNumber recordNumber = recordLayer.sendHandshakeRecordAtEpoch(fragment.getEpoch(), encoded,
                0, encoded.length);

            // RFC 9147 7.2. The same fragment under a new record number: either record being ACKed retires it
            flightTracker.register(recordNumber, message.getSeq(), fragment.getFragmentOffset(),
                fragment.getFragmentLength());
        }

        this.resendMillis = DTLSReliableHandshake.backOff(resendMillis);
        this.resendTimeout = new Timeout(resendMillis, currentTimeMillis);
    }

    private DTLSReliableHandshake.Message getMessage(int messageSeq)
    {
        for (int i = 0; i < messages.size(); ++i)
        {
            DTLSReliableHandshake.Message message = (DTLSReliableHandshake.Message)messages.elementAt(i);
            if (message.getSeq() == messageSeq)
            {
                return message;
            }
        }
        return null;
    }

    private void end()
    {
        this.outstanding = false;
        this.resendTimeout = null;

        // The flight's bodies are the largest thing held here, and nothing will read them again
        messages.removeAllElements();
        flightTracker.reset();
    }
}
