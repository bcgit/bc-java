package org.bouncycastle.tls.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import junit.framework.TestCase;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsTimeoutException;

/**
 * Regression test for github #1666: the blocking TlsClientProtocol / TlsServerProtocol stream API
 * should honour TlsPeer.getHandshakeTimeoutMillis(), which was previously respected only by the
 * DTLS protocols.
 */
public class TlsHandshakeTimeoutTest
    extends TestCase
{
    private static final int HANDSHAKE_TIMEOUT_MS = 500;

    /**
     * A peer that keeps sending well formed, ignorable records - a warning alert the client is
     * required to tolerate - one at a time, forever. Every read completes, so no per-read timeout
     * can end this; only a total handshake deadline can.
     */
    public void testSlowPeerTimesOut()
        throws Exception
    {
        // NOTE: the record limit only bounds the failure case (with no deadline the handshake would
        // otherwise run forever); it is far more than any passing run reaches.
        InputStream input = new AlertDripInputStream(HANDSHAKE_TIMEOUT_MS / 10, 200);
        OutputStream output = new ByteArrayOutputStream();

        TlsClientProtocol protocol = new TlsClientProtocol(input, output);

        long start = System.currentTimeMillis();
        try
        {
            protocol.connect(new TimeoutTlsClient(HANDSHAKE_TIMEOUT_MS));
            fail("handshake should have timed out");
        }
        catch (TlsTimeoutException e)
        {
            long elapsed = System.currentTimeMillis() - start;
            assertTrue("handshake timed out too late (" + elapsed + "ms)",
                elapsed < 10L * HANDSHAKE_TIMEOUT_MS);
        }
    }

    /**
     * The same peer, with no handshake timeout configured. A zero timeout means an infinite one, so
     * the handshake must not be abandoned - this is the compatibility case for every existing peer,
     * all of which inherit zero from AbstractTlsPeer.
     */
    public void testNoTimeoutIsInfinite()
        throws Exception
    {
        InputStream input = new AlertDripInputStream(HANDSHAKE_TIMEOUT_MS / 10, 40);
        OutputStream output = new ByteArrayOutputStream();

        TlsClientProtocol protocol = new TlsClientProtocol(input, output);

        try
        {
            protocol.connect(new TimeoutTlsClient(0));
            fail("handshake should not have completed");
        }
        catch (TlsTimeoutException e)
        {
            fail("handshake timed out with no handshake timeout configured");
        }
        catch (IOException e)
        {
            // Expected: the peer runs out of records long after any deadline would have fired
        }
    }

    private static class TimeoutTlsClient
        extends MockTlsClient
    {
        private final int handshakeTimeoutMillis;

        TimeoutTlsClient(int handshakeTimeoutMillis)
        {
            super(null);

            this.handshakeTimeoutMillis = handshakeTimeoutMillis;
        }

        public int getHandshakeTimeoutMillis()
        {
            return handshakeTimeoutMillis;
        }

        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
        {
            // Quieter than MockTlsClient: the timeout raises a fatal alert by design
        }

        public void notifyAlertReceived(short alertLevel, short alertDescription)
        {
        }
    }

    private static class AlertDripInputStream
        extends InputStream
    {
        private static final byte[] WARNING_ALERT_RECORD = new byte[]{
            (byte)ContentType.alert, 0x03, 0x03, 0x00, 0x02,
            (byte)AlertLevel.warning, (byte)AlertDescription.user_canceled };

        private final long delayMillis;
        private final int recordLimit;

        private int recordCount = 0;
        private int pos = 0;

        AlertDripInputStream(long delayMillis, int recordLimit)
        {
            this.delayMillis = delayMillis;
            this.recordLimit = recordLimit;
        }

        public int read()
            throws IOException
        {
            byte[] b = new byte[1];
            int n = read(b, 0, 1);
            return n < 0 ? -1 : (b[0] & 0xFF);
        }

        public int read(byte[] b, int off, int len)
            throws IOException
        {
            if (len < 1)
            {
                return 0;
            }

            if (pos == 0)
            {
                if (recordLimit >= 0 && recordCount >= recordLimit)
                {
                    return -1;
                }

                ++recordCount;

                try
                {
                    Thread.sleep(delayMillis);
                }
                catch (InterruptedException e)
                {
                    throw new IOException("interrupted");
                }
            }

            int n = Math.min(len, WARNING_ALERT_RECORD.length - pos);
            System.arraycopy(WARNING_ALERT_RECORD, pos, b, off, n);

            pos = (pos + n) % WARNING_ALERT_RECORD.length;

            return n;
        }
    }
}
