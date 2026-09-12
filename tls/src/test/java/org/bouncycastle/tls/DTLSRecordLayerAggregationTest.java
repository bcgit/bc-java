package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * github #1487: handshake records written as one flight are packed into as few datagrams as the MTU
 * allows, instead of one datagram per record. Records written outside a flight still go out immediately.
 * Each send reports the record number it used, which the reliable handshake needs for ACK tracking.
 */
public class DTLSRecordLayerAggregationTest
    extends TestCase
{
    private static final int MTU = 300;

    /** Captures every datagram the record layer hands to the transport. */
    static class CapturingTransport
        implements DatagramTransport
    {
        final Vector datagrams = new Vector();

        /** Datagrams queued for the record layer to receive; an empty queue reads as a timeout. */
        final Vector inbound = new Vector();

        int sendLimit = MTU;

        public int getReceiveLimit()
        {
            return MTU;
        }

        public int getSendLimit()
        {
            return sendLimit;
        }

        public int receive(byte[] buf, int off, int len, int waitMillis)
        {
            if (!inbound.isEmpty())
            {
                byte[] datagram = (byte[])inbound.elementAt(0);
                inbound.removeElementAt(0);

                int length = Math.min(len, datagram.length);
                System.arraycopy(datagram, 0, buf, off, length);
                return length;
            }

            // NOTE: Block like a real transport would, so the caller's timers advance as it expects
            if (waitMillis > 0)
            {
                try
                {
                    Thread.sleep(waitMillis);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                }
            }

            return -1;
        }

        public void send(byte[] buf, int off, int len)
        {
            datagrams.addElement(Arrays.copyOfRange(buf, off, off + len));
        }

        public void close()
        {
        }
    }

    private CapturingTransport transport;
    private DTLSRecordLayer recordLayer;

    private void setUpPlaintextLayer() throws IOException
    {
        // epoch 0, null cipher: records go out in the legacy plaintext format, which is all this test needs
        TlsCrypto crypto = new BcTlsCrypto();
        AbstractTlsContext context = TlsAEADCipherDTLS13Test.createContext(crypto, false,
            CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, new byte[32], new byte[32]);

        TlsPeer peer = new DefaultTlsClient(crypto)
        {
            public TlsAuthentication getAuthentication()
            {
                return null;
            }
        };

        transport = new CapturingTransport();
        recordLayer = new DTLSRecordLayer(context, peer, transport);
        recordLayer.setWriteVersion(ProtocolVersion.DTLSv12);
        recordLayer.setReadVersion(ProtocolVersion.DTLSv12);
    }

    private static byte[] handshakeFragment(int length)
    {
        // a plausible handshake fragment: type, 24-bit length, message_seq, fragment offset/length, body
        byte[] fragment = new byte[DTLSReliableHandshake.MESSAGE_HEADER_LENGTH + length];
        TlsUtils.writeUint8(HandshakeType.certificate, fragment, 0);
        TlsUtils.writeUint24(length, fragment, 1);
        TlsUtils.writeUint16(0, fragment, 4);
        TlsUtils.writeUint24(0, fragment, 6);
        TlsUtils.writeUint24(length, fragment, 9);
        return fragment;
    }

    public void testRecordsOutsideAFlightGoOutImmediately() throws Exception
    {
        setUpPlaintextLayer();

        recordLayer.send(handshakeFragment(10), 0, DTLSReliableHandshake.MESSAGE_HEADER_LENGTH + 10);
        assertEquals(1, transport.datagrams.size());

        recordLayer.send(handshakeFragment(10), 0, DTLSReliableHandshake.MESSAGE_HEADER_LENGTH + 10);
        assertEquals(2, transport.datagrams.size());
    }

    public void testFlightRecordsSharePackedDatagrams() throws Exception
    {
        setUpPlaintextLayer();

        byte[] fragment = handshakeFragment(20);
        int len = fragment.length;

        recordLayer.beginFlight();
        for (int i = 0; i < 5; ++i)
        {
            recordLayer.send(fragment, 0, len);
        }
        // nothing is flushed until the flight ends or the datagram fills
        assertEquals(0, transport.datagrams.size());
        recordLayer.endFlight();

        assertEquals("five small records must share one datagram", 1, transport.datagrams.size());

        byte[] datagram = (byte[])transport.datagrams.elementAt(0);
        assertEquals(5 * (DTLSRecordLayer.RECORD_HEADER_LENGTH + len), datagram.length);
        assertTrue(datagram.length <= MTU);

        // every record in the datagram is well formed and carries the fragment
        int pos = 0;
        for (int i = 0; i < 5; ++i)
        {
            assertEquals(ContentType.handshake, TlsUtils.readUint8(datagram, pos));
            assertEquals(len, TlsUtils.readUint16(datagram, pos + 11));
            assertTrue(Arrays.areEqual(fragment, Arrays.copyOfRange(datagram,
                pos + DTLSRecordLayer.RECORD_HEADER_LENGTH,
                pos + DTLSRecordLayer.RECORD_HEADER_LENGTH + len)));
            pos += DTLSRecordLayer.RECORD_HEADER_LENGTH + len;
        }
        assertEquals(datagram.length, pos);
    }

    public void testFlightFlushesWhenTheDatagramFills() throws Exception
    {
        setUpPlaintextLayer();

        // each record is 13 + 12 + 80 = 105 bytes, so only two fit in a 300 byte datagram
        byte[] fragment = handshakeFragment(80);
        int len = fragment.length;

        recordLayer.beginFlight();
        for (int i = 0; i < 5; ++i)
        {
            recordLayer.send(fragment, 0, len);
        }
        recordLayer.endFlight();

        assertEquals("five 105 byte records across 300 byte datagrams", 3, transport.datagrams.size());
        for (int i = 0; i < transport.datagrams.size(); ++i)
        {
            byte[] datagram = (byte[])transport.datagrams.elementAt(i);
            assertTrue("datagram " + i + " exceeds the MTU", datagram.length <= MTU);
        }
        assertEquals(2 * (DTLSRecordLayer.RECORD_HEADER_LENGTH + len),
            ((byte[])transport.datagrams.elementAt(0)).length);
        assertEquals(1 * (DTLSRecordLayer.RECORD_HEADER_LENGTH + len),
            ((byte[])transport.datagrams.elementAt(2)).length);
    }

    public void testEndFlightWithNothingBufferedSendsNothing() throws Exception
    {
        setUpPlaintextLayer();

        recordLayer.beginFlight();
        recordLayer.endFlight();
        assertEquals(0, transport.datagrams.size());
    }

    public void testSendReportsIncreasingRecordNumbers() throws Exception
    {
        setUpPlaintextLayer();

        byte[] fragment = handshakeFragment(10);
        int len = fragment.length;

        DTLSRecordNumber first = recordLayer.sendReturningRecordNumber(fragment, 0, len);
        DTLSRecordNumber second = recordLayer.sendReturningRecordNumber(fragment, 0, len);

        assertNotNull(first);
        assertNotNull(second);
        assertEquals(0L, first.getEpoch());
        assertEquals(0L, second.getEpoch());
        assertEquals(first.getSequenceNumber() + 1, second.getSequenceNumber());

        // the reported sequence number is the one actually on the wire
        byte[] datagram = (byte[])transport.datagrams.elementAt(0);
        assertEquals(first.getSequenceNumber(), TlsUtils.readUint48(datagram, 5));
    }

    public void testBufferedSendsStillReportTheirRecordNumbers() throws Exception
    {
        setUpPlaintextLayer();

        byte[] fragment = handshakeFragment(10);
        int len = fragment.length;

        recordLayer.beginFlight();
        DTLSRecordNumber a = recordLayer.sendReturningRecordNumber(fragment, 0, len);
        DTLSRecordNumber b = recordLayer.sendReturningRecordNumber(fragment, 0, len);
        recordLayer.endFlight();

        assertEquals(a.getSequenceNumber() + 1, b.getSequenceNumber());
        assertEquals(1, transport.datagrams.size());

        byte[] datagram = (byte[])transport.datagrams.elementAt(0);
        assertEquals(a.getSequenceNumber(), TlsUtils.readUint48(datagram, 5));
        int secondOff = DTLSRecordLayer.RECORD_HEADER_LENGTH + len;
        assertEquals(b.getSequenceNumber(), TlsUtils.readUint48(datagram, secondOff + 5));
    }

    public void testAlertDuringAFlightIsSentImmediately() throws Exception
    {
        setUpPlaintextLayer();

        byte[] fragment = handshakeFragment(10);
        int len = fragment.length;

        recordLayer.beginFlight();
        recordLayer.send(fragment, 0, len);
        assertEquals("the handshake record must stay buffered", 0, transport.datagrams.size());

        recordLayer.warn(AlertDescription.close_notify, null);
        assertEquals("the alert must leave immediately, not sit behind the flight",
            2, transport.datagrams.size());

        // the buffered flight is flushed first, since it was written before the alert
        byte[] handshakeDatagram = (byte[])transport.datagrams.elementAt(0);
        assertEquals(ContentType.handshake, TlsUtils.readUint8(handshakeDatagram, 0));

        byte[] alertDatagram = (byte[])transport.datagrams.elementAt(1);
        assertEquals(ContentType.alert, TlsUtils.readUint8(alertDatagram, 0));

        recordLayer.endFlight();
        assertEquals("nothing is left buffered once the alert flushed the flight",
            2, transport.datagrams.size());
    }

    public void testApplicationDataDuringAFlightIsNotBuffered() throws Exception
    {
        setUpPlaintextLayer();

        byte[] fragment = handshakeFragment(10);
        int len = fragment.length;

        recordLayer.beginFlight();
        recordLayer.send(fragment, 0, len);
        assertEquals(0, transport.datagrams.size());

        // the record layer must be past the handshake for send() to classify the payload as application data
        recordLayer.inHandshake = false;

        byte[] appData = new byte[]{ 1, 2, 3, 4 };
        recordLayer.send(appData, 0, appData.length);

        assertEquals("application data racing the flight must not wait behind it",
            2, transport.datagrams.size());

        // write order is preserved: the flight written first leaves first
        byte[] handshakeDatagram = (byte[])transport.datagrams.elementAt(0);
        assertEquals(ContentType.handshake, TlsUtils.readUint8(handshakeDatagram, 0));

        byte[] datagram = (byte[])transport.datagrams.elementAt(1);
        assertEquals(ContentType.application_data, TlsUtils.readUint8(datagram, 0));

        recordLayer.endFlight();
        assertEquals("nothing is left buffered once the application data flushed the flight",
            2, transport.datagrams.size());
    }

    public void testNonHandshakeRecordFlushesTheFlightFirst() throws Exception
    {
        setUpPlaintextLayer();

        byte[] fragment = handshakeFragment(10);
        int len = fragment.length;

        recordLayer.beginFlight();
        recordLayer.send(fragment, 0, len);
        recordLayer.send(fragment, 0, len);
        assertEquals(0, transport.datagrams.size());

        // a change_cipher_spec written during the flight must not overtake the records before it
        byte[] ccs = new byte[]{ 1 };
        recordLayer.sendRecordForTest(ContentType.change_cipher_spec, ccs, 0, ccs.length);

        assertEquals(2, transport.datagrams.size());

        byte[] first = (byte[])transport.datagrams.elementAt(0);
        assertEquals("the buffered handshake records must leave in an earlier datagram",
            ContentType.handshake, TlsUtils.readUint8(first, 0));
        assertEquals(2 * (DTLSRecordLayer.RECORD_HEADER_LENGTH + len), first.length);

        byte[] second = (byte[])transport.datagrams.elementAt(1);
        assertEquals(ContentType.change_cipher_spec, TlsUtils.readUint8(second, 0));

        recordLayer.endFlight();
        assertEquals(2, transport.datagrams.size());
    }

    public void testCloseFlushesABufferedFlight() throws Exception
    {
        setUpPlaintextLayer();

        byte[] fragment = handshakeFragment(10);
        int len = fragment.length;

        recordLayer.beginFlight();
        recordLayer.send(fragment, 0, len);
        assertEquals(0, transport.datagrams.size());

        recordLayer.close();

        boolean handshakeRecordReachedTransport = false;
        for (int i = 0; i < transport.datagrams.size(); ++i)
        {
            byte[] datagram = (byte[])transport.datagrams.elementAt(i);
            if (ContentType.handshake == TlsUtils.readUint8(datagram, 0))
            {
                handshakeRecordReachedTransport = true;
            }
        }
        assertTrue("the buffered handshake record must reach the transport on close",
            handshakeRecordReachedTransport);
    }

    public void testRecordLargerThanTheSendLimitIsSentAlone() throws Exception
    {
        setUpPlaintextLayer();

        byte[] small = handshakeFragment(20);
        int smallLen = small.length;

        // an encoded record bigger than the 300 byte MTU on its own
        byte[] big = handshakeFragment(400);
        int bigLen = big.length;
        assertTrue(DTLSRecordLayer.RECORD_HEADER_LENGTH + bigLen > MTU);

        recordLayer.beginFlight();
        recordLayer.send(small, 0, smallLen);
        assertEquals(0, transport.datagrams.size());

        recordLayer.send(big, 0, bigLen);

        assertEquals("the buffered record must flush before the oversized record goes out alone",
            2, transport.datagrams.size());

        byte[] flushedDatagram = (byte[])transport.datagrams.elementAt(0);
        assertEquals(DTLSRecordLayer.RECORD_HEADER_LENGTH + smallLen, flushedDatagram.length);

        byte[] bigDatagram = (byte[])transport.datagrams.elementAt(1);
        assertEquals(DTLSRecordLayer.RECORD_HEADER_LENGTH + bigLen, bigDatagram.length);
        assertTrue(bigDatagram.length > MTU);

        recordLayer.endFlight();
        assertEquals("nothing left buffered after the oversized record was sent alone",
            2, transport.datagrams.size());
    }

    public void testShrunkSendLimitIsRespected() throws Exception
    {
        setUpPlaintextLayer();

        // each record is 13 + 12 + 80 = 105 bytes
        byte[] fragment = handshakeFragment(80);
        int len = fragment.length;

        transport.sendLimit = 300;
        recordLayer.beginFlight();
        for (int i = 0; i < 2; ++i)
        {
            recordLayer.send(fragment, 0, len);
        }
        recordLayer.endFlight();

        int datagramsBeforeShrink = transport.datagrams.size();

        transport.sendLimit = 150;
        recordLayer.beginFlight();
        for (int i = 0; i < 3; ++i)
        {
            recordLayer.send(fragment, 0, len);
        }
        recordLayer.endFlight();

        assertTrue(transport.datagrams.size() > datagramsBeforeShrink);
        for (int i = datagramsBeforeShrink; i < transport.datagrams.size(); ++i)
        {
            byte[] datagram = (byte[])transport.datagrams.elementAt(i);
            assertTrue("datagram " + i + " exceeds the shrunk send limit (150)", datagram.length <= 150);
        }
    }
}
