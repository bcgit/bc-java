package org.bouncycastle.tls.test;

import java.io.IOException;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * End-to-end DTLS 1.3 handshakes between the BC client and the BC server.
 * <p>
 * The assertions are deliberately made against the bytes on the wire, rather than against internal
 * record-layer state, so that a DTLS 1.2 handshake which merely happened to complete could not pass: RFC
 * 9147 4's unified header and RFC 9147 6.1's epoch numbering are both observable from outside.
 */
public class DTLS13ProtocolTest
    extends TestCase
{
    private static final int HANDSHAKE_TIMEOUT_MILLIS = 60000;

    /*
     * RFC 9147 4. Re-derived here rather than read from the package-private DTLS13UnifiedHeader, so that the
     * test checks the encoding independently of the constants the implementation uses.
     */
    private static final int UNIFIED_FIXED_BITS = 0x20;
    private static final int UNIFIED_FIXED_BITS_MASK = 0xE0;
    private static final int UNIFIED_FLAG_CID = 0x10;
    private static final int UNIFIED_FLAG_SEQ16 = 0x08;
    private static final int UNIFIED_FLAG_LENGTH = 0x04;
    private static final int UNIFIED_EPOCH_BITS_MASK = 0x03;

    /** RFC 9147 5.2. The DTLS handshake message header, which the wire keeps and the transcript omits. */
    private static final int MESSAGE_HEADER_LENGTH = 12;

    private static final int PLAINTEXT_HEADER_LENGTH = 13;

    public void testClientServer() throws Exception
    {
        Harness harness = new Harness();

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertTrue("client cipher suite is not a TLS 1.3 suite: " + harness.clientCipherSuite,
            isTLSv13CipherSuite(harness.clientCipherSuite));
        assertTrue("server cipher suite is not a TLS 1.3 suite: " + harness.serverCipherSuite,
            isTLSv13CipherSuite(harness.serverCipherSuite));
        assertEquals("cipher suites differ", harness.clientCipherSuite, harness.serverCipherSuite);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        checkClientHello(harness.clientRecords());
        checkServerHello(harness.serverRecords());

        checkUnifiedHeadersAfterHello(harness.clientRecords(), "client");
        checkUnifiedHeadersAfterHello(harness.serverRecords(), "server");

        checkEpochProgression(harness.clientRecords(), "client");
        checkEpochProgression(harness.serverRecords(), "server");
    }

    /**
     * RFC 9147 5.8.1. The client's final flight is dropped once, so the server retransmits its own flight
     * under the handshake traffic keys and the client must answer with a retransmitted Finished at the epoch
     * the server can still read. Without the record layer retaining the handshake epoch for reading, the
     * retransmitted server flight is discarded and the handshake never completes.
     */
    public void testClientServerWithClientFinishedLost() throws Exception
    {
        Harness harness = new Harness();
        harness.dropFirstClientEpoch2Datagram = true;

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));

        assertTrue("the client's final flight was not dropped", harness.dropped > 0);

        int clientEpoch2Records = countRecordsAtEpoch(harness.clientRecords(), 2);
        assertTrue("the client did not retransmit its final flight (epoch 2 records: " + clientEpoch2Records
            + ")", clientEpoch2Records >= 2);

        checkUnifiedHeadersAfterHello(harness.clientRecords(), "client");

        /*
         * The Finished still goes out at the handshake epoch first, and the retransmission of it arrives after
         * the client has moved on to epoch 3 - which is the whole point: the write epoch is not wound back, so
         * the retransmission is addressed to the retained handshake epoch while application data continues at
         * the application epoch.
         */
        assertEquals("the client's first protected record was not at the handshake epoch", 2,
            firstProtectedEpoch(harness.clientRecords()));
        assertTrue("the client did not retransmit at the handshake epoch after reaching epoch 3",
            lastProtectedEpoch(harness.clientRecords()) == 3
                && epochSequence(harness.clientRecords()).indexOf("323") >= 0);
    }

    /**
     * The ACK-driven retransmission of RFC 9147 7 over a lossy path, in both directions.
     */
    public void testClientServerWithPacketLoss() throws Exception
    {
        Harness harness = new Harness();
        harness.loss = new UnreliableDatagramTransportFactory(new Random(0x13131313L), 10, 10);

        harness.run(16);

        assertEquals("client negotiated version", ProtocolVersion.DTLSv13, harness.clientVersion);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv13, harness.serverVersion);

        assertNotNull("no application data echoed back", harness.echo);
        assertTrue("echoed application data differs", Arrays.areEqual(harness.request, harness.echo));
    }

    private static boolean isTLSv13CipherSuite(int cipherSuite)
    {
        switch (cipherSuite)
        {
        case CipherSuite.TLS_AES_128_CCM_8_SHA256:
        case CipherSuite.TLS_AES_128_CCM_SHA256:
        case CipherSuite.TLS_AES_128_GCM_SHA256:
        case CipherSuite.TLS_AES_256_GCM_SHA384:
        case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return true;
        default:
            return false;
        }
    }

    /**
     * RFC 9147 5.3 and 5.2. The ClientHello is a plaintext record at epoch 0, and carries the full 12-byte
     * DTLS handshake message header on the wire - which is exactly what the DTLS 1.3 transcript must
     * <em>not</em> include (RFC 9147 5.2), so this pins the two encodings apart.
     */
    private void checkClientHello(Vector records) throws IOException
    {
        assertFalse("no client records captured", records.isEmpty());

        Record first = (Record)records.elementAt(0);

        assertFalse("the ClientHello used the DTLS 1.3 unified header", first.isUnified());
        assertEquals("ClientHello record content type", ContentType.handshake, first.getContentType());
        assertEquals("ClientHello record epoch", 0, first.getPlaintextEpoch());

        byte[] fragment = first.getFragment();
        assertTrue("ClientHello record too short for a handshake message header",
            fragment.length >= MESSAGE_HEADER_LENGTH);

        assertEquals("handshake message type", HandshakeType.client_hello, fragment[0] & 0xFF);

        int length = readUint24(fragment, 1);
        int messageSeq = readUint16(fragment, 4);
        int fragmentOffset = readUint24(fragment, 6);
        int fragmentLength = readUint24(fragment, 9);

        assertEquals("ClientHello message_seq", 0, messageSeq);
        assertEquals("ClientHello fragment_offset", 0, fragmentOffset);
        assertEquals("ClientHello fragment_length", length, fragmentLength);
        assertEquals("ClientHello record length", MESSAGE_HEADER_LENGTH + fragmentLength, fragment.length);
    }

    /** RFC 9147 5.3. The ServerHello is still a plaintext record, with legacy_record_version 0xfefd. */
    private void checkServerHello(Vector records) throws IOException
    {
        assertFalse("no server records captured", records.isEmpty());

        Record first = (Record)records.elementAt(0);

        assertFalse("the ServerHello used the DTLS 1.3 unified header", first.isUnified());
        assertEquals("ServerHello record content type", ContentType.handshake, first.getContentType());
        assertEquals("ServerHello record epoch", 0, first.getPlaintextEpoch());
        assertEquals("ServerHello legacy_record_version", ProtocolVersion.DTLSv12, first.getPlaintextVersion());

        assertEquals("handshake message type", HandshakeType.server_hello, first.getFragment()[0] & 0xFF);
    }

    /**
     * RFC 9147 4. Every record after the initial plaintext hello must be a DTLSCiphertext with the unified
     * header, whose first byte has the fixed bits 001 in its top three bits.
     */
    private void checkUnifiedHeadersAfterHello(Vector records, String side)
    {
        int unified = 0;

        for (int i = 1; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);

            assertTrue(side + " record " + i + " is not a DTLS 1.3 unified-header record (first byte 0x"
                + Integer.toHexString(record.getFirstByte()) + ")", record.isUnified());

            assertEquals(side + " record " + i + " unified header fixed bits", UNIFIED_FIXED_BITS,
                record.getFirstByte() & UNIFIED_FIXED_BITS_MASK);

            ++unified;
        }

        assertTrue("no unified-header records sent by the " + side, unified > 0);
    }

    /**
     * RFC 9147 6.1. Epoch 1 is reserved for early data, so the handshake traffic keys are epoch 2 and the
     * application traffic keys epoch 3. Nothing may be sent at epoch 3 before the Finished has gone out at
     * epoch 2, and the connection must actually reach epoch 3.
     */
    private void checkEpochProgression(Vector records, String side)
    {
        boolean seenEpoch2 = false;
        boolean seenEpoch3 = false;

        for (int i = 0; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);
            if (!record.isUnified())
            {
                continue;
            }

            int epochBits = record.getFirstByte() & UNIFIED_EPOCH_BITS_MASK;

            if (2 == epochBits)
            {
                assertFalse(side + " sent a handshake-epoch record after moving to epoch 3", seenEpoch3);
                seenEpoch2 = true;
            }
            else if (3 == epochBits)
            {
                assertTrue(side + " reached epoch 3 without sending anything at epoch 2", seenEpoch2);
                seenEpoch3 = true;
            }
            else
            {
                fail(side + " sent a protected record with unexpected epoch bits " + epochBits);
            }
        }

        assertTrue(side + " sent nothing at the handshake epoch", seenEpoch2);
        assertTrue(side + " never reached epoch 3", seenEpoch3);
    }

    /** The epoch bits of each protected record, in order, as digits. */
    private static String epochSequence(Vector records)
    {
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);
            if (record.isUnified())
            {
                sb.append((char)('0' + (record.getFirstByte() & UNIFIED_EPOCH_BITS_MASK)));
            }
        }

        return sb.toString();
    }

    private static int firstProtectedEpoch(Vector records)
    {
        String epochs = epochSequence(records);
        return epochs.length() < 1 ? -1 : epochs.charAt(0) - '0';
    }

    private static int lastProtectedEpoch(Vector records)
    {
        String epochs = epochSequence(records);
        return epochs.length() < 1 ? -1 : epochs.charAt(epochs.length() - 1) - '0';
    }

    private static int countRecordsAtEpoch(Vector records, int epoch)
    {
        int count = 0;

        for (int i = 0; i < records.size(); ++i)
        {
            Record record = (Record)records.elementAt(i);
            if (record.isUnified() && (record.getFirstByte() & UNIFIED_EPOCH_BITS_MASK) == (epoch & 0x03))
            {
                ++count;
            }
        }

        return count;
    }

    private static int readUint16(byte[] buf, int off)
    {
        return ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
    }

    private static int readUint24(byte[] buf, int off)
    {
        return ((buf[off] & 0xFF) << 16) | ((buf[off + 1] & 0xFF) << 8) | (buf[off + 2] & 0xFF);
    }

    /**
     * The harness drives one complete handshake and one application-data exchange, recording every record
     * that crossed the client's transport in either direction.
     */
    static class Harness
    {
        boolean dropFirstClientEpoch2Datagram = false;
        UnreliableDatagramTransportFactory loss = null;

        ProtocolVersion clientVersion = null;
        ProtocolVersion serverVersion = null;
        int clientCipherSuite = -1;
        int serverCipherSuite = -1;
        byte[] request = null;
        byte[] echo = null;
        int dropped = 0;

        private RecordingDatagramTransport recording = null;

        Vector clientRecords()
        {
            return recording.getSentRecords();
        }

        Vector serverRecords()
        {
            return recording.getReceivedRecords();
        }

        void run(int dataLength) throws Exception
        {
            MockDTLSClient client = new MockDTLSClient(null)
            {
                protected ProtocolVersion[] getSupportedVersions()
                {
                    return ProtocolVersion.DTLSv13.only();
                }

                public void notifyServerVersion(ProtocolVersion version) throws IOException
                {
                    super.notifyServerVersion(version);

                    clientVersion = version;
                }

                public void notifyHandshakeComplete() throws IOException
                {
                    super.notifyHandshakeComplete();

                    clientCipherSuite = context.getSecurityParametersConnection().getCipherSuite();
                }
            };
            client.setHandshakeTimeoutMillis(HANDSHAKE_TIMEOUT_MILLIS);

            MockDTLSServer server = new MockDTLSServer()
            {
                protected ProtocolVersion[] getSupportedVersions()
                {
                    return ProtocolVersion.DTLSv13.only();
                }

                public int getHandshakeTimeoutMillis()
                {
                    return HANDSHAKE_TIMEOUT_MILLIS;
                }

                public ProtocolVersion getServerVersion() throws IOException
                {
                    ProtocolVersion version = super.getServerVersion();

                    serverVersion = version;

                    return version;
                }

                public void notifyHandshakeComplete() throws IOException
                {
                    super.notifyHandshakeComplete();

                    serverCipherSuite = context.getSecurityParametersConnection().getCipherSuite();
                }
            };

            MockDatagramAssociation network = new MockDatagramAssociation(1500);

            ServerThread serverThread = new ServerThread(new DTLSServerProtocol(), server, network.getServer());
            serverThread.setDaemon(true);
            serverThread.start();

            DatagramTransport clientTransport = network.getClient();

            if (null != loss)
            {
                clientTransport = loss.create(clientTransport);
            }

            this.recording = new RecordingDatagramTransport(clientTransport);
            recording.dropFirstEpoch2Datagram = dropFirstClientEpoch2Datagram;

            try
            {
                DTLSTransport dtlsClient = new DTLSClientProtocol().connect(client, recording);

                this.request = new byte[dataLength];
                Arrays.fill(request, (byte)0x5A);

                byte[] buf = new byte[dtlsClient.getReceiveLimit()];

                /*
                 * The request is re-sent on each attempt: with loss, the server may still be completing its
                 * own handshake when the client's first application record arrives at an epoch the server
                 * cannot yet read, and that record is legitimately discarded.
                 */
                for (int attempt = 0; attempt < 20 && null == echo; ++attempt)
                {
                    dtlsClient.send(request, 0, request.length);

                    int length = dtlsClient.receive(buf, 0, buf.length, 500);
                    if (length >= 0)
                    {
                        this.echo = Arrays.copyOfRange(buf, 0, length);
                    }
                }

                dtlsClient.close();
            }
            finally
            {
                this.dropped = recording.getDropped();

                serverThread.shutdown();
            }
        }
    }

    static class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final TlsServer server;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;

        ServerThread(DTLSServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.serverTransport = serverTransport;
        }

        public void run()
        {
            try
            {
                /*
                 * NOTE: Not the DTLSVerifier harness the DTLS 1.2 tests use: that issues a DTLS 1.2
                 * HelloVerifyRequest, where RFC 9147 uses a HelloRetryRequest cookie instead.
                 */
                DTLSTransport dtlsTransport = serverProtocol.accept(server, serverTransport);

                byte[] buf = new byte[dtlsTransport.getReceiveLimit()];
                while (!isShutdown)
                {
                    int length = dtlsTransport.receive(buf, 0, buf.length, 100);
                    if (length >= 0)
                    {
                        dtlsTransport.send(buf, 0, length);
                    }
                }
                dtlsTransport.close();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }

        void shutdown()
            throws InterruptedException
        {
            if (!isShutdown)
            {
                isShutdown = true;
                this.join();
            }
        }
    }

    static class UnreliableDatagramTransportFactory
    {
        private final Random random;
        private final int percentPacketLossReceiving, percentPacketLossSending;

        UnreliableDatagramTransportFactory(Random random, int percentPacketLossReceiving,
            int percentPacketLossSending)
        {
            this.random = random;
            this.percentPacketLossReceiving = percentPacketLossReceiving;
            this.percentPacketLossSending = percentPacketLossSending;
        }

        DatagramTransport create(DatagramTransport transport)
        {
            return new UnreliableDatagramTransport(transport, random, percentPacketLossReceiving,
                percentPacketLossSending);
        }
    }

    /**
     * Records every record seen in either direction, and optionally drops the first datagram carrying a
     * record at the handshake epoch - which for the client is exactly its final flight.
     */
    static class RecordingDatagramTransport
        implements DatagramTransport
    {
        private final DatagramTransport transport;
        private final Vector sentRecords = new Vector();
        private final Vector receivedRecords = new Vector();

        boolean dropFirstEpoch2Datagram = false;

        private int dropped = 0;

        RecordingDatagramTransport(DatagramTransport transport)
        {
            this.transport = transport;
        }

        Vector getSentRecords()
        {
            synchronized (sentRecords)
            {
                return new Vector(sentRecords);
            }
        }

        Vector getReceivedRecords()
        {
            synchronized (receivedRecords)
            {
                return new Vector(receivedRecords);
            }
        }

        int getDropped()
        {
            return dropped;
        }

        public int getReceiveLimit() throws IOException
        {
            return transport.getReceiveLimit();
        }

        public int getSendLimit() throws IOException
        {
            return transport.getSendLimit();
        }

        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException
        {
            int length = transport.receive(buf, off, len, waitMillis);
            if (length > 0)
            {
                Vector records = parseRecords(buf, off, length);
                synchronized (receivedRecords)
                {
                    for (int i = 0; i < records.size(); ++i)
                    {
                        receivedRecords.addElement(records.elementAt(i));
                    }
                }
            }
            return length;
        }

        public void send(byte[] buf, int off, int len) throws IOException
        {
            Vector records = parseRecords(buf, off, len);

            // NOTE: Recorded even when dropped below - these are the records the client emitted
            synchronized (sentRecords)
            {
                for (int i = 0; i < records.size(); ++i)
                {
                    sentRecords.addElement(records.elementAt(i));
                }
            }

            if (dropFirstEpoch2Datagram && containsEpoch(records, 2))
            {
                dropFirstEpoch2Datagram = false;
                ++dropped;

                System.out.println("DTLS 1.3 test: dropped the client's " + len + " byte handshake-epoch flight");
                return;
            }

            transport.send(buf, off, len);
        }

        public void close() throws IOException
        {
            transport.close();
        }

        private static boolean containsEpoch(Vector records, int epoch)
        {
            for (int i = 0; i < records.size(); ++i)
            {
                Record record = (Record)records.elementAt(i);
                if (record.isUnified() && (record.getFirstByte() & UNIFIED_EPOCH_BITS_MASK) == (epoch & 0x03))
                {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Splits a datagram into the records it carries - a flight is coalesced into as few datagrams as the MTU
     * allows, so one datagram is usually several records.
     */
    static Vector parseRecords(byte[] buf, int off, int len)
    {
        Vector records = new Vector();

        int pos = off;
        int end = off + len;

        while (pos < end)
        {
            int firstByte = buf[pos] & 0xFF;
            int recordLength;

            if ((firstByte & UNIFIED_FIXED_BITS_MASK) == UNIFIED_FIXED_BITS)
            {
                if ((firstByte & UNIFIED_FLAG_CID) != 0)
                {
                    // This implementation never writes a connection ID, so its length is not known here
                    throw new IllegalStateException("unexpected connection ID in a DTLS 1.3 record");
                }

                int headerLength = 1 + ((firstByte & UNIFIED_FLAG_SEQ16) != 0 ? 2 : 1)
                    + ((firstByte & UNIFIED_FLAG_LENGTH) != 0 ? 2 : 0);

                if ((firstByte & UNIFIED_FLAG_LENGTH) != 0)
                {
                    if (pos + headerLength > end)
                    {
                        break;
                    }
                    recordLength = headerLength + readUint16(buf, pos + headerLength - 2);
                }
                else
                {
                    recordLength = end - pos;
                }
            }
            else
            {
                if (pos + PLAINTEXT_HEADER_LENGTH > end)
                {
                    break;
                }
                recordLength = PLAINTEXT_HEADER_LENGTH + readUint16(buf, pos + 11);
            }

            if (recordLength < 1 || pos + recordLength > end)
            {
                break;
            }

            records.addElement(new Record(Arrays.copyOfRange(buf, pos, pos + recordLength)));

            pos += recordLength;
        }

        return records;
    }

    static class Record
    {
        private final byte[] record;

        Record(byte[] record)
        {
            this.record = record;
        }

        int getFirstByte()
        {
            return record[0] & 0xFF;
        }

        boolean isUnified()
        {
            return (getFirstByte() & UNIFIED_FIXED_BITS_MASK) == UNIFIED_FIXED_BITS;
        }

        short getContentType()
        {
            return (short)getFirstByte();
        }

        ProtocolVersion getPlaintextVersion()
        {
            return ProtocolVersion.get(record[1] & 0xFF, record[2] & 0xFF);
        }

        int getPlaintextEpoch()
        {
            return readUint16(record, 3);
        }

        /** The plaintext fragment of an unprotected record. */
        byte[] getFragment()
        {
            return Arrays.copyOfRange(record, PLAINTEXT_HEADER_LENGTH, record.length);
        }
    }
}
