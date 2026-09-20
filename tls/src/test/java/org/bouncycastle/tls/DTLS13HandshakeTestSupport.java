package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsDTLS13Cipher;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

/**
 * Drives the outbound side of a real {@link DTLSReliableHandshake} over a real {@link DTLSRecordLayer} in
 * DTLS 1.3 mode, writing to a capturing transport. Everything asserted by the tests is read back off the
 * captured datagrams, so the assertions are about bytes actually emitted.
 */
class DTLS13HandshakeTestSupport
{
    // large enough that a 200 byte handshake message is one fragment and a flight shares one datagram
    private static final int SEND_LIMIT = 1200;

    // type, version, epoch, sequence number, length
    private static final int LEGACY_RECORD_HEADER_LENGTH = 13;

    final DTLSRecordLayerAggregationTest.CapturingTransport transport =
        new DTLSRecordLayerAggregationTest.CapturingTransport();

    private DTLSRecordLayer recordLayer;
    private DTLSReliableHandshake handshake;

    // the peer's half of the epoch keys, used to read the records back off the wire
    private TlsDTLS13Cipher peerCipher;

    private int writeEpoch;

    // false once begun without protected epochs, where records on the wire are plaintext at epoch 0
    private boolean protectedRecords = true;

    void begin() throws IOException
    {
        begin(60000);
    }

    /**
     * @param handshakeTimeoutMillis the overall handshake timeout, so a test can let the receive loop run to
     *                               its end without waiting a minute.
     */
    void begin(int handshakeTimeoutMillis) throws IOException
    {
        implBegin(handshakeTimeoutMillis, true, true);
    }

    /**
     * The same handshake over a DTLS 1.2 record layer: epoch 0, null cipher, legacy record format. Used to
     * show that none of the RFC 9147 ACK behaviour runs in DTLS 1.2.
     */
    void beginDTLS12(int handshakeTimeoutMillis) throws IOException
    {
        implBegin(handshakeTimeoutMillis, false, false);
    }

    private void implBegin(int handshakeTimeoutMillis, boolean dtls13, boolean protect) throws IOException
    {
        BcTlsCrypto crypto = new BcTlsCrypto();

        byte[] clientSecret = new byte[32];
        byte[] serverSecret = new byte[32];
        for (int i = 0; i < 32; ++i)
        {
            clientSecret[i] = (byte)i;
            serverSecret[i] = (byte)(0xFF - i);
        }

        AbstractTlsContext clientContext = TlsAEADCipherDTLS13Test.createContext(crypto, false,
            CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, clientSecret, serverSecret);
        AbstractTlsContext serverContext = TlsAEADCipherDTLS13Test.createContext(crypto, true,
            CipherSuite.TLS_AES_128_GCM_SHA256, CryptoHashAlgorithm.sha256, clientSecret, serverSecret);

        TlsPeer peer = new DefaultTlsClient(crypto)
        {
            public TlsAuthentication getAuthentication()
            {
                return null;
            }
        };

        transport.sendLimit = SEND_LIMIT;

        recordLayer = new DTLSRecordLayer(clientContext, peer, transport);
        recordLayer.setWriteVersion(ProtocolVersion.DTLSv12);
        recordLayer.setReadVersion(ProtocolVersion.DTLSv12);

        this.protectedRecords = protect;

        if (dtls13)
        {
            peerCipher = (TlsDTLS13Cipher)TlsUtils.initCipher(serverContext);

            // a pending DTLS 1.3 epoch is what switches the record layer to the RFC 9147 record format
            recordLayer.initPendingEpoch(TlsUtils.initCipher(clientContext));
        }

        if (protect)
        {
            // switch both directions to the first protected DTLS 1.3 epoch
            recordLayer.enablePendingEpochRead();
            recordLayer.enablePendingEpochWrite();
        }

        writeEpoch = recordLayer.getReadEpoch();

        handshake = new DTLSReliableHandshake(clientContext, recordLayer, handshakeTimeoutMillis, 1000, null,
            1 << 14);
    }

    /**
     * Write a flight of exactly 'fragmentLengths.length' handshake fragments, then close the flight the way
     * implReceiveMessage does.
     * <p>
     * The flight is two messages, as a real one would be: the leading fragments are one message split at
     * fragmentLengths[0] (every entry but the last must be that length, which is what a fragmented message
     * looks like on the wire), and the last entry is a second, unfragmented message.
     * </p>
     */
    void writeFlight(int[] fragmentLengths) throws IOException
    {
        int fragmentLimit = fragmentLengths[0];

        int leadingLength = 0;
        for (int i = 0; i < fragmentLengths.length - 1; ++i)
        {
            if (fragmentLengths[i] != fragmentLimit)
            {
                throw new IllegalArgumentException("only the last fragment may be short");
            }
            leadingLength += fragmentLengths[i];
        }

        // the record layer's send limit is what writeMessage fragments against
        recordLayer.setPlaintextLimit(DTLSReliableHandshake.MESSAGE_HEADER_LENGTH + fragmentLimit);

        handshake.sendMessage(HandshakeType.certificate, new byte[leadingLength]);
        handshake.sendMessage(HandshakeType.certificate,
            new byte[fragmentLengths[fragmentLengths.length - 1]]);

        handshake.endFlightForTest();
    }

    /** The record numbers of the handshake records on the wire, in the order they were sent. */
    Vector getSentRecordNumbers() throws IOException
    {
        Vector recordNumbers = new Vector();

        Vector records = parseHandshakeRecords();
        for (int i = 0; i < records.size(); ++i)
        {
            recordNumbers.addElement(((ParsedRecord)records.elementAt(i)).recordNumber);
        }

        return recordNumbers;
    }

    /**
     * Deliver an ACK the way the record layer's listener does, round-tripped through the wire encoding.
     * (The record layer's own ACK receive path is covered by DTLSAckTransportTest.)
     */
    void deliverAck(Vector recordNumbers) throws IOException
    {
        byte[] body = DTLSAck.encode(recordNumbers);
        Vector decoded = DTLSAck.decode(body, 0, body.length);

        handshake.acknowledgeForTest(decoded);
    }

    /**
     * Run the real receive loop against a transport that never delivers anything, until the handshake
     * timeout fires. Every retransmission decision the loop makes is a real one.
     */
    void receiveUntilHandshakeTimeout() throws IOException
    {
        handshake.receiveMessage();
    }

    /** Drive the retransmission path as a resend timeout would. */
    void timeoutAndResend() throws IOException
    {
        handshake.resendOutboundFlightForTest();
    }

    int countRecordsSent() throws IOException
    {
        return parseHandshakeRecords().size();
    }

    int lastFragmentOffsetSent() throws IOException
    {
        Vector records = parseHandshakeRecords();
        if (records.isEmpty())
        {
            throw new IllegalStateException("no handshake records were sent");
        }

        byte[] fragment = ((ParsedRecord)records.elementAt(records.size() - 1)).fragment;
        return TlsUtils.readUint24(fragment, 6);
    }

    /** The epoch both directions of the record layer are at. */
    int getReadEpoch()
    {
        return recordLayer.getReadEpoch();
    }

    /** The record layer's plaintext send limit, which is what bounds one ACK body. */
    int getSendLimit() throws IOException
    {
        return recordLayer.getSendLimit();
    }

    /** The record number an inbound record delivered with 'recordSeq' will have. */
    DTLSRecordNumber inboundRecordNumber(long recordSeq)
    {
        return new DTLSRecordNumber(writeEpoch, recordSeq);
    }

    /**
     * Queue one handshake record, framed and protected the way the peer would send it, for the record layer
     * to receive. The record carries a single handshake fragment.
     */
    void deliverHandshakeRecord(long recordSeq, short msgType, int messageSeq, int length, int fragmentOffset,
        int fragmentLength) throws IOException
    {
        deliverRecord(recordSeq, handshakeFragment(msgType, messageSeq, length, fragmentOffset, fragmentLength));
    }

    /**
     * Queue one handshake record carrying the same fragment twice. A record may carry several handshake
     * messages, and this is how a duplicate of an already complete message reaches the reassembler: the
     * first copy completes the message and the second arrives before the caller has drained it.
     */
    void deliverRepeatedHandshakeRecord(long recordSeq, short msgType, int messageSeq, int length,
        int fragmentOffset, int fragmentLength) throws IOException
    {
        byte[] one = handshakeFragment(msgType, messageSeq, length, fragmentOffset, fragmentLength);

        byte[] both = new byte[one.length * 2];
        System.arraycopy(one, 0, both, 0, one.length);
        System.arraycopy(one, 0, both, one.length, one.length);

        deliverRecord(recordSeq, both);
    }

    private void deliverRecord(long recordSeq, byte[] fragment) throws IOException
    {
        transport.inbound.addElement(protectedRecords ? protectedRecord(recordSeq, fragment)
            : plaintextRecord(recordSeq, fragment));
    }

    private static byte[] handshakeFragment(short msgType, int messageSeq, int length, int fragmentOffset,
        int fragmentLength)
    {
        byte[] fragment = new byte[DTLSReliableHandshake.MESSAGE_HEADER_LENGTH + fragmentLength];
        TlsUtils.writeUint8(msgType, fragment, 0);
        TlsUtils.writeUint24(length, fragment, 1);
        TlsUtils.writeUint16(messageSeq, fragment, 4);
        TlsUtils.writeUint24(fragmentOffset, fragment, 6);
        TlsUtils.writeUint24(fragmentLength, fragment, 9);
        return fragment;
    }

    private byte[] protectedRecord(long recordSeq, byte[] fragment) throws IOException
    {
        int firstByte = DTLS13UnifiedHeader.FIXED_BITS | DTLS13UnifiedHeader.FLAG_SEQ16
            | DTLS13UnifiedHeader.FLAG_LENGTH | (writeEpoch & DTLS13UnifiedHeader.EPOCH_BITS_MASK);

        byte[] header = TlsAEADCipherDTLS13Test.header(firstByte, recordSeq);

        TlsEncodeResult encoded = peerCipher.encodeDTLS13Plaintext(recordSeq, ContentType.handshake, header, 0,
            header.length, fragment, 0, fragment.length);

        return Arrays.copyOfRange(encoded.buf, encoded.off, encoded.off + encoded.len);
    }

    private byte[] plaintextRecord(long recordSeq, byte[] fragment) throws IOException
    {
        byte[] record = new byte[LEGACY_RECORD_HEADER_LENGTH + fragment.length];
        TlsUtils.writeUint8(ContentType.handshake, record, 0);
        TlsUtils.writeVersion(ProtocolVersion.DTLSv12, record, 1);
        TlsUtils.writeUint16(writeEpoch, record, 3);
        TlsUtils.writeUint48(recordSeq, record, 5);
        TlsUtils.writeUint16(fragment.length, record, 11);
        System.arraycopy(fragment, 0, record, LEGACY_RECORD_HEADER_LENGTH, fragment.length);
        return record;
    }

    /** Receive one complete handshake message. */
    DTLSReliableHandshake.Message receiveMessage() throws IOException
    {
        return handshake.receiveMessage();
    }

    /**
     * Run the real receive loop until the handshake timeout fires. Nothing here ever completes a whole
     * flight, so the timeout is the expected end of the loop and is not itself the thing under test.
     */
    void receiveUntilTimeout() throws IOException
    {
        try
        {
            handshake.receiveMessage();
        }
        catch (TlsTimeoutException e)
        {
            // expected
        }
    }

    /** Send a small message, which opens a new outbound flight (and so a new inbound flight). */
    void setNextSendSeq(int nextSendSeq)
    {
        handshake.setNextSendSeqForTest(nextSendSeq);
    }

    void sendMessage() throws IOException
    {
        handshake.sendMessage(HandshakeType.certificate, new byte[8]);
    }

    void finish() throws IOException
    {
        handshake.finish();
    }

    /** The decoded record-number lists of the ACK records on the wire, in the order they were sent. */
    Vector getAcksSent() throws IOException
    {
        Vector acks = new Vector();

        Vector records = parseRecords(ContentType.ack);
        for (int i = 0; i < records.size(); ++i)
        {
            byte[] body = ((ParsedRecord)records.elementAt(i)).fragment;
            acks.addElement(DTLSAck.decode(body, 0, body.length));
        }

        return acks;
    }

    private static class ParsedRecord
    {
        final short contentType;
        final DTLSRecordNumber recordNumber;
        final byte[] fragment;

        ParsedRecord(short contentType, DTLSRecordNumber recordNumber, byte[] fragment)
        {
            this.contentType = contentType;
            this.recordNumber = recordNumber;
            this.fragment = fragment;
        }
    }

    /** Every captured record, in the order it was sent. */
    private Vector parseHandshakeRecords() throws IOException
    {
        return parseRecords(ContentType.handshake);
    }

    /**
     * Walk every captured datagram, unmask and decrypt each record, and return those of 'contentType'.
     */
    private Vector parseRecords(short contentType) throws IOException
    {
        if (!protectedRecords)
        {
            return parsePlaintextRecords(contentType);
        }

        Vector records = new Vector();

        for (int i = 0; i < transport.datagrams.size(); ++i)
        {
            byte[] datagram = (byte[])transport.datagrams.elementAt(i);

            int pos = 0;
            while (pos < datagram.length)
            {
                int firstByte = datagram[pos] & 0xFF;
                if (!DTLS13UnifiedHeader.isCiphertextRecord(firstByte)
                    || !DTLS13UnifiedHeader.hasLength(firstByte))
                {
                    throw new IllegalStateException("unexpected record form in datagram " + i);
                }

                int headerLength = DTLS13UnifiedHeader.getHeaderLength(firstByte, 0);
                int ciphertextLength = TlsUtils.readUint16(datagram, pos + headerLength - 2);
                int recordLength = headerLength + ciphertextLength;

                // NOTE: a fresh copy each time, since unmasking the record number rewrites the header
                byte[] record = Arrays.copyOfRange(datagram, pos, pos + recordLength);
                peerCipher.decryptDTLS13RecordNumber(record, 0, recordLength);

                long sequenceNumber = TlsUtils.readUint16(record, 1);

                TlsDecodeResult decoded = peerCipher.decodeDTLS13Ciphertext(sequenceNumber, record, 0, headerLength,
                    ciphertextLength);

                if (contentType == decoded.contentType)
                {
                    records.addElement(new ParsedRecord(decoded.contentType,
                        new DTLSRecordNumber(writeEpoch, sequenceNumber),
                        Arrays.copyOfRange(decoded.buf, decoded.off, decoded.off + decoded.len)));
                }

                pos += recordLength;
            }
        }

        return records;
    }

    /** The same walk over legacy (DTLS 1.2, epoch 0, null cipher) records. */
    private Vector parsePlaintextRecords(short contentType) throws IOException
    {
        Vector records = new Vector();

        for (int i = 0; i < transport.datagrams.size(); ++i)
        {
            byte[] datagram = (byte[])transport.datagrams.elementAt(i);

            int pos = 0;
            while (pos + LEGACY_RECORD_HEADER_LENGTH <= datagram.length)
            {
                short recordType = TlsUtils.readUint8(datagram, pos);
                int epoch = TlsUtils.readUint16(datagram, pos + 3);
                long sequenceNumber = TlsUtils.readUint48(datagram, pos + 5);
                int length = TlsUtils.readUint16(datagram, pos + 11);

                int bodyOff = pos + LEGACY_RECORD_HEADER_LENGTH;

                if (contentType == recordType)
                {
                    records.addElement(new ParsedRecord(recordType, new DTLSRecordNumber(epoch, sequenceNumber),
                        Arrays.copyOfRange(datagram, bodyOff, bodyOff + length)));
                }

                pos = bodyOff + length;
            }
        }

        return records;
    }
}
