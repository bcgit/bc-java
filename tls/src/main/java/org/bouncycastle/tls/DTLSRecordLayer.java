package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;

import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsNullNullCipher;
import org.bouncycastle.util.Arrays;

class DTLSRecordLayer
    implements DatagramTransport
{
    private static final int RECORD_HEADER_LENGTH = 13;
    private static final int MAX_FRAGMENT_LENGTH = 1 << 14;
    private static final long TCP_MSL = 1000L * 60 * 2;
    private static final long RETRANSMIT_TIMEOUT = TCP_MSL * 2;

    static byte[] receiveClientHelloRecord(byte[] data, int dataOff, int dataLen) throws IOException
    {
        if (dataLen < RECORD_HEADER_LENGTH)
        {
            return null;
        }

        short contentType = TlsUtils.readUint8(data, dataOff + 0);
        if (ContentType.handshake != contentType)
        {
            return null;
        }

        ProtocolVersion version = TlsUtils.readVersion(data, dataOff + 1);
        if (!ProtocolVersion.DTLSv10.isEqualOrEarlierVersionOf(version))
        {
            return null;
        }

        int epoch = TlsUtils.readUint16(data, dataOff + 3);
        if (0 != epoch)
        {
            return null;
        }

//        long sequenceNumber = TlsUtils.readUint48(data, dataOff + 5);

        int length = TlsUtils.readUint16(data, dataOff + 11);
        if (dataLen < RECORD_HEADER_LENGTH + length)
        {
            return null;
        }

        if (length > MAX_FRAGMENT_LENGTH)
        {
            return null;
        }

        // NOTE: We ignore/drop any data after the first record 
        return TlsUtils.copyOfRangeExact(data, dataOff + RECORD_HEADER_LENGTH, dataOff + RECORD_HEADER_LENGTH + length);
    }

    static void sendHelloVerifyRequestRecord(DatagramSender sender, long recordSeq, byte[] message) throws IOException
    {
        TlsUtils.checkUint16(message.length);

        byte[] record = new byte[RECORD_HEADER_LENGTH + message.length];
        TlsUtils.writeUint8(ContentType.handshake, record, 0);
        TlsUtils.writeVersion(ProtocolVersion.DTLSv10, record, 1);
        TlsUtils.writeUint16(0, record, 3);
        TlsUtils.writeUint48(recordSeq, record, 5);
        TlsUtils.writeUint16(message.length, record, 11);

        System.arraycopy(message, 0, record, RECORD_HEADER_LENGTH, message.length);

        sendDatagram(sender, record, 0, record.length);
    }

    private static void sendDatagram(DatagramSender sender, byte[] buf, int off, int len)
        throws IOException
    {
        try
        {
            sender.send(buf, off, len);
        }
        catch (InterruptedIOException e)
        {
            e.bytesTransferred = 0;
            throw e;
        }
    }

    private final TlsContext context;
    private final TlsPeer peer;
    private final DatagramTransport transport;

    private final ByteQueue recordQueue = new ByteQueue();
    private final Object writeLock = new Object();

    private volatile boolean closed = false;
    private volatile boolean failed = false;
    // TODO[dtls13] Review the draft/RFC (legacy_record_version) to see if readVersion can be removed
    private volatile ProtocolVersion readVersion = null, writeVersion = null;
    private volatile boolean inConnection;
    private volatile boolean inHandshake;
    private volatile int plaintextLimit;
    private DTLSEpoch currentEpoch, pendingEpoch;
    private DTLSEpoch readEpoch, writeEpoch;

    private DTLSHandshakeRetransmit retransmit = null;
    private DTLSEpoch retransmitEpoch = null;
    private Timeout retransmitTimeout = null;

    private TlsHeartbeat heartbeat = null;              // If non-null, controls the sending of heartbeat requests
    private boolean heartBeatResponder = false;         // Whether we should send heartbeat responses

    private HeartbeatMessage heartbeatInFlight = null;  // The current in-flight heartbeat request, if any
    private Timeout heartbeatTimeout = null;            // Idle timeout (if none in-flight), else expiry timeout for response

    private int heartbeatResendMillis = -1;             // Delay before retransmit of current in-flight heartbeat request
    private Timeout heartbeatResendTimeout = null;      // Timeout for next retransmit of the in-flight heartbeat request

    DTLSRecordLayer(TlsContext context, TlsPeer peer, DatagramTransport transport)
    {
        this.context = context;
        this.peer = peer;
        this.transport = transport;

        this.inHandshake = true;

        this.currentEpoch = new DTLSEpoch(0, TlsNullNullCipher.INSTANCE);
        this.pendingEpoch = null;
        this.readEpoch = currentEpoch;
        this.writeEpoch = currentEpoch;

        setPlaintextLimit(MAX_FRAGMENT_LENGTH);
    }

    boolean isClosed()
    {
        return closed;
    }

    void resetAfterHelloVerifyRequestServer(long recordSeq)
    {
        this.inConnection = true;

        currentEpoch.setSequenceNumber(recordSeq);
        currentEpoch.getReplayWindow().reset(recordSeq);
    }

    void setPlaintextLimit(int plaintextLimit)
    {
        this.plaintextLimit = plaintextLimit;
    }

    int getReadEpoch()
    {
        return readEpoch.getEpoch();
    }

    ProtocolVersion getReadVersion()
    {
        return readVersion;
    }

    void setReadVersion(ProtocolVersion readVersion)
    {
        this.readVersion = readVersion;
    }

    void setWriteVersion(ProtocolVersion writeVersion)
    {
        this.writeVersion = writeVersion;
    }

    void initPendingEpoch(TlsCipher pendingCipher)
    {
        if (pendingEpoch != null)
        {
            throw new IllegalStateException();
        }

        /*
         * TODO "In order to ensure that any given sequence/epoch pair is unique, implementations
         * MUST NOT allow the same epoch value to be reused within two times the TCP maximum segment
         * lifetime."
         */

        // TODO Check for overflow
        this.pendingEpoch = new DTLSEpoch(writeEpoch.getEpoch() + 1, pendingCipher);
    }

    void handshakeSuccessful(DTLSHandshakeRetransmit retransmit)
    {
        if (readEpoch == currentEpoch || writeEpoch == currentEpoch)
        {
            // TODO
            throw new IllegalStateException();
        }

        if (null != retransmit)
        {
            this.retransmit = retransmit;
            this.retransmitEpoch = currentEpoch;
            this.retransmitTimeout = new Timeout(RETRANSMIT_TIMEOUT);
        }

        this.inHandshake = false;
        this.currentEpoch = pendingEpoch;
        this.pendingEpoch = null;
    }

    void initHeartbeat(TlsHeartbeat heartbeat, boolean heartbeatResponder)
    {
        if (inHandshake)
        {
            throw new IllegalStateException();
        }

        this.heartbeat = heartbeat;
        this.heartBeatResponder = heartbeatResponder;

        if (null != heartbeat)
        {
            resetHeartbeat();
        }
    }

    void resetWriteEpoch()
    {
        if (null != retransmitEpoch)
        {
            this.writeEpoch = retransmitEpoch;
        }
        else
        {
            this.writeEpoch = currentEpoch;
        }
    }

    public int getReceiveLimit()
        throws IOException
    {
        return Math.min(this.plaintextLimit,
            readEpoch.getCipher().getPlaintextLimit(transport.getReceiveLimit() - RECORD_HEADER_LENGTH));
    }

    public int getSendLimit()
        throws IOException
    {
        return Math.min(this.plaintextLimit,
            writeEpoch.getCipher().getPlaintextLimit(transport.getSendLimit() - RECORD_HEADER_LENGTH));
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        long currentTimeMillis = System.currentTimeMillis();

        Timeout timeout = Timeout.forWaitMillis(waitMillis, currentTimeMillis);
        byte[] record = null;

        while (waitMillis >= 0)
        {
            if (null != retransmitTimeout && retransmitTimeout.remainingMillis(currentTimeMillis) < 1)
            {
                retransmit = null;
                retransmitEpoch = null;
                retransmitTimeout = null;
            }

            if (Timeout.hasExpired(heartbeatTimeout, currentTimeMillis))
            {
                if (null != heartbeatInFlight)
                {
                    throw new TlsTimeoutException("Heartbeat timed out");
                }

                this.heartbeatInFlight = HeartbeatMessage.create(context, HeartbeatMessageType.heartbeat_request,
                    heartbeat.generatePayload());
                this.heartbeatTimeout = new Timeout(heartbeat.getTimeoutMillis(), currentTimeMillis);

                this.heartbeatResendMillis = DTLSReliableHandshake.INITIAL_RESEND_MILLIS;
                this.heartbeatResendTimeout = new Timeout(heartbeatResendMillis, currentTimeMillis);

                sendHeartbeatMessage(heartbeatInFlight);
            }
            else if (Timeout.hasExpired(heartbeatResendTimeout, currentTimeMillis))
            {
                this.heartbeatResendMillis = DTLSReliableHandshake.backOff(heartbeatResendMillis);
                this.heartbeatResendTimeout = new Timeout(heartbeatResendMillis, currentTimeMillis);

                sendHeartbeatMessage(heartbeatInFlight);
            }

            waitMillis = Timeout.constrainWaitMillis(waitMillis, heartbeatTimeout, currentTimeMillis);
            waitMillis = Timeout.constrainWaitMillis(waitMillis, heartbeatResendTimeout, currentTimeMillis);

            // NOTE: Guard against bad logic giving a negative value 
            if (waitMillis < 0)
            {
                waitMillis = 1;
            }

            int receiveLimit = Math.min(len, getReceiveLimit()) + RECORD_HEADER_LENGTH;
            if (null == record || record.length < receiveLimit)
            {
                record = new byte[receiveLimit];
            }

            int received = receiveRecord(record, 0, receiveLimit, waitMillis);
            int processed = processRecord(received, record, buf, off);
            if (processed >= 0)
            {
                return processed;
            }

            currentTimeMillis = System.currentTimeMillis();
            waitMillis = Timeout.getWaitMillis(timeout, currentTimeMillis);
        }

        return -1;
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        short contentType = ContentType.application_data;

        if (this.inHandshake || this.writeEpoch == this.retransmitEpoch)
        {
            contentType = ContentType.handshake;

            short handshakeType = TlsUtils.readUint8(buf, off);
            if (handshakeType == HandshakeType.finished)
            {
                DTLSEpoch nextEpoch = null;
                if (this.inHandshake)
                {
                    nextEpoch = pendingEpoch;
                }
                else if (this.writeEpoch == this.retransmitEpoch)
                {
                    nextEpoch = currentEpoch;
                }

                if (nextEpoch == null)
                {
                    // TODO
                    throw new IllegalStateException();
                }

                // Implicitly send change_cipher_spec and change to pending cipher state

                // TODO Send change_cipher_spec and finished records in single datagram?
                byte[] data = new byte[]{ 1 };
                sendRecord(ContentType.change_cipher_spec, data, 0, data.length);

                writeEpoch = nextEpoch;
            }
        }

        sendRecord(contentType, buf, off, len);
    }

    public void close()
        throws IOException
    {
        if (!closed)
        {
            if (inHandshake && inConnection)
            {
                warn(AlertDescription.user_canceled, "User canceled handshake");
            }
            closeTransport();
        }
    }

    void fail(short alertDescription)
    {
        if (!closed)
        {
            if (inConnection)
            {
                try
                {
                    raiseAlert(AlertLevel.fatal, alertDescription, null, null);
                }
                catch (Exception e)
                {
                    // Ignore
                }
            }

            failed = true;

            closeTransport();
        }
    }

    void failed()
    {
        if (!closed)
        {
            failed = true;

            closeTransport();
        }
    }

    void warn(short alertDescription, String message)
        throws IOException
    {
        raiseAlert(AlertLevel.warning, alertDescription, message, null);
    }

    private void closeTransport()
    {
        if (!closed)
        {
            /*
             * RFC 5246 7.2.1. Unless some other fatal alert has been transmitted, each party is
             * required to send a close_notify alert before closing the write side of the
             * connection. The other party MUST respond with a close_notify alert of its own and
             * close down the connection immediately, discarding any pending writes.
             */

            try
            {
                if (!failed)
                {
                    warn(AlertDescription.close_notify, null);
                }
                transport.close();
            }
            catch (Exception e)
            {
                // Ignore
            }

            closed = true;
        }
    }

    private void raiseAlert(short alertLevel, short alertDescription, String message, Throwable cause)
        throws IOException
    {
        peer.notifyAlertRaised(alertLevel, alertDescription, message, cause);

        byte[] error = new byte[2];
        error[0] = (byte)alertLevel;
        error[1] = (byte)alertDescription;

        sendRecord(ContentType.alert, error, 0, 2);
    }

    private int receiveDatagram(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        try
        {
            return transport.receive(buf, off, len, waitMillis);
        }
        catch (SocketTimeoutException e)
        {
            return -1;
        }
        catch (InterruptedIOException e)
        {
            e.bytesTransferred = 0;
            throw e;
        }
    }

    // TODO Include 'currentTimeMillis' as an argument, use with Timeout, resetHeartbeat
    private int processRecord(int received, byte[] record, byte[] buf, int off)
        throws IOException
    {
        // NOTE: received < 0 (timeout) is covered by this first case
        if (received < RECORD_HEADER_LENGTH)
        {
            return -1;
        }
        int length = TlsUtils.readUint16(record, 11);
        if (received != (length + RECORD_HEADER_LENGTH))
        {
            return -1;
        }

        // TODO[dtls13] Deal with opaque record type for 1.3 AEAD ciphers
        short recordType = TlsUtils.readUint8(record, 0);

        switch (recordType)
        {
        case ContentType.alert:
        case ContentType.application_data:
        case ContentType.change_cipher_spec:
        case ContentType.handshake:
        case ContentType.heartbeat:
            break;
        default:
            return -1;
        }

        int epoch = TlsUtils.readUint16(record, 3);

        DTLSEpoch recordEpoch = null;
        if (epoch == readEpoch.getEpoch())
        {
            recordEpoch = readEpoch;
        }
        else if (recordType == ContentType.handshake && null != retransmitEpoch
            && epoch == retransmitEpoch.getEpoch())
        {
            recordEpoch = retransmitEpoch;
        }

        if (null == recordEpoch)
        {
            return -1;
        }

        long seq = TlsUtils.readUint48(record, 5);
        if (recordEpoch.getReplayWindow().shouldDiscard(seq))
        {
            return -1;
        }

        ProtocolVersion recordVersion = TlsUtils.readVersion(record, 1);
        if (!recordVersion.isDTLS())
        {
            return -1;
        }

        if (null != readVersion && !readVersion.equals(recordVersion))
        {
            /*
             * Special-case handling for retransmitted ClientHello records.
             * 
             * TODO Revisit how 'readVersion' works, since this is quite awkward.
             */
            boolean isClientHelloFragment =
                    getReadEpoch() == 0
                &&  length > 0
                &&  ContentType.handshake == recordType
                &&  HandshakeType.client_hello == TlsUtils.readUint8(record, RECORD_HEADER_LENGTH);

            if (!isClientHelloFragment)
            {
                return -1;
            }
        }

        long macSeqNo = getMacSequenceNumber(recordEpoch.getEpoch(), seq);

        TlsDecodeResult decoded = recordEpoch.getCipher().decodeCiphertext(macSeqNo, recordType, recordVersion, record,
            RECORD_HEADER_LENGTH, length);

        recordEpoch.getReplayWindow().reportAuthenticated(seq);

        if (decoded.len > this.plaintextLimit)
        {
            return -1;
        }
        if (decoded.len < 1 && decoded.contentType != ContentType.application_data)
        {
            return -1;
        }

        if (null == readVersion)
        {
            boolean isHelloVerifyRequest =
                    getReadEpoch() == 0
                &&  length > 0
                &&  ContentType.handshake == recordType
                &&  HandshakeType.hello_verify_request == TlsUtils.readUint8(record, RECORD_HEADER_LENGTH);

            if (isHelloVerifyRequest)
            {
                /*
                 * RFC 6347 4.2.1 DTLS 1.2 server implementations SHOULD use DTLS version 1.0
                 * regardless of the version of TLS that is expected to be negotiated. DTLS 1.2 and
                 * 1.0 clients MUST use the version solely to indicate packet formatting (which is
                 * the same in both DTLS 1.2 and 1.0) and not as part of version negotiation.
                 */
                if (!ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(recordVersion))
                {
                    return -1;
                }
            }
            else
            {
                readVersion = recordVersion;
            }
        }

        switch (decoded.contentType)
        {
        case ContentType.alert:
        {
            if (decoded.len == 2)
            {
                short alertLevel = TlsUtils.readUint8(decoded.buf, decoded.off);
                short alertDescription = TlsUtils.readUint8(decoded.buf, decoded.off + 1);

                peer.notifyAlertReceived(alertLevel, alertDescription);

                if (alertLevel == AlertLevel.fatal)
                {
                    failed();
                    throw new TlsFatalAlert(alertDescription);
                }

                // TODO Can close_notify be a fatal alert?
                if (alertDescription == AlertDescription.close_notify)
                {
                    closeTransport();
                }
            }

            return -1;
        }
        case ContentType.application_data:
        {
            if (inHandshake)
            {
                // TODO Consider buffering application data for new epoch that arrives
                // out-of-order with the Finished message
                return -1;
            }
            break;
        }
        case ContentType.change_cipher_spec:
        {
            // Implicitly receive change_cipher_spec and change to pending cipher state

            for (int i = 0; i < decoded.len; ++i)
            {
                short message = TlsUtils.readUint8(decoded.buf, decoded.off + i);
                if (message != ChangeCipherSpec.change_cipher_spec)
                {
                    continue;
                }

                if (pendingEpoch != null)
                {
                    readEpoch = pendingEpoch;
                }
            }

            return -1;
        }
        case ContentType.handshake:
        {
            if (!inHandshake)
            {
                if (null != retransmit)
                {
                    retransmit.receivedHandshakeRecord(epoch, decoded.buf, decoded.off, decoded.len);
                }

                // TODO Consider support for HelloRequest
                return -1;
            }
            break;
        }
        case ContentType.heartbeat:
        {
            if (null != heartbeatInFlight || heartBeatResponder)
            {
                try
                {
                    ByteArrayInputStream input = new ByteArrayInputStream(decoded.buf, decoded.off, decoded.len);
                    HeartbeatMessage heartbeatMessage = HeartbeatMessage.parse(input);

                    if (null != heartbeatMessage)
                    {
                        switch (heartbeatMessage.getType())
                        {
                        case HeartbeatMessageType.heartbeat_request:
                        {
                            if (heartBeatResponder)
                            {
                                HeartbeatMessage response = HeartbeatMessage.create(context,
                                    HeartbeatMessageType.heartbeat_response, heartbeatMessage.getPayload());

                                sendHeartbeatMessage(response);
                            }
                            break;
                        }
                        case HeartbeatMessageType.heartbeat_response:
                        {
                            if (null != heartbeatInFlight
                                && Arrays.areEqual(heartbeatMessage.getPayload(), heartbeatInFlight.getPayload()))
                            {
                                resetHeartbeat();
                            }
                            break;
                        }
                        default:
                            break;
                        }
                    }
                }
                catch (Exception e)
                {
                    // Ignore
                }
            }

            return -1;
        }
        default:
            return -1;
        }

        /*
         * NOTE: If we receive any non-handshake data in the new epoch implies the peer has
         * received our final flight.
         */
        if (!inHandshake && null != retransmit)
        {
            this.retransmit = null;
            this.retransmitEpoch = null;
            this.retransmitTimeout = null;
        }

        System.arraycopy(decoded.buf, decoded.off, buf, off, decoded.len);
        return decoded.len;
    }

    private int receiveRecord(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        if (recordQueue.available() > 0)
        {
            int length = 0;
            if (recordQueue.available() >= RECORD_HEADER_LENGTH)
            {
                byte[] lengthBytes = new byte[2];
                recordQueue.read(lengthBytes, 0, 2, 11);
                length = TlsUtils.readUint16(lengthBytes, 0);
            }

            int received = Math.min(recordQueue.available(), RECORD_HEADER_LENGTH + length);
            recordQueue.removeData(buf, off, received, 0);
            return received;
        }

        int received = receiveDatagram(buf, off, len, waitMillis);
        if (received >= RECORD_HEADER_LENGTH)
        {
            this.inConnection = true;

            int fragmentLength = TlsUtils.readUint16(buf, off + 11);
            int recordLength = RECORD_HEADER_LENGTH + fragmentLength;
            if (received > recordLength)
            {
                recordQueue.addData(buf, off + recordLength, received - recordLength);
                received = recordLength;
            }
        }

        return received;
    }

    private void resetHeartbeat()
    {
        this.heartbeatInFlight = null;
        this.heartbeatResendMillis = -1;
        this.heartbeatResendTimeout = null;
        this.heartbeatTimeout = new Timeout(heartbeat.getIdleMillis());
    }

    private void sendHeartbeatMessage(HeartbeatMessage heartbeatMessage)
        throws IOException
    {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        heartbeatMessage.encode(output);
        byte[] buf = output.toByteArray();

        sendRecord(ContentType.heartbeat, buf, 0, buf.length);
    }

    /*
     * Currently uses synchronization to ensure heartbeat sends and application data sends don't
     * interfere with each other. It may be overly cautious; the sequence number allocation is
     * atomic, and if we synchronize only on the datagram send instead, then the only effect should
     * be possible reordering of records (which might surprise a reliable transport implementation).
     */
    private void sendRecord(short contentType, byte[] buf, int off, int len) throws IOException
    {
        // Never send anything until a valid ClientHello has been received
        if (writeVersion == null)
        {
            return;
        }

        if (len > this.plaintextLimit)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /*
         * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
         * or ChangeCipherSpec content types.
         */
        if (len < 1 && contentType != ContentType.application_data)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        synchronized (writeLock)
        {
            int recordEpoch = writeEpoch.getEpoch();
            long recordSequenceNumber = writeEpoch.allocateSequenceNumber();
            long macSequenceNumber = getMacSequenceNumber(recordEpoch, recordSequenceNumber);
            ProtocolVersion recordVersion = writeVersion;

            TlsEncodeResult encoded = writeEpoch.getCipher().encodePlaintext(macSequenceNumber, contentType,
                recordVersion, RECORD_HEADER_LENGTH, buf, off, len);

            int ciphertextLength = encoded.len - RECORD_HEADER_LENGTH;
            TlsUtils.checkUint16(ciphertextLength);

            TlsUtils.writeUint8(encoded.recordType, encoded.buf, encoded.off + 0);
            TlsUtils.writeVersion(recordVersion, encoded.buf, encoded.off + 1);
            TlsUtils.writeUint16(recordEpoch, encoded.buf, encoded.off + 3);
            TlsUtils.writeUint48(recordSequenceNumber, encoded.buf, encoded.off + 5);
            TlsUtils.writeUint16(ciphertextLength, encoded.buf, encoded.off + 11);

            sendDatagram(transport, encoded.buf, encoded.off, encoded.len);
        }
    }

    private static long getMacSequenceNumber(int epoch, long sequence_number)
    {
        return ((epoch & 0xFFFFFFFFL) << 48) | sequence_number;
    }
}
