package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDTLS13Cipher;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsNullNullCipher;
import org.bouncycastle.util.Arrays;

class DTLSRecordLayer
    implements DatagramTransport
{
    static final int RECORD_HEADER_LENGTH = 13;

    /**
     * RFC 9147 4. Returned by {@link #getDTLS13RecordLength(byte[], int, int)} for a record without the L bit:
     * the record runs to the end of the datagram, whose true length only the caller knows.
     */
    private static final int RECORD_LENGTH_REST_OF_DATAGRAM = -2;

    private static final int MAX_FRAGMENT_LENGTH = 1 << 14;
    private static final long TCP_MSL = 1000L * 60 * 2;
    private static final long RETRANSMIT_TIMEOUT = TCP_MSL * 2;

    static int receiveClientHelloRecord(byte[] data, int dataOff, int dataLen) throws IOException
    {
        if (dataLen < RECORD_HEADER_LENGTH)
        {
            return -1;
        }

        short contentType = TlsUtils.readUint8(data, dataOff + 0);
        if (ContentType.handshake != contentType)
        {
            return -1;
        }

        ProtocolVersion version = TlsUtils.readVersion(data, dataOff + 1);
        if (!ProtocolVersion.DTLSv10.isEqualOrEarlierVersionOf(version))
        {
            return -1;
        }

        int epoch = TlsUtils.readUint16(data, dataOff + 3);
        if (0 != epoch)
        {
            return -1;
        }

//        long sequenceNumber = TlsUtils.readUint48(data, dataOff + 5);

        int length = TlsUtils.readUint16(data, dataOff + 11);
        if (length < 1 || length > MAX_FRAGMENT_LENGTH)
        {
            return -1;
        }

        if (dataLen < RECORD_HEADER_LENGTH + length)
        {
            return -1;
        }

        short msgType = TlsUtils.readUint8(data, dataOff + RECORD_HEADER_LENGTH);
        if (HandshakeType.client_hello != msgType)
        {
            return -1;
        }

        // NOTE: We ignore/drop any data after the first record 
        return length;
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

    // github #1487. While a flight is open, records are packed into as few datagrams as the MTU allows.
    private byte[] flightBuffer = null;
    private int flightBufferPos = 0;
    private int flightSendLimit = 0;
    private boolean inFlight = false;

    private volatile boolean closed = false;
    private volatile boolean failed = false;
    // TODO[dtls13] Review the draft/RFC (legacy_record_version) to see if readVersion can be removed
    private volatile ProtocolVersion readVersion = null, writeVersion = null;
    private volatile boolean inConnection;
    // Package-private: the reliable-handshake and aggregation tests set this directly.
    volatile boolean inHandshake;
    private volatile int plaintextLimit;
    private DTLSEpoch currentEpoch, pendingEpoch;
    private DTLSEpoch readEpoch, writeEpoch;
    private int lastReceivedEpoch = -1;

    // Set once a DTLS 1.3 version has been negotiated (at initPendingEpoch); selects the RFC 9147 record format
    private volatile boolean dtls13 = false;

    private DTLSHandshakeRetransmit retransmit = null;
    private DTLSEpoch retransmitEpoch = null;
    /*
     * RFC 9147 5.8.1. DTLS 1.3 only. A DTLS 1.3 flight straddles an epoch change - the ServerHello is
     * plaintext at epoch 0 while the rest of the same flight is protected at the handshake epoch - so
     * answering a retransmission of it means being able to read the plaintext epoch too. Handshake records
     * only, exactly as for retransmitEpoch.
     *
     * Epoch 0 is unauthenticated, so anyone able to put a datagram on the path can forge a record at it, and
     * retaining it for reading would otherwise be a way to draw an answer out of a completed client. It is
     * harmless because of three separate gates, all of which have to hold for it to stay harmless:
     *
     * 1. DTLSReliableHandshake.processRecord's DTLS 1.3 'expectedEpoch' check (RFC 9147 6.1). At epoch 0
     *    only a client_hello or server_hello msg_type is accepted, so a forgery cannot stand in for anything
     *    later in the flight; on the client, which is the only side that retains epoch 0, that leaves
     *    server_hello fragments.
     * 2. DTLSReliableHandshake.processRecord only answers a retransmission once
     *    checkAll(previousInboundFlight) finds that flight complete, and the rest of that flight is
     *    protected at the handshake epoch, which cannot be forged. A plaintext-only forgery therefore never
     *    completes a flight and never draws a retransmission.
     * 3. Post-handshake, processRecord is called with a 'windowSize' of 0 (see the retransmit callback in
     *    DTLSReliableHandshake.finish), so every message_seq is 'too far ahead' and no DTLSReassembler is
     *    ever allocated: the forgery cannot make us buffer anything either.
     */
    private DTLSEpoch retransmitEpochPlaintext = null;
    private Timeout retransmitTimeout = null;

    /*
     * DTLS 1.3 only. The epoch most recently retired by commitPendingEpochIfCurrent, kept so that
     * handshakeSuccessful can retain the handshake epoch (RFC 9147 5.8.1): once both directions have moved to
     * the application epoch, nothing else holds a reference to the handshake epoch's keys or replay window.
     * Cleared by handshakeSuccessful, which hands it to retransmitEpoch (or drops it), so that the retention
     * really does end when the retransmit timeout expires.
     */
    private DTLSEpoch retiredEpoch = null;

    // The epoch 0 (unprotected) epoch, which is never replaced; see retransmitEpochPlaintext
    private final DTLSEpoch plaintextEpoch;

    private DTLSAckListener ackListener = null;

    /*
     * RFC 9147 7.1. The record number of the most recently accepted handshake record. It is assigned only
     * for records whose decoded content type is handshake, which is its only consumer: the reliable
     * handshake reads it after a receive, and assigning it for alerts, ACKs or application data would
     * leave it pointing at a record the handshake never saw.
     */
    private DTLSRecordNumber lastReceivedRecordNumber = null;

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

        this.currentEpoch = new DTLSEpoch(0, TlsNullNullCipher.INSTANCE, RECORD_HEADER_LENGTH, RECORD_HEADER_LENGTH);        
        this.plaintextEpoch = currentEpoch;
        this.pendingEpoch = null;
        this.readEpoch = currentEpoch;
        this.writeEpoch = currentEpoch;

        setPlaintextLimit(MAX_FRAGMENT_LENGTH);
    }

    boolean isClosed()
    {
        return closed;
    }

    boolean isFailed()
    {
        return failed;
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

    /**
     * The epoch of the record most recently delivered by a receive call.
     * <p>
     * During the handshake this can differ from {@link #getReadEpoch()}: a handshake record from the current epoch
     * is still delivered after the peer's ChangeCipherSpec has moved the read epoch on (a message that was lost and
     * later retransmitted, while the ChangeCipherSpec and Finished that followed it arrived).
     */
    int getLastReceivedEpoch()
    {
        return lastReceivedEpoch;
    }

    /**
     * @return the record number of the most recently accepted handshake record, or null if none. Used by
     *         the reliable handshake to build ACKs (RFC 9147 7.1).
     */
    DTLSRecordNumber getLastReceivedRecordNumber()
    {
        return lastReceivedRecordNumber;
    }

    /**
     * @return true once a DTLS 1.3 version has been negotiated and the record layer has switched to the
     *         RFC 9147 record format.
     */
    boolean isDTLS13()
    {
        return dtls13;
    }

    /** The pending epoch number, or -1 when there is no pending epoch. */
    int getPendingEpoch()
    {
        return null == pendingEpoch ? -1 : pendingEpoch.getEpoch();
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

        SecurityParameters securityParameters = context.getSecurityParameters();
        byte[] connectionIDLocal = securityParameters.getConnectionIDLocal();
        byte[] connectionIDPeer = securityParameters.getConnectionIDPeer();
        int connectionIDLocalLength = connectionIDLocal != null ? connectionIDLocal.length : 0;
        int connectionIDPeerLength = connectionIDPeer != null ? connectionIDPeer.length : 0;

        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        boolean nextDtls13 = null != negotiatedVersion && TlsUtils.isTLSv13(negotiatedVersion);

        int nextEpoch;
        int recordHeaderLengthRead, recordHeaderLengthWrite;
        if (nextDtls13)
        {
            /*
             * RFC 9147 6.1. Epoch 1 is reserved for early data (not supported), so the first protected epoch
             * (handshake traffic keys) is 2 and application traffic keys begin at 3.
             */
            if (!(pendingCipher instanceof TlsDTLS13Cipher))
            {
                throw new IllegalStateException("DTLS 1.3 requires a TlsDTLS13Cipher");
            }

            nextEpoch = writeEpoch.getEpoch() == 0 ? 2 : writeEpoch.getEpoch() + 1;
            // NOTE: A peer may send the compact header form, so the read side must budget for its minimum
            recordHeaderLengthRead = DTLS13UnifiedHeader.getMinReadHeaderLength(connectionIDPeerLength);
            recordHeaderLengthWrite = DTLS13UnifiedHeader.getWriteHeaderLength(connectionIDLocalLength);
        }
        else
        {
            // TODO Check for overflow
            nextEpoch = writeEpoch.getEpoch() + 1;
            recordHeaderLengthRead = RECORD_HEADER_LENGTH + connectionIDPeerLength;
            recordHeaderLengthWrite = RECORD_HEADER_LENGTH + connectionIDLocalLength;
        }

        this.dtls13 = nextDtls13;
        this.pendingEpoch = new DTLSEpoch(nextEpoch, pendingCipher, recordHeaderLengthRead, recordHeaderLengthWrite);
    }

    /**
     * DTLS 1.3: switch the read direction to the pending epoch. Once both directions use the pending epoch it
     * becomes the current epoch and the pending slot is cleared.
     */
    void enablePendingEpochRead()
    {
        if (null == pendingEpoch)
        {
            throw new IllegalStateException();
        }

        this.readEpoch = pendingEpoch;
        commitPendingEpochIfCurrent();
    }

    /**
     * DTLS 1.3: switch the write direction to the pending epoch (see {@link #enablePendingEpochRead()}).
     */
    void enablePendingEpochWrite()
    {
        if (null == pendingEpoch)
        {
            throw new IllegalStateException();
        }

        this.writeEpoch = pendingEpoch;
        commitPendingEpochIfCurrent();
    }

    private void commitPendingEpochIfCurrent()
    {
        if (readEpoch == pendingEpoch && writeEpoch == pendingEpoch)
        {
            /*
             * DTLS 1.2 never reads 'retiredEpoch': handshakeSuccessful retains 'currentEpoch' there, because
             * in DTLS 1.2 the epoch being superseded is still the current one at that point. Assigning it
             * only for DTLS 1.3 keeps the DTLS 1.2 path's state untouched by this field.
             *
             * TODO[dtls13] This holds only the MOST RECENT retired epoch, which is all RFC 9147 5.8.1 needs
             * while the only epoch change after the handshake epoch is the one to the application epoch. Once
             * post-handshake key update (RFC 9147 8) lands, several epochs can be retired in succession and
             * which of them is still readable becomes load-bearing.
             */
            if (dtls13)
            {
                this.retiredEpoch = currentEpoch;
            }

            this.currentEpoch = pendingEpoch;
            this.pendingEpoch = null;
        }
    }

    /**
     * RFC 9147 5.8.1. DTLS 1.3 only: the epoch that {@link #handshakeSuccessful(DTLSHandshakeRetransmit)} is
     * about to retain for reading, i.e. the handshake epoch the peer's final flight was protected under, or
     * -1 if no epoch has been retired. Read by {@link DTLSReliableHandshake#finish()}, so that the epoch a
     * retransmission of that flight has to arrive at is taken from the record layer rather than assumed.
     */
    int getRetiredEpoch()
    {
        return (null != retiredEpoch) ? retiredEpoch.getEpoch() : -1;
    }

    void handshakeSuccessful(DTLSHandshakeRetransmit retransmit)
    {
        if (!dtls13 && (readEpoch == currentEpoch || writeEpoch == currentEpoch))
        {
            // TODO
            throw new IllegalStateException();
        }

        /*
         * RFC 6347 4.2.4 and RFC 9147 5.8.1. For at least twice the default MSL, a peer that is still
         * retransmitting the flight we have just accepted must get an answer, so the epoch that flight was
         * protected under is retained for reading. In DTLS 1.2 that epoch is the one being superseded, which
         * is still the current epoch here; in DTLS 1.3 both directions have already moved on to the
         * application epoch, so it is the epoch commitPendingEpochIfCurrent retired.
         *
         * NOTE: Retaining it never moves the write epoch. resetWriteEpoch is DTLS 1.2 only, and
         * sendReturningRecordNumber's handshake classification is likewise gated, so DTLS 1.3 application
         * data continues to be written at the application epoch as application_data. The answer itself goes
         * out through sendHandshakeRecordAtEpoch (a retransmitted flight) or sendAck (a retransmitted ACK).
         */
        DTLSEpoch epochToRetain = dtls13 ? retiredEpoch : currentEpoch;

        /*
         * Nothing else reads the retired epoch after this point: a retransmission of our own flight resolves
         * its epoch through retransmitEpoch below, so holding a second reference here would keep the handshake
         * traffic keys and replay window alive for the whole connection instead of for the retransmit timeout.
         */
        this.retiredEpoch = null;

        if (null != retransmit && null != epochToRetain)
        {
            this.retransmit = retransmit;
            this.retransmitEpoch = epochToRetain;

            /*
             * Epoch 0 is unauthenticated, so it is retained only by the side that has a reason to read it,
             * which is the client. In DTLS 1.3 the client sends the last flight, so (see
             * DTLSReliableHandshake.finish) the client answers a retransmission by re-sending its own flight
             * while the server answers one with another ACK. The flight the client answers - the server's - is
             * the one that straddles the epoch change, with the ServerHello plaintext at epoch 0 and the rest
             * protected at the handshake epoch, so the client must be able to read epoch 0 to recognise it.
             * The client's final flight, which is what the server answers, is protected in its entirety at the
             * handshake epoch and contains no epoch-0 record, so the server never needs epoch 0 - and
             * retaining it there would let anyone able to put a datagram on the path draw an answer out of a
             * completed server with an unauthenticated record.
             */
            this.retransmitEpochPlaintext = (dtls13 && !context.isServer()) ? plaintextEpoch : null;
            this.retransmitTimeout = new Timeout(RETRANSMIT_TIMEOUT);
        }

        this.inHandshake = false;
        if (null != pendingEpoch)
        {
            this.currentEpoch = pendingEpoch;
            this.pendingEpoch = null;
        }
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
        int ciphertextLimit = transport.getReceiveLimit() - readEpoch.getRecordHeaderLengthRead();
        TlsCipher cipher = readEpoch.getCipher();

        int plaintextDecodeLimit = cipher.getPlaintextDecodeLimit(ciphertextLimit);

        return Math.min(plaintextLimit, plaintextDecodeLimit);
    }

    public int getSendLimit()
        throws IOException
    {
        TlsCipher cipher = writeEpoch.getCipher();
        int ciphertextLimit = transport.getSendLimit() - writeEpoch.getRecordHeaderLengthWrite();

        int plaintextEncodeLimit = cipher.getPlaintextEncodeLimit(ciphertextLimit);

        return Math.min(plaintextLimit, plaintextEncodeLimit);        
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        return receive(buf, off, len, waitMillis, null);
    }

    /**
     * A waitMillis of zero is interpreted as an infinite timeout.
     */
    int receive(byte[] buf, int off, int len, int waitMillis, DTLSRecordCallback recordCallback)
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
                retransmitEpochPlaintext = null;
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

                this.heartbeatResendMillis = peer.getHandshakeResendTimeMillis();
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

            int receiveLimit = transport.getReceiveLimit();            
            if (null == record || record.length < receiveLimit)
            {
                record = new byte[receiveLimit];
            }

            int received = receiveRecord(record, 0, receiveLimit, waitMillis);
            int processed = processRecord(received, record, buf, off, len, recordCallback);            
            if (processed >= 0)
            {
                return processed;
            }

            currentTimeMillis = System.currentTimeMillis();
            waitMillis = Timeout.getWaitMillis(timeout, currentTimeMillis);
        }

        return -1;
    }

    int receivePending(byte[] buf, int off, int len, DTLSRecordCallback recordCallback)
        throws IOException
    {
        if (recordQueue.available() > 0)
        {
            int receiveLimit = recordQueue.available();
            byte[] record = new byte[receiveLimit];

            do
            {
                int received = receivePendingRecord(record, 0, receiveLimit);
                int processed = processRecord(received, record, buf, off, len, recordCallback);
                if (processed >= 0)
                {
                    return processed;
                }
            }
            while (recordQueue.available() > 0);
        }

        return -1;
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        sendReturningRecordNumber(buf, off, len);
    }

    /**
     * As {@link #send(byte[], int, int)}, but reports the record number the data was sent in, which the
     * reliable handshake needs to map handshake fragments to records for ACK processing (RFC 9147 7).
     *
     * @return the record number used, or null if nothing was sent.
     */
    DTLSRecordNumber sendReturningRecordNumber(byte[] buf, int off, int len)
        throws IOException
    {
        short contentType = ContentType.application_data;

        /*
         * NOTE: The retransmitEpoch test is DTLS 1.2 only. DTLS 1.3 retains the handshake epoch for reading
         * and retransmits through sendHandshakeRecordAtEpoch without ever making it the write epoch, so
         * application data must not be reclassified here on its account.
         */
        if (this.inHandshake || (!dtls13 && this.writeEpoch == this.retransmitEpoch))
        {
            contentType = ContentType.handshake;

            short handshakeType = TlsUtils.readUint8(buf, off);
            if (handshakeType == HandshakeType.finished && !dtls13)
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

        return sendRecord(contentType, buf, off, len);
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
            synchronized (writeLock)
            {
                /*
                 * github #1487. Unlike closeTransport, discard the buffered flight rather than flushing it:
                 * a fatal alert follows, so the flight is abandoned and transmitting its records ahead of
                 * the alert has no upside.
                 */
                inFlight = false;
                flightBufferPos = 0;
            }

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
            synchronized (writeLock)
            {
                /*
                 * github #1487. A graceful close should not have anything buffered, but if it does the
                 * flight was not abandoned, so flush it. Contrast fail(), which discards it.
                 */
                try
                {
                    flushFlightBuffer();
                }
                catch (Exception e)
                {
                    // Ignore: we are tearing down
                }
                inFlight = false;
                flightBufferPos = 0;
            }

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
            // NOTE: the buffer is sized to support transport.getReceiveLimit().
            int received = transport.receive(buf, off, len, waitMillis);

            // Check the transport returned a sensible value, otherwise discard the datagram.
            if (received <= len)
            {
                return received;
            }
        }
        catch (SocketTimeoutException e)
        {
        }
        catch (InterruptedIOException e)
        {
            e.bytesTransferred = 0;
            throw e;
        }

        return -1;
    }

    // TODO Include 'currentTimeMillis' as an argument, use with Timeout, resetHeartbeat
    private int processRecord(int received, byte[] record, byte[] buf, int off, int len,
        DTLSRecordCallback recordCallback)    
        throws IOException
    {
        // NOTE: received < 0 (timeout) is covered by this first case
        if (received < 1)
        {
            return -1;
        }

        if (dtls13 && DTLS13UnifiedHeader.isCiphertextRecord(record[0] & 0xFF))
        {
            return processDTLS13Record(received, record, buf, off, len, recordCallback);
        }

        if (received < RECORD_HEADER_LENGTH)
        {
            return -1;
        }

        short recordType = TlsUtils.readUint8(record, 0);

        switch (recordType)
        {
        case ContentType.alert:
        case ContentType.application_data:
        case ContentType.change_cipher_spec:
        case ContentType.handshake:
        case ContentType.heartbeat:
        case ContentType.tls12_cid:
            break;
        default:
            return -1;
        }

        ProtocolVersion recordVersion = TlsUtils.readVersion(record, 1);
        if (!recordVersion.isDTLS())
        {
            return -1;
        }

        int epoch = TlsUtils.readUint16(record, 3);

        DTLSEpoch recordEpoch = null;
        if (epoch == readEpoch.getEpoch())
        {
            recordEpoch = readEpoch;
        }
        else if (null != retransmitEpoch && epoch == retransmitEpoch.getEpoch())
        {
            if (recordType == ContentType.handshake)
            {
                recordEpoch = retransmitEpoch;
            }
        }
        else if (inHandshake && epoch == currentEpoch.getEpoch())
        {
            /*
             * The peer's ChangeCipherSpec has moved the read epoch on, but a handshake message from before it
             * (e.g. CertificateVerify) may have been lost and is now being retransmitted. Until the handshake
             * completes, handshake records from the current epoch are still accepted.
             */
            if (recordType == ContentType.handshake)
            {
                recordEpoch = currentEpoch;
            }
        }
        else if (null != retransmitEpochPlaintext && epoch == retransmitEpochPlaintext.getEpoch())
        {
            if (recordType == ContentType.handshake)
            {
                recordEpoch = retransmitEpochPlaintext;
            }
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

        int recordHeaderLength = recordEpoch.getRecordHeaderLengthRead();
        if (recordHeaderLength > RECORD_HEADER_LENGTH)
        {
            if (ContentType.tls12_cid != recordType)
            {
                return -1;
            }

            if (received < recordHeaderLength)
            {
                return -1;
            }

            byte[] connectionID = context.getSecurityParameters().getConnectionIDPeer();
            if (!Arrays.constantTimeAreEqual(connectionID.length, connectionID, 0, record, 11))
            {
                return -1;
            }
        }
        else
        {
            if (ContentType.tls12_cid == recordType)
            {
                return -1;
            }
        }

        int length = TlsUtils.readUint16(record, recordHeaderLength - 2);
        if (received != (length + recordHeaderLength))
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
                &&  HandshakeType.client_hello == TlsUtils.readUint8(record, recordHeaderLength);

            if (!isClientHelloFragment)
            {
                return -1;
            }
        }

        long macSeqNo = getMacSequenceNumber(recordEpoch.getEpoch(), seq);

        TlsDecodeResult decoded;
        try
        {
            decoded = recordEpoch.getCipher().decodeCiphertext(macSeqNo, recordType, recordVersion, record,
                recordHeaderLength, length);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            /*
             * RFC 9147 4.5.2. Unlike TLS, DTLS is resilient in the face of invalid records (e.g., invalid
             * formatting, length, MAC, etc.). In general, invalid records SHOULD be silently discarded, thus
             * preserving the association [...] generating fatal alerts is NOT RECOMMENDED for such transports,
             * both to increase the reliability of DTLS service and to avoid the risk of spoofing attacks sending
             * traffic to unrelated third parties.
             *
             * RFC 9146 6. DTLS implementations MUST silently discard records with bad MACs or that are otherwise
             * invalid.
             *
             * An internal_error is not a verdict on the record: it means the implementation itself has hit
             * something it did not anticipate, so it is not safe to proceed and the alert is propagated.
             */
            if (AlertDescription.internal_error == fatalAlert.getAlertDescription())
            {
                throw fatalAlert;
            }

            return -1;
        }

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
                &&  HandshakeType.hello_verify_request == TlsUtils.readUint8(record, recordHeaderLength);

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

        boolean isLatestConfirmed = recordEpoch.getReplayWindow().reportAuthenticated(seq);

        /*
         * NOTE: The record has passed record layer validation and will be dispatched according to the decoded
         * content type.
         */
        if (recordCallback != null)
        {
            int flags = DTLSRecordFlags.NONE;

            if (recordEpoch == readEpoch && isLatestConfirmed)
            {
                flags |= DTLSRecordFlags.IS_NEWEST;
            }

            if (ContentType.tls12_cid == recordType)
            {
                flags |= DTLSRecordFlags.USES_CONNECTION_ID;
            }

            recordCallback.recordAccepted(flags);
        }

        if (ContentType.handshake == decoded.contentType)
        {
            this.lastReceivedRecordNumber = new DTLSRecordNumber(epoch, seq);
        }

        return processDecodedRecord(decoded, epoch, buf, off, len);
    }

    private int processDecodedRecord(TlsDecodeResult decoded, int epoch, byte[] buf, int off, int len)
        throws IOException
    {
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
                    throw new TlsFatalAlertReceived(alertDescription);
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

                // RFC 9147 5. DTLS 1.3 does not use the TLS 1.3 compatibility-mode change_cipher_spec
                if (!dtls13 && pendingEpoch != null)
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
        case ContentType.ack:
        {
            /*
             * RFC 9147 7. ACK is not a handshake message and never reaches the application; it is
             * delivered to the handshake, which uses it to retire acknowledged fragments. A malformed
             * body is discarded like any other invalid record (RFC 9147 4.5.2).
             */
            if (null != ackListener)
            {
                Vector recordNumbers = DTLSAck.decode(decoded.buf, decoded.off, decoded.len);
                if (null != recordNumbers)
                {
                    ackListener.receivedAck(filterAckRecordNumbers(recordNumbers, epoch));
                }
            }

            return -1;
        }
        case ContentType.tls12_cid:
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
            this.retransmitEpochPlaintext = null;
            this.retransmitTimeout = null;
        }

        this.lastReceivedEpoch = epoch;

        // NOTE: Internal error implies getReceiveLimit() was not used to allocate result space
        if (decoded.len > len)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        System.arraycopy(decoded.buf, decoded.off, buf, off, decoded.len);
        return decoded.len;
    }

    /**
     * RFC 9147 4. Process a DTLSCiphertext record (unified header). Invalid records are silently discarded
     * (RFC 9147 4.5.2), with the same internal_error exception as the legacy path.
     */
    private int processDTLS13Record(int received, byte[] record, byte[] buf, int off, int len,
        DTLSRecordCallback recordCallback) throws IOException
    {
        int firstByte = record[0] & 0xFF;

        byte[] connectionID = context.getSecurityParameters().getConnectionIDPeer();
        int connectionIDLength = null == connectionID ? 0 : connectionID.length;

        // NOTE: Establish that the whole header is present before reading any of it
        int headerLength = DTLS13UnifiedHeader.getHeaderLength(firstByte, connectionIDLength);
        if (received < headerLength + DTLS13UnifiedHeader.MIN_CIPHERTEXT_LENGTH)
        {
            return -1;
        }

        if (DTLS13UnifiedHeader.hasConnectionID(firstByte))
        {
            if (connectionIDLength == 0
                || !Arrays.constantTimeAreEqual(connectionIDLength, connectionID, 0, record, 1))
            {
                return -1;
            }
        }
        else if (connectionIDLength != 0)
        {
            return -1;
        }

        int ciphertextLength;
        if (DTLS13UnifiedHeader.hasLength(firstByte))
        {
            ciphertextLength = TlsUtils.readUint16(record, headerLength - 2);
            if (received != headerLength + ciphertextLength)
            {
                return -1;
            }
        }
        else
        {
            ciphertextLength = received - headerLength;
        }
        if (ciphertextLength < DTLS13UnifiedHeader.MIN_CIPHERTEXT_LENGTH)
        {
            return -1;
        }

        /*
         * NOTE: Only the low 2 epoch bits are on the wire, so a record can only be attributed to an epoch the
         * record layer still holds: the read epoch, or the handshake epoch retained by handshakeSuccessful for
         * RFC 9147 5.8.1.
         */
        DTLSEpoch recordEpoch = null;
        if (DTLS13UnifiedHeader.matchesEpoch(firstByte, readEpoch.getEpoch()))
        {
            recordEpoch = readEpoch;
        }
        else if (null != retransmitEpoch && DTLS13UnifiedHeader.matchesEpoch(firstByte, retransmitEpoch.getEpoch()))
        {
            recordEpoch = retransmitEpoch;
        }
        if (null == recordEpoch)
        {
            return -1;
        }

        TlsCipher recordCipher = recordEpoch.getCipher();
        if (!(recordCipher instanceof TlsDTLS13Cipher))
        {
            // A DTLSCiphertext record can only belong to a protected epoch; epoch 0 uses the null cipher.
            return -1;
        }
        TlsDTLS13Cipher cipher = (TlsDTLS13Cipher)recordCipher;
        DTLSReplayWindow replayWindow = recordEpoch.getReplayWindow();

        TlsDecodeResult decoded;
        long seq;
        try
        {
            cipher.decryptDTLS13RecordNumber(record, 0, received);

            int seqNumOff = 1 + connectionIDLength;
            int seqBitCount = DTLS13UnifiedHeader.hasSeq16(firstByte) ? 16 : 8;
            int seqBits = seqBitCount == 16 ? TlsUtils.readUint16(record, seqNumOff)
                : TlsUtils.readUint8(record, seqNumOff);

            long expected = replayWindow.getLatestConfirmedSeq() + 1;
            seq = DTLS13UnifiedHeader.reconstructSequenceNumber(expected, seqBits, seqBitCount);
            if (replayWindow.shouldDiscard(seq))
            {
                return -1;
            }

            decoded = cipher.decodeDTLS13Ciphertext(seq, record, 0, headerLength, ciphertextLength);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            // See processRecord: only an internal_error is propagated
            if (AlertDescription.internal_error == fatalAlert.getAlertDescription())
            {
                throw fatalAlert;
            }

            return -1;
        }

        if (decoded.len > this.plaintextLimit)
        {
            return -1;
        }
        if (decoded.len < 1 && decoded.contentType != ContentType.application_data)
        {
            return -1;
        }

        boolean isLatestConfirmed = replayWindow.reportAuthenticated(seq);

        if (recordCallback != null)
        {
            int flags = DTLSRecordFlags.NONE;

            if (recordEpoch == readEpoch && isLatestConfirmed)
            {
                flags |= DTLSRecordFlags.IS_NEWEST;
            }

            if (DTLS13UnifiedHeader.hasConnectionID(firstByte))
            {
                flags |= DTLSRecordFlags.USES_CONNECTION_ID;
            }

            recordCallback.recordAccepted(flags);
        }

        if (ContentType.handshake == decoded.contentType)
        {
            this.lastReceivedRecordNumber = new DTLSRecordNumber(recordEpoch.getEpoch(), seq);
        }

        return processDecodedRecord(decoded, recordEpoch.getEpoch(), buf, off, len);
    }

    /**
     * RFC 9147 7. An ACK is sent at an epoch equal to or higher than the records it acknowledges, so a
     * record number naming an epoch above the one that carried the ACK is discarded.
     * <p>
     * Without this an off-path attacker who can spoof the peer's address has a blind denial of service:
     * epoch 0 is unauthenticated (a fragmented ClientHello has to be acknowledgeable there) and DTLS
     * sequence numbers start at 0 and are predictable, so a forged plaintext ACK listing the protected
     * epochs would retire handshake fragments that were never delivered. Retransmission then writes
     * nothing and the handshake stalls until it times out.
     * </p>
     * An ACK all of whose record numbers are filtered out is still delivered: an empty ACK is meaningful.
     */
    private static Vector filterAckRecordNumbers(Vector recordNumbers, int epoch)
    {
        Vector result = new Vector(recordNumbers.size());
        for (int i = 0; i < recordNumbers.size(); ++i)
        {
            DTLSRecordNumber recordNumber = (DTLSRecordNumber)recordNumbers.elementAt(i);
            /*
             * A forged epoch at or above 2^63 decodes to a negative long, which would otherwise slip past
             * an upper-bound-only test; require a real epoch so the filter's invariant holds exactly.
             */
            if (recordNumber.getEpoch() >= 0 && recordNumber.getEpoch() <= epoch)
            {
                result.addElement(recordNumber);
            }
        }
        return result;
    }

    private int receivePendingRecord(byte[] buf, int off, int len)
        throws IOException
    {
//        assert recordQueue.available() > 0;

        int recordLength = RECORD_HEADER_LENGTH;

        byte[] firstByteBuf = new byte[1];
        recordQueue.read(firstByteBuf, 0, 1, 0);
        int firstByte = firstByteBuf[0] & 0xFF;

        if (dtls13 && DTLS13UnifiedHeader.isCiphertextRecord(firstByte))
        {
            int available = recordQueue.available();
            byte[] head = new byte[Math.min(available, 16)];
            recordQueue.read(head, 0, head.length, 0);

            recordLength = getDTLS13RecordLength(head, 0, head.length);
            if (RECORD_LENGTH_REST_OF_DATAGRAM == recordLength)
            {
                recordLength = available;
            }
            else if (recordLength < 0)
            {
                recordQueue.removeData(available);
                return -1;
            }
        }
        else if (recordQueue.available() >= recordLength)
        {
            int epoch = recordQueue.readUint16(3);

            DTLSEpoch recordEpoch = null;
            if (epoch == readEpoch.getEpoch())
            {
                recordEpoch = readEpoch;
            }
            else if (null != retransmitEpoch && epoch == retransmitEpoch.getEpoch())
            {
                recordEpoch = retransmitEpoch;
            }
            else if (inHandshake && epoch == currentEpoch.getEpoch())
            {
                recordEpoch = currentEpoch;
            }
            else if (null != retransmitEpochPlaintext && epoch == retransmitEpochPlaintext.getEpoch())
            {
                recordEpoch = retransmitEpochPlaintext;
            }

            if (null == recordEpoch)
            {
                recordQueue.removeData(recordQueue.available());
                return -1;
            }

            recordLength = recordEpoch.getRecordHeaderLengthRead();
            if (recordQueue.available() >= recordLength)
            {
                int fragmentLength = recordQueue.readUint16(recordLength - 2);
                recordLength += fragmentLength;
            }
        }

        int received = Math.min(recordQueue.available(), recordLength);
        recordQueue.removeData(buf, off, received, 0);
        return received;
    }

    /**
     * RFC 9147 4. Length of the DTLS 1.3 ciphertext record at the start of buf[off..off + available), or -1 if
     * it cannot be determined. A record without the L bit consumes the rest of the datagram, which is reported
     * as {@link #RECORD_LENGTH_REST_OF_DATAGRAM} because 'available' may be only a peek window rather than the
     * true remaining length; the caller substitutes the length it knows.
     */
    private int getDTLS13RecordLength(byte[] buf, int off, int available)
    {
        int firstByte = buf[off] & 0xFF;

        byte[] connectionID = context.getSecurityParameters().getConnectionIDPeer();
        int connectionIDLength = null == connectionID ? 0 : connectionID.length;

        int headerLength = DTLS13UnifiedHeader.getHeaderLength(firstByte, connectionIDLength);
        if (available < headerLength)
        {
            return -1;
        }
        if (!DTLS13UnifiedHeader.hasLength(firstByte))
        {
            return RECORD_LENGTH_REST_OF_DATAGRAM;
        }
        return headerLength + TlsUtils.readUint16(buf, off + headerLength - 2);
    }

    private int receiveRecord(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        if (recordQueue.available() > 0)
        {
            return receivePendingRecord(buf, off, len);
        }

        int received = receiveDatagram(buf, off, len, waitMillis);

        if (dtls13 && received >= 1 && DTLS13UnifiedHeader.isCiphertextRecord(buf[off] & 0xFF))
        {
            this.inConnection = true;

            int recordLength = getDTLS13RecordLength(buf, off, received);
            if (RECORD_LENGTH_REST_OF_DATAGRAM == recordLength)
            {
                recordLength = received;
            }
            else if (recordLength < 0)
            {
                return -1;
            }
            if (received > recordLength)
            {
                recordQueue.addData(buf, off + recordLength, received - recordLength);
                received = recordLength;
            }
            return received;
        }

        if (received >= RECORD_HEADER_LENGTH)
        {
            this.inConnection = true;

            int epoch = TlsUtils.readUint16(buf, off + 3);

            DTLSEpoch recordEpoch = null;
            if (epoch == readEpoch.getEpoch())
            {
                recordEpoch = readEpoch;
            }
            else if (null != retransmitEpoch && epoch == retransmitEpoch.getEpoch())
            {
                recordEpoch = retransmitEpoch;
            }
            else if (inHandshake && epoch == currentEpoch.getEpoch())
            {
                recordEpoch = currentEpoch;
            }
            else if (null != retransmitEpochPlaintext && epoch == retransmitEpochPlaintext.getEpoch())
            {
                recordEpoch = retransmitEpochPlaintext;
            }

            if (null == recordEpoch)
            {
                return -1;
            }

            int recordHeaderLength = recordEpoch.getRecordHeaderLengthRead();
            if (received >= recordHeaderLength)
            {
                int fragmentLength = TlsUtils.readUint16(buf, off + recordHeaderLength - 2);
                int recordLength = recordHeaderLength + fragmentLength;
                if (received > recordLength)
                {
                    recordQueue.addData(buf, off + recordLength, received - recordLength);
                    received = recordLength;
                }
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
    void setAckListener(DTLSAckListener ackListener)
    {
        this.ackListener = ackListener;
    }

    /**
     * RFC 9147 7. Send an ACK covering the given record numbers.
     * <p>
     * An ACK must be sent at an epoch equal to or higher than the records it acknowledges. The read and
     * write epochs advance through separate calls in DTLS 1.3, so the write epoch is checked against the
     * highest epoch named rather than assumed to be above it; if it is below, no ACK is sent. Emitting one
     * anyway would both violate that requirement and hand the record numbers of protected records to a
     * passive observer. The only cost of not sending it is a retransmission.
     * </p>
     *
     * @return the record number the ACK was sent in, or null if no ACK was sent.
     */
    DTLSRecordNumber sendAck(Vector recordNumbers) throws IOException
    {
        if (!dtls13)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        long maxEpoch = 0;
        for (int i = 0; i < recordNumbers.size(); ++i)
        {
            long recordEpoch = ((DTLSRecordNumber)recordNumbers.elementAt(i)).getEpoch();
            if (recordEpoch > maxEpoch)
            {
                maxEpoch = recordEpoch;
            }
        }

        if (writeEpoch.getEpoch() < maxEpoch)
        {
            return null;
        }

        byte[] body = DTLSAck.encode(recordNumbers);
        return sendRecord(ContentType.ack, body, 0, body.length);
    }

    DTLSRecordNumber sendRecordForTest(short contentType, byte[] buf, int off, int len) throws IOException
    {
        return sendRecord(contentType, buf, off, len);
    }

    /**
     * RFC 9147 5.8.1. DTLS 1.3 only: retransmit a handshake record under the epoch it was first sent at, rather
     * than under the current write epoch. A DTLS 1.3 flight straddles an epoch change - the ServerHello is
     * plaintext at epoch 0 while the rest of the server's flight is protected at the handshake epoch - and a
     * peer discards a handshake message that arrives at the wrong epoch (RFC 9147 6.1). After the handshake
     * has completed, our own last flight must likewise still go out at the handshake epoch, which is the only
     * epoch a peer that is still retransmitting can read.
     * <p>
     * The write epoch is never changed by this, so application data continues at the application epoch.
     *
     * @return the record number used, never null.
     * @throws TlsFatalAlert if the record cannot be written at that epoch - because the connection is not DTLS
     *             1.3, because the epoch is no longer held, or because the record layer has no write version
     *             yet. Each of those would silently truncate the retransmitted flight into one the peer can
     *             never answer, leaving only a handshake timeout to diagnose it, so it is raised here instead.
     */
    DTLSRecordNumber sendHandshakeRecordAtEpoch(int epoch, byte[] buf, int off, int len) throws IOException
    {
        DTLSEpoch recordEpoch = getEpochForRetransmit(epoch);

        if (!dtls13 || null == recordEpoch)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        DTLSRecordNumber recordNumber = sendRecord(recordEpoch, ContentType.handshake, buf, off, len);

        if (null == recordNumber)
        {
            // NOTE: sendRecord only declines a record before a write version is known, i.e. before ClientHello
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return recordNumber;
    }

    private DTLSEpoch getEpochForRetransmit(int epoch)
    {
        if (epoch < 0)
        {
            return null;
        }
        if (writeEpoch.getEpoch() == epoch)
        {
            return writeEpoch;
        }
        if (readEpoch.getEpoch() == epoch)
        {
            return readEpoch;
        }
        if (currentEpoch.getEpoch() == epoch)
        {
            return currentEpoch;
        }
        if (null != retransmitEpoch && retransmitEpoch.getEpoch() == epoch)
        {
            return retransmitEpoch;
        }
        if (null != retiredEpoch && retiredEpoch.getEpoch() == epoch)
        {
            return retiredEpoch;
        }
        if (plaintextEpoch.getEpoch() == epoch)
        {
            return plaintextEpoch;
        }
        return null;
    }

    private DTLSRecordNumber sendRecord(short contentType, byte[] buf, int off, int len) throws IOException
    {
        return sendRecord(null, contentType, buf, off, len);
    }

    private DTLSRecordNumber sendRecord(DTLSEpoch epoch, short contentType, byte[] buf, int off, int len)
        throws IOException
    {
        // Never send anything until a valid ClientHello has been received
        if (writeVersion == null)
        {
            return null;
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
            DTLSEpoch recordEpoch = null != epoch ? epoch : writeEpoch;

            if (dtls13 && recordEpoch.getEpoch() > 0)
            {
                return sendDTLS13Record(recordEpoch, contentType, buf, off, len);
            }

            int recordEpochNumber = recordEpoch.getEpoch();
            long recordSequenceNumber = recordEpoch.allocateSequenceNumber();
            long macSequenceNumber = getMacSequenceNumber(recordEpochNumber, recordSequenceNumber);
            ProtocolVersion recordVersion = writeVersion;

            int recordHeaderLength = recordEpoch.getRecordHeaderLengthWrite();

            TlsEncodeResult encoded = recordEpoch.getCipher().encodePlaintext(macSequenceNumber, contentType,
                recordVersion, recordHeaderLength, buf, off, len);

            int ciphertextLength = encoded.len - recordHeaderLength;
            TlsUtils.checkUint16(ciphertextLength);

            TlsUtils.writeUint8(encoded.recordType, encoded.buf, encoded.off + 0);
            TlsUtils.writeVersion(recordVersion, encoded.buf, encoded.off + 1);
            TlsUtils.writeUint16(recordEpochNumber, encoded.buf, encoded.off + 3);
            TlsUtils.writeUint48(recordSequenceNumber, encoded.buf, encoded.off + 5);

            if (recordHeaderLength > RECORD_HEADER_LENGTH)
            {
                byte[] connectionID = context.getSecurityParameters().getConnectionIDLocal();
                System.arraycopy(connectionID, 0, encoded.buf, encoded.off + 11, connectionID.length);
            }

            TlsUtils.writeUint16(ciphertextLength, encoded.buf, encoded.off + (recordHeaderLength - 2));

            emitRecord(contentType, encoded.buf, encoded.off, encoded.len);

            return new DTLSRecordNumber(recordEpochNumber, recordSequenceNumber);
        }
    }

    private DTLSRecordNumber sendDTLS13Record(DTLSEpoch recordEpoch, short contentType, byte[] buf, int off,
        int len) throws IOException
    {
        int recordEpochNumber = recordEpoch.getEpoch();
        long recordSequenceNumber = recordEpoch.allocateSequenceNumber();

        byte[] connectionID = context.getSecurityParameters().getConnectionIDLocal();
        int connectionIDLength = null == connectionID ? 0 : connectionID.length;

        byte[] header = new byte[DTLS13UnifiedHeader.getWriteHeaderLength(connectionIDLength)];
        int headerLength = DTLS13UnifiedHeader.writeHeader(recordEpochNumber, recordSequenceNumber, connectionID,
            header, 0);

        // NOTE: initPendingEpoch checked this for every DTLS 1.3 epoch
        TlsDTLS13Cipher cipher = (TlsDTLS13Cipher)recordEpoch.getCipher();

        TlsEncodeResult encoded = cipher.encodeDTLS13Plaintext(recordSequenceNumber, contentType, header, 0,
            headerLength, buf, off, len);

        emitRecord(contentType, encoded.buf, encoded.off, encoded.len);

        return new DTLSRecordNumber(recordEpochNumber, recordSequenceNumber);
    }

    /**
     * github #1487. Begin coalescing handshake records into datagrams. Records written until
     * {@link #endFlight()} are packed into as few datagrams as the send limit allows, rather than one
     * datagram each.
     */
    void beginFlight() throws IOException
    {
        synchronized (writeLock)
        {
            if (inFlight)
            {
                return;
            }

            int sendLimit = transport.getSendLimit();
            if (null == flightBuffer || flightBuffer.length < sendLimit)
            {
                flightBuffer = new byte[sendLimit];
            }

            flightSendLimit = sendLimit;
            flightBufferPos = 0;
            inFlight = true;
        }
    }

    /**
     * github #1487. Flush any partially filled datagram and stop coalescing.
     */
    void endFlight() throws IOException
    {
        synchronized (writeLock)
        {
            if (!inFlight)
            {
                return;
            }

            flushFlightBuffer();
            inFlight = false;
        }
    }

    /**
     * Emit one encoded record: append it to the current datagram while a flight is open and the record is
     * a handshake record, otherwise send it on its own. Caller holds 'writeLock'.
     */
    private void emitRecord(short contentType, byte[] buf, int off, int len) throws IOException
    {
        /*
         * github #1487. Only handshake records are packed: alerts must not sit in a buffer that a close
         * could discard, and heartbeat or application-data sends can race a flight under 'writeLock'.
         */
        if (!inFlight)
        {
            sendDatagram(transport, buf, off, len);
            return;
        }

        if (ContentType.handshake != contentType)
        {
            /*
             * Preserve write order: anything buffered was written before this record, so it must reach the
             * peer first. A change_cipher_spec that overtook the flight it belongs to would move the peer's
             * read epoch ahead of records it has not seen yet.
             */
            flushFlightBuffer();
            sendDatagram(transport, buf, off, len);
            return;
        }

        if (len > flightSendLimit)
        {
            // Larger than the send limit: flush what we have and let it go out alone rather than drop it
            flushFlightBuffer();
            sendDatagram(transport, buf, off, len);
            return;
        }

        if (flightBufferPos + len > flightSendLimit)
        {
            flushFlightBuffer();
        }

        System.arraycopy(buf, off, flightBuffer, flightBufferPos, len);
        flightBufferPos += len;
    }

    /** Caller holds 'writeLock'. */
    private void flushFlightBuffer() throws IOException
    {
        if (flightBufferPos > 0)
        {
            int len = flightBufferPos;
            flightBufferPos = 0;
            sendDatagram(transport, flightBuffer, 0, len);
        }
    }

    private static long getMacSequenceNumber(int epoch, long sequence_number)
    {
        return ((epoch & 0xFFFFFFFFL) << 48) | sequence_number;
    }
}
