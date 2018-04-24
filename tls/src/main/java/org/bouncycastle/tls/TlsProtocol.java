package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public abstract class TlsProtocol
{
    protected static final Integer EXT_RenegotiationInfo = Integers.valueOf(ExtensionType.renegotiation_info);
    protected static final Integer EXT_SessionTicket = Integers.valueOf(ExtensionType.session_ticket);

    /*
     * Our Connection states
     */
    protected static final short CS_START = 0;
    protected static final short CS_CLIENT_HELLO = 1;
    protected static final short CS_SERVER_HELLO = 2;
    protected static final short CS_SERVER_SUPPLEMENTAL_DATA = 3;
    protected static final short CS_SERVER_CERTIFICATE = 4;
    protected static final short CS_CERTIFICATE_STATUS = 5;
    protected static final short CS_SERVER_KEY_EXCHANGE = 6;
    protected static final short CS_CERTIFICATE_REQUEST = 7;
    protected static final short CS_SERVER_HELLO_DONE = 8;
    protected static final short CS_CLIENT_SUPPLEMENTAL_DATA = 9;
    protected static final short CS_CLIENT_CERTIFICATE = 10;
    protected static final short CS_CLIENT_KEY_EXCHANGE = 11;
    protected static final short CS_CERTIFICATE_VERIFY = 12;
    protected static final short CS_CLIENT_FINISHED = 13;
    protected static final short CS_SERVER_SESSION_TICKET = 14;
    protected static final short CS_SERVER_FINISHED = 15;
    protected static final short CS_END = 16;

    /*
     * Different modes to handle the known IV weakness
     */
    protected static final short ADS_MODE_1_Nsub1 = 0; // 1/n-1 record splitting
    protected static final short ADS_MODE_0_N = 1; // 0/n record splitting
    protected static final short ADS_MODE_0_N_FIRSTONLY = 2; // 0/n record splitting on first data fragment only

    /*
     * Queues for data from some protocols.
     */
    private ByteQueue applicationDataQueue = new ByteQueue(0);
    private ByteQueue alertQueue = new ByteQueue(2);
    private ByteQueue handshakeQueue = new ByteQueue(0);
//    private ByteQueue heartbeatQueue = new ByteQueue();

    /*
     * The Record Stream we use
     */
    RecordStream recordStream;

    private TlsInputStream tlsInputStream = null;
    private TlsOutputStream tlsOutputStream = null;

    private volatile boolean closed = false;
    private volatile boolean failedWithError = false;
    private volatile boolean appDataReady = false;
    private volatile boolean appDataSplitEnabled = true;
    private volatile int appDataSplitMode = ADS_MODE_1_Nsub1;
    // TODO[tls-ops] Investigate whether we can handle (expected/actual) verify data using TlsSecret
    private byte[] expected_verify_data = null;

    protected TlsSession tlsSession = null;
    protected SessionParameters sessionParameters = null;
    protected SecurityParameters securityParameters = null;
    protected Certificate localCertificate = null;
    protected Certificate peerCertificate = null;

    protected int[] offeredCipherSuites = null;
    protected short[] offeredCompressionMethods = null;
    protected Hashtable clientExtensions = null;
    protected Hashtable serverExtensions = null;

    protected short connection_state = CS_START;
    protected boolean resumedSession = false;
    protected boolean receivedChangeCipherSpec = false;
    protected boolean secure_renegotiation = false;
    protected boolean allowCertificateStatus = false;
    protected boolean expectSessionTicket = false;

    protected boolean blocking;
    protected ByteQueueInputStream inputBuffers;
    protected ByteQueueOutputStream outputBuffer;

    protected TlsProtocol()
    {
        this.blocking = false;
        this.inputBuffers = new ByteQueueInputStream();
        this.outputBuffer = new ByteQueueOutputStream();
        this.recordStream = new RecordStream(this, inputBuffers, outputBuffer);
    }

    protected TlsProtocol(InputStream input, OutputStream output)
    {
        this.blocking = true;
        this.recordStream = new RecordStream(this, input, output);
    }

    protected abstract TlsContext getContext();

    abstract AbstractTlsContext getContextAdmin();

    protected abstract TlsPeer getPeer();

    protected void handleAlertMessage(short alertLevel, short alertDescription)
        throws IOException
    {
        getPeer().notifyAlertReceived(alertLevel, alertDescription);

        if (alertLevel == AlertLevel.warning)
        {
            handleAlertWarningMessage(alertDescription);
        }
        else
        {
            handleFailure();

            throw new TlsFatalAlertReceived(alertDescription);
        }
    }

    protected void handleAlertWarningMessage(short alertDescription)
        throws IOException
    {
        /*
         * RFC 5246 7.2.1. The other party MUST respond with a close_notify alert of its own
         * and close down the connection immediately, discarding any pending writes.
         */
        if (alertDescription == AlertDescription.close_notify)
        {
            if (!appDataReady)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            handleClose(false);
        }
    }

    protected void handleChangeCipherSpecMessage() throws IOException
    {
    }

    protected void handleClose(boolean user_canceled)
        throws IOException
    {
        if (!closed)
        {
            this.closed = true;

            if (user_canceled && !appDataReady)
            {
                raiseAlertWarning(AlertDescription.user_canceled, "User canceled handshake");
            }

            raiseAlertWarning(AlertDescription.close_notify, "Connection closed");

            recordStream.safeClose();

            if (!appDataReady)
            {
                cleanupHandshake();
            }
        }
    }

    protected void handleException(short alertDescription, String message, Throwable cause)
        throws IOException
    {
        if (!closed)
        {
            raiseAlertFatal(alertDescription, message, cause);

            handleFailure();
        }
    }

    protected void handleFailure()
    {
        this.closed = true;
        this.failedWithError = true;

        /*
         * RFC 2246 7.2.1. The session becomes unresumable if any connection is terminated
         * without proper close_notify messages with level equal to warning.
         */
        // TODO This isn't quite in the right place. Also, as of TLS 1.1 the above is obsolete.
        invalidateSession();

        recordStream.safeClose();

        if (!appDataReady)
        {
            cleanupHandshake();
        }
    }

    protected abstract void handleHandshakeMessage(short type, ByteArrayInputStream buf)
        throws IOException;

    protected void applyMaxFragmentLengthExtension()
        throws IOException
    {
        short maxFragmentLength = securityParameters.getMaxFragmentLength();
        if (maxFragmentLength >= 0)
        {
            if (!MaxFragmentLength.isValid(maxFragmentLength))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error); 
            }

            int plainTextLimit = 1 << (8 + maxFragmentLength);
            recordStream.setPlaintextLimit(plainTextLimit);
        }
    }

    protected void checkReceivedChangeCipherSpec(boolean expected)
        throws IOException
    {
        if (expected != receivedChangeCipherSpec)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void cleanupHandshake()
    {
        if (this.expected_verify_data != null)
        {
            Arrays.fill(this.expected_verify_data, (byte)0);
            this.expected_verify_data = null;
        }

        this.tlsSession = null;
        this.sessionParameters = null;
        this.securityParameters.clear();
        this.localCertificate = null;
        this.peerCertificate = null;

        this.offeredCipherSuites = null;
        this.offeredCompressionMethods = null;
        this.clientExtensions = null;
        this.serverExtensions = null;

        this.resumedSession = false;
        this.receivedChangeCipherSpec = false;
        this.secure_renegotiation = false;
        this.allowCertificateStatus = false;
        this.expectSessionTicket = false;
    }
    
    protected void blockForHandshake() throws IOException
    {
        if (blocking)
        {
            while (this.connection_state != CS_END)
            {
                if (this.closed)
                {
                    // NOTE: Any close during the handshake should have raised an exception.
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                safeReadRecord();
            }
        }
    }

    protected void completeHandshake()
        throws IOException
    {
        try
        {
            this.connection_state = CS_END;

            this.alertQueue.shrink();
            this.handshakeQueue.shrink();

            this.recordStream.finaliseHandshake();

            this.appDataSplitEnabled = !TlsUtils.isTLSv11(getContext());

            /*
             * If this was an initial handshake, we are now ready to send and receive application data.
             */
            if (!appDataReady)
            {
                this.appDataReady = true;

                if (blocking)
                {
                    this.tlsInputStream = new TlsInputStream(this);
                    this.tlsOutputStream = new TlsOutputStream(this);
                }
            }

            if (this.sessionParameters == null)
            {
                this.sessionParameters = new SessionParameters.Builder()
                    .setCipherSuite(this.securityParameters.getCipherSuite())
                    .setCompressionAlgorithm(this.securityParameters.getCompressionAlgorithm())
                    .setLocalCertificate(this.localCertificate)
                    .setMasterSecret(getContext().getCrypto().adoptSecret(this.securityParameters.getMasterSecret()))
                    .setNegotiatedVersion(getContext().getServerVersion())
                    .setPeerCertificate(this.peerCertificate)
                    .setPSKIdentity(this.securityParameters.getPSKIdentity())
                    .setSRPIdentity(this.securityParameters.getSRPIdentity())
                    // TODO Consider filtering extensions that aren't relevant to resumed sessions
                    .setServerExtensions(this.serverExtensions)
                    .build();

                this.tlsSession = TlsUtils.importSession(this.tlsSession.getSessionID(), this.sessionParameters);
            }

            getContextAdmin().setSession(this.tlsSession);

            getPeer().notifyHandshakeComplete();
        }
        finally
        {
            cleanupHandshake();
        }
    }

    protected void processRecord(short protocol, byte[] buf, int off, int len)
        throws IOException
    {
        /*
         * Have a look at the protocol type, and add it to the correct queue.
         */
        switch (protocol)
        {
        case ContentType.alert:
        {
            alertQueue.addData(buf, off, len);
            processAlertQueue();
            break;
        }
        case ContentType.application_data:
        {
            if (!appDataReady)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            applicationDataQueue.addData(buf, off, len);
            processApplicationDataQueue();
            break;
        }
        case ContentType.change_cipher_spec:
        {
            processChangeCipherSpec(buf, off, len);
            break;
        }
        case ContentType.handshake:
        {
            if (handshakeQueue.available() > 0)
            {
                handshakeQueue.addData(buf, off, len);
                processHandshakeQueue(handshakeQueue);
            }
            else
            {
                ByteQueue tmpQueue = new ByteQueue(buf, off, len);
                processHandshakeQueue(tmpQueue);
                int remaining = tmpQueue.available();
                if (remaining > 0)
                {
                    handshakeQueue.addData(buf, off + len - remaining, remaining);
                }
            }
            break;
        }
//        case ContentType.heartbeat:
//        {
//            if (!appDataReady)
//            {
//                throw new TlsFatalAlert(AlertDescription.unexpected_message);
//            }
//            // TODO[RFC 6520]
////            heartbeatQueue.addData(buf, offset, len);
////            processHeartbeat();
//            break;
//        }
        default:
            // Record type should already have been checked
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    private void processHandshakeQueue(ByteQueue queue)
        throws IOException
    {
        /*
         * We need the first 4 bytes, they contain type and length of the message.
         */
        while (queue.available() >= 4)
        {
            byte[] beginning = new byte[4];
            queue.read(beginning, 0, 4, 0);
            short type = TlsUtils.readUint8(beginning, 0);
            int length = TlsUtils.readUint24(beginning, 1);
            int totalLength = 4 + length;

            /*
             * Check if we have enough bytes in the buffer to read the full message.
             */
            if (queue.available() < totalLength)
            {
                break;
            }

            checkReceivedChangeCipherSpec(connection_state == CS_END || type == HandshakeType.finished);

            /*
             * RFC 2246 7.4.9. The value handshake_messages includes all handshake messages
             * starting at client hello up to, but not including, this finished message.
             * [..] Note: [Also,] Hello Request messages are omitted from handshake hashes.
             */
            switch (type)
            {
            case HandshakeType.hello_request:
                break;
            case HandshakeType.finished:
            {
                TlsContext ctx = getContext();
                if (this.expected_verify_data == null
                    && ctx.getSecurityParameters().getMasterSecret() != null)
                {
                    this.expected_verify_data = createVerifyData(!ctx.isServer());
                }

                // NB: Fall through to next case label
            }
            default:
                queue.copyTo(recordStream.getHandshakeHashUpdater(), totalLength);
                break;
            }

            queue.removeData(4);

            ByteArrayInputStream buf = queue.readFrom(length);

            /*
             * Now, parse the message.
             */
            handleHandshakeMessage(type, buf);
        }
    }

    private void processApplicationDataQueue()
    {
        /*
         * There is nothing we need to do here.
         * 
         * This function could be used for callbacks when application data arrives in the future.
         */
    }

    private void processAlertQueue()
        throws IOException
    {
        while (alertQueue.available() >= 2)
        {
            /*
             * An alert is always 2 bytes. Read the alert.
             */
            byte[] alert = alertQueue.removeData(2, 0);
            short alertLevel = alert[0];
            short alertDescription = alert[1];

            handleAlertMessage(alertLevel, alertDescription);
        }
    }

    /**
     * This method is called, when a change cipher spec message is received.
     *
     * @throws IOException If the message has an invalid content or the handshake is not in the correct
     * state.
     */
    private void processChangeCipherSpec(byte[] buf, int off, int len)
        throws IOException
    {
        for (int i = 0; i < len; ++i)
        {
            short message = TlsUtils.readUint8(buf, off + i);

            if (message != ChangeCipherSpec.change_cipher_spec)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            if (this.receivedChangeCipherSpec
                || alertQueue.available() > 0
                || handshakeQueue.available() > 0)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            recordStream.receivedReadCipherSpec();

            this.receivedChangeCipherSpec = true;

            handleChangeCipherSpecMessage();
        }
    }

    public int applicationDataAvailable()
    {
        return applicationDataQueue.available();
    }

    /**
     * Read data from the network. The method will return immediately, if there is still some data
     * left in the buffer, or block until some application data has been read from the network.
     *
     * @param buf    The buffer where the data will be copied to.
     * @param offset The position where the data will be placed in the buffer.
     * @param len    The maximum number of bytes to read.
     * @return The number of bytes read.
     * @throws IOException If something goes wrong during reading data.
     */
    public int readApplicationData(byte[] buf, int offset, int len)
        throws IOException
    {
        if (len < 1)
        {
            return 0;
        }

        while (applicationDataQueue.available() == 0)
        {
            if (this.closed)
            {
                if (this.failedWithError)
                {
                    throw new IOException("Cannot read application data on failed TLS connection");
                }
                return -1;
            }
            if (!appDataReady)
            {
                throw new IllegalStateException("Cannot read application data until initial handshake completed.");
            }

            safeReadRecord();
        }

        len = Math.min(len, applicationDataQueue.available());
        applicationDataQueue.removeData(buf, offset, len, 0);
        return len;
    }

    protected RecordPreview safePreviewRecordHeader(byte[] recordHeader)
        throws IOException
    {
        try
        {
            return recordStream.previewRecordHeader(recordHeader, appDataReady);
        }
        catch (TlsFatalAlert e)
        {
            handleException(e.getAlertDescription(), "Failed to read record", e);
            throw e;
        }
        catch (IOException e)
        {
            handleException(AlertDescription.internal_error, "Failed to read record", e);
            throw e;
        }
        catch (RuntimeException e)
        {
            handleException(AlertDescription.internal_error, "Failed to read record", e);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    protected void safeReadRecord()
        throws IOException
    {
        try
        {
            if (recordStream.readRecord())
            {
                return;
            }

            if (!appDataReady)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }
        catch (TlsFatalAlertReceived e)
        {
            // Connection failure already handled at source
            throw e;
        }
        catch (TlsFatalAlert e)
        {
            handleException(e.getAlertDescription(), "Failed to read record", e);
            throw e;
        }
        catch (IOException e)
        {
            handleException(AlertDescription.internal_error, "Failed to read record", e);
            throw e;
        }
        catch (RuntimeException e)
        {
            handleException(AlertDescription.internal_error, "Failed to read record", e);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        handleFailure();

        throw new TlsNoCloseNotifyException();
    }

    protected boolean safeReadFullRecord(byte[] record)
        throws IOException
    {
        try
        {
            return recordStream.readFullRecord(record);
        }
        catch (TlsFatalAlert e)
        {
            handleException(e.getAlertDescription(), "Failed to process record", e);
            throw e;
        }
        catch (IOException e)
        {
            handleException(AlertDescription.internal_error, "Failed to process record", e);
            throw e;
        }
        catch (RuntimeException e)
        {
            handleException(AlertDescription.internal_error, "Failed to process record", e);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    protected void safeWriteRecord(short type, byte[] buf, int offset, int len)
        throws IOException
    {
        try
        {
            recordStream.writeRecord(type, buf, offset, len);
        }
        catch (TlsFatalAlert e)
        {
            handleException(e.getAlertDescription(), "Failed to write record", e);
            throw e;
        }
        catch (IOException e)
        {
            handleException(AlertDescription.internal_error, "Failed to write record", e);
            throw e;
        }
        catch (RuntimeException e)
        {
            handleException(AlertDescription.internal_error, "Failed to write record", e);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    /**
     * Write some application data. Fragmentation is handled internally. Usable in both
     * blocking/non-blocking modes.<br>
     * <br>
     * In blocking mode, the output will be automatically sent via the underlying transport. In
     * non-blocking mode, call {@link #readOutput(byte[], int, int)} to get the output bytes to send
     * to the peer.<br>
     * <br>
     * This method must not be called until after the initial handshake is complete. Attempting to
     * call it earlier will result in an {@link IllegalStateException}.
     *
     * @param buf
     *            The buffer containing application data to send
     * @param offset
     *            The offset at which the application data begins
     * @param len
     *            The number of bytes of application data
     * @throws IllegalStateException
     *             If called before the initial handshake has completed.
     * @throws IOException
     *             If connection is already closed, or for encryption or transport errors.
     */
    public void writeApplicationData(byte[] buf, int offset, int len)
        throws IOException
    {
        if (this.closed)
        {
            throw new IOException("Cannot write application data on closed/failed TLS connection");
        }
        if (!appDataReady)
        {
            throw new IllegalStateException("Cannot write application data until initial handshake completed.");
        }

        while (len > 0)
        {
            /*
             * RFC 5246 6.2.1. Zero-length fragments of Application data MAY be sent as they are
             * potentially useful as a traffic analysis countermeasure.
             * 
             * NOTE: Actually, implementations appear to have settled on 1/n-1 record splitting.
             */

            if (this.appDataSplitEnabled)
            {
                /*
                 * Protect against known IV attack!
                 * 
                 * DO NOT REMOVE THIS CODE, EXCEPT YOU KNOW EXACTLY WHAT YOU ARE DOING HERE.
                 */
                switch (appDataSplitMode) {
                    case ADS_MODE_0_N_FIRSTONLY:
                        this.appDataSplitEnabled = false;
                        // fall through intended!
                    case ADS_MODE_0_N:
                        safeWriteRecord(ContentType.application_data, TlsUtils.EMPTY_BYTES, 0, 0);
                        break;
                    case ADS_MODE_1_Nsub1:
                    default:
                        safeWriteRecord(ContentType.application_data, buf, offset, 1);
                        ++offset;
                        --len;
                        break;
                }
            }

            if (len > 0)
            {
                // Fragment data according to the current fragment limit.
                int toWrite = Math.min(len, recordStream.getPlaintextLimit());
                safeWriteRecord(ContentType.application_data, buf, offset, toWrite);
                offset += toWrite;
                len -= toWrite;
            }
        }
    }

    protected void setAppDataSplitMode(int appDataSplitMode) {
        if (appDataSplitMode < ADS_MODE_1_Nsub1 ||
            appDataSplitMode > ADS_MODE_0_N_FIRSTONLY)
        {
            throw new IllegalArgumentException("Illegal appDataSplitMode mode: " + appDataSplitMode);
        }
        this.appDataSplitMode = appDataSplitMode;
	}

    protected void writeHandshakeMessage(byte[] buf, int off, int len) throws IOException
    {
        if (len < 4)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        short type = TlsUtils.readUint8(buf, off);
        if (type != HandshakeType.hello_request)
        {
            recordStream.getHandshakeHashUpdater().write(buf, off, len);
        }

        int total = 0;
        do
        {
            // Fragment data according to the current fragment limit.
            int toWrite = Math.min(len - total, recordStream.getPlaintextLimit());
            safeWriteRecord(ContentType.handshake, buf, off + total, toWrite);
            total += toWrite;
        }
        while (total < len);
    }

    /**
     * @return An OutputStream which can be used to send data. Only allowed in blocking mode.
     */
    public OutputStream getOutputStream()
    {
        if (!blocking)
        {
            throw new IllegalStateException("Cannot use OutputStream in non-blocking mode! Use offerOutput() instead.");
        }
        return this.tlsOutputStream;
    }

    /**
     * @return An InputStream which can be used to read data. Only allowed in blocking mode.
     */
    public InputStream getInputStream()
    {
        if (!blocking)
        {
            throw new IllegalStateException("Cannot use InputStream in non-blocking mode! Use offerInput() instead.");
        }
        return this.tlsInputStream;
    }

    /**
     * Should be called in non-blocking mode when the input data reaches EOF.
     */
    public void closeInput() throws IOException
    {
        if (blocking)
        {
            throw new IllegalStateException("Cannot use closeInput() in blocking mode!");
        }

        if (closed)
        {
            return;
        }

        if (inputBuffers.available() > 0)
        {
            throw new EOFException();
        }

        if (!appDataReady)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        throw new TlsNoCloseNotifyException();
    }

    public RecordPreview previewInputRecord(byte[] recordHeader) throws IOException
    {
        if (blocking)
        {
            throw new IllegalStateException("Cannot use previewInputRecord() in blocking mode!");
        }
        if (inputBuffers.available() != 0)
        {
            throw new IllegalStateException("Can only use previewInputRecord() for record-aligned input.");
        }

        if (closed)
        {
            throw new IOException("Connection is closed, cannot accept any more input");
        }

        return safePreviewRecordHeader(recordHeader);
    }

    public RecordPreview previewOutputRecord(int applicationDataSize) throws IOException
    {
        if (blocking)
        {
            throw new IllegalStateException("Cannot use previewOutputRecord() in blocking mode!");
        }
        if (outputBuffer.getBuffer().available() != 0)
        {
            throw new IllegalStateException("Can only use previewOutputRecord() for record-aligned output.");
        }

        if (closed)
        {
            throw new IOException("Connection is closed, cannot produce any more output");
        }

        if (applicationDataSize < 1)
        {
            return new RecordPreview(0, 0);
        }

        if (this.appDataSplitEnabled)
        {
            switch (appDataSplitMode)
            {
                case ADS_MODE_0_N_FIRSTONLY:
                case ADS_MODE_0_N:
                {
                    RecordPreview a = recordStream.previewOutputRecord(0);
                    RecordPreview b = recordStream.previewOutputRecord(applicationDataSize);
                    return RecordPreview.combine(a, b);
                }
                case ADS_MODE_1_Nsub1:
                default:
                {
                    RecordPreview a = recordStream.previewOutputRecord(1);
                    if (applicationDataSize > 1)
                    {
                        RecordPreview b = recordStream.previewOutputRecord(applicationDataSize - 1);
                        a = RecordPreview.combine(a, b);
                    }
                    return a;
                }
            }
        }
        else
        {
            return recordStream.previewOutputRecord(applicationDataSize);
        }
    }

    /**
     * Offer input from an arbitrary source. Only allowed in non-blocking mode.<br>
     * <br>
     * After this method returns, the input buffer is "owned" by this object. Other code
     * must not attempt to do anything with it.<br>
     * <br>
     * This method will decrypt and process all records that are fully available.
     * If only part of a record is available, the buffer will be retained until the
     * remainder of the record is offered.<br>
     * <br>
     * If any records containing application data were processed, the decrypted data
     * can be obtained using {@link #readInput(byte[], int, int)}. If any records
     * containing protocol data were processed, a response may have been generated.
     * You should always check to see if there is any available output after calling
     * this method by calling {@link #getAvailableOutputBytes()}.
     * @param input The input buffer to offer
     * @throws IOException If an error occurs while decrypting or processing a record
     */
    public void offerInput(byte[] input) throws IOException
    {
        if (blocking)
        {
            throw new IllegalStateException("Cannot use offerInput() in blocking mode! Use getInputStream() instead.");
        }
        
        if (closed)
        {
            throw new IOException("Connection is closed, cannot accept any more input");
        }

        // Fast path if the input is arriving one record at a time
        if (inputBuffers.available() == 0 && safeReadFullRecord(input))
        {
            if (closed)
            {
                if (connection_state != CS_END)
                {
                    // NOTE: Any close during the handshake should have raised an exception.
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }
            }
            return;
        }

        inputBuffers.addBytes(input);

        // loop while there are enough bytes to read the length of the next record
        while (inputBuffers.available() >= RecordFormat.FRAGMENT_OFFSET)
        {
            byte[] recordHeader = new byte[RecordFormat.FRAGMENT_OFFSET];
            inputBuffers.peek(recordHeader);

            RecordPreview preview = safePreviewRecordHeader(recordHeader);
            if (inputBuffers.available() < preview.getRecordSize())
            {
                // not enough bytes to read a whole record
                break;
            }

            safeReadRecord();

            if (closed)
            {
                if (connection_state != CS_END)
                {
                    // NOTE: Any close during the handshake should have raised an exception.
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }
                break;
            }
        }
    }

    public int getApplicationDataLimit()
    {
        return recordStream.getPlaintextLimit();
    }

    /**
     * Gets the amount of received application data. A call to {@link #readInput(byte[], int, int)}
     * is guaranteed to be able to return at least this much data.<br>
     * <br>
     * Only allowed in non-blocking mode.
     * @return The number of bytes of available application data
     */
    public int getAvailableInputBytes()
    {
        if (blocking)
        {
            throw new IllegalStateException("Cannot use getAvailableInputBytes() in blocking mode! Use getInputStream().available() instead.");
        }
        return applicationDataAvailable();
    }

    /**
     * Retrieves received application data. Use {@link #getAvailableInputBytes()} to check
     * how much application data is currently available. This method functions similarly to
     * {@link InputStream#read(byte[], int, int)}, except that it never blocks. If no data
     * is available, nothing will be copied and zero will be returned.<br>
     * <br>
     * Only allowed in non-blocking mode.
     * @param buffer The buffer to hold the application data
     * @param offset The start offset in the buffer at which the data is written
     * @param length The maximum number of bytes to read
     * @return The total number of bytes copied to the buffer. May be less than the
     *          length specified if the length was greater than the amount of available data.
     */
    public int readInput(byte[] buffer, int offset, int length)
    {
        if (blocking)
        {
            throw new IllegalStateException("Cannot use readInput() in blocking mode! Use getInputStream() instead.");
        }

        length = Math.min(length, applicationDataQueue.available());
        if (length < 1)
        {
            return 0;
        }

        applicationDataQueue.removeData(buffer, offset, length, 0);
        return length;
    }

    /**
     * Gets the amount of encrypted data available to be sent. A call to
     * {@link #readOutput(byte[], int, int)} is guaranteed to be able to return at
     * least this much data.<br>
     * <br>
     * Only allowed in non-blocking mode.
     * @return The number of bytes of available encrypted data
     */
    public int getAvailableOutputBytes()
    {
        if (blocking)
        {
            throw new IllegalStateException("Cannot use getAvailableOutputBytes() in blocking mode! Use getOutputStream() instead.");
        }
        
        return outputBuffer.getBuffer().available();
    }

    /**
     * Retrieves encrypted data to be sent. Use {@link #getAvailableOutputBytes()} to check
     * how much encrypted data is currently available. This method functions similarly to
     * {@link InputStream#read(byte[], int, int)}, except that it never blocks. If no data
     * is available, nothing will be copied and zero will be returned.<br>
     * <br>
     * Only allowed in non-blocking mode.
     * @param buffer The buffer to hold the encrypted data
     * @param offset The start offset in the buffer at which the data is written
     * @param length The maximum number of bytes to read
     * @return The total number of bytes copied to the buffer. May be less than the
     *          length specified if the length was greater than the amount of available data.
     */
    public int readOutput(byte[] buffer, int offset, int length)
    {
        if (blocking)
        {
            throw new IllegalStateException("Cannot use readOutput() in blocking mode! Use getOutputStream() instead.");
        }
        
        int bytesToRead = Math.min(getAvailableOutputBytes(), length);
        outputBuffer.getBuffer().removeData(buffer, offset, bytesToRead, 0);
        return bytesToRead;
    }

    protected void invalidateSession()
    {
        if (this.sessionParameters != null)
        {
            this.sessionParameters.clear();
            this.sessionParameters = null;
        }

        if (this.tlsSession != null)
        {
            this.tlsSession.invalidate();
            this.tlsSession = null;
        }
    }

    protected void processFinishedMessage(ByteArrayInputStream buf)
        throws IOException
    {
        if (expected_verify_data == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        byte[] verify_data = TlsUtils.readFully(expected_verify_data.length, buf);

        assertEmpty(buf);

        /*
         * Compare both checksums.
         */
        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data))
        {
            /*
             * Wrong checksum in the finished message.
             */
            throw new TlsFatalAlert(AlertDescription.decrypt_error);
        }

        if (null == securityParameters.getTLSUnique())
        {
            securityParameters.tlsUnique = verify_data;
        }
    }

    protected void raiseAlertFatal(short alertDescription, String message, Throwable cause)
        throws IOException
    {
        getPeer().notifyAlertRaised(AlertLevel.fatal, alertDescription, message, cause);

        byte[] alert = new byte[]{ (byte)AlertLevel.fatal, (byte)alertDescription };

        try
        {
            recordStream.writeRecord(ContentType.alert, alert, 0, 2);
        }
        catch (Exception e)
        {
            // We are already processing an exception, so just ignore this
        }
    }

    protected void raiseAlertWarning(short alertDescription, String message)
        throws IOException
    {
        getPeer().notifyAlertRaised(AlertLevel.warning, alertDescription, message, null);

        byte[] alert = new byte[]{ (byte)AlertLevel.warning, (byte)alertDescription };

        safeWriteRecord(ContentType.alert, alert, 0, 2);
    }

    protected void sendCertificateMessage(Certificate certificate)
        throws IOException
    {
        if (certificate == null)
        {
            certificate = Certificate.EMPTY_CHAIN;
        }

        HandshakeMessage message = new HandshakeMessage(HandshakeType.certificate);

        certificate.encode(message);

        message.writeToRecordStream();

        this.localCertificate = certificate;
    }

    protected void sendChangeCipherSpecMessage()
        throws IOException
    {
        byte[] message = new byte[]{ 1 };
        safeWriteRecord(ContentType.change_cipher_spec, message, 0, message.length);
        recordStream.sentWriteCipherSpec();
    }

    protected void sendFinishedMessage()
        throws IOException
    {
        byte[] verify_data = createVerifyData(getContext().isServer());

        HandshakeMessage message = new HandshakeMessage(HandshakeType.finished, verify_data.length);

        message.write(verify_data);

        message.writeToRecordStream();

        if (null == securityParameters.getTLSUnique())
        {
            securityParameters.tlsUnique = verify_data;
        }
    }

    protected void sendSupplementalDataMessage(Vector supplementalData)
        throws IOException
    {
        HandshakeMessage message = new HandshakeMessage(HandshakeType.supplemental_data);

        writeSupplementalData(message, supplementalData);

        message.writeToRecordStream();
    }

    protected byte[] createVerifyData(boolean isServer)
    {
        return TlsUtils.calculateTLSVerifyData(getContext(), recordStream.getHandshakeHash(), isServer);
    }

    /**
     * Closes this connection.
     *
     * @throws IOException If something goes wrong during closing.
     */
    public void close()
        throws IOException
    {
        handleClose(true);
    }

    public void flush()
        throws IOException
    {
        recordStream.flush();
    }

    public boolean isClosed()
    {
        return closed;
    }

    protected short processMaxFragmentLengthExtension(Hashtable clientExtensions, Hashtable serverExtensions,
        short alertDescription)
        throws IOException
    {
        short maxFragmentLength = TlsExtensionsUtils.getMaxFragmentLengthExtension(serverExtensions);
        if (maxFragmentLength >= 0)
        {
            if (!MaxFragmentLength.isValid(maxFragmentLength)
                || (!this.resumedSession && maxFragmentLength != TlsExtensionsUtils
                    .getMaxFragmentLengthExtension(clientExtensions)))
            {
                throw new TlsFatalAlert(alertDescription);
            }
        }
        return maxFragmentLength;
    }

    protected void refuseRenegotiation() throws IOException
    {
        raiseAlertWarning(AlertDescription.no_renegotiation, "Renegotiation not supported");
    }

    /**
     * Make sure the InputStream 'buf' now empty. Fail otherwise.
     *
     * @param buf The InputStream to check.
     * @throws IOException If 'buf' is not empty.
     */
    protected static void assertEmpty(ByteArrayInputStream buf)
        throws IOException
    {
        if (buf.available() > 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
    }

    protected static byte[] createRandomBlock(boolean useGMTUnixTime, TlsContext context)
    {
        byte[] result = context.getNonceGenerator().generateNonce(32);

        if (useGMTUnixTime)
        {
            TlsUtils.writeGMTUnixTime(result, 0);
        }

        return result;
    }

    protected static byte[] createRenegotiationInfo(byte[] renegotiated_connection)
        throws IOException
    {
        return TlsUtils.encodeOpaque8(renegotiated_connection);
    }

    protected static void establishMasterSecret(TlsContext context, TlsKeyExchange keyExchange)
        throws IOException
    {
        TlsSecret preMasterSecret = keyExchange.generatePreMasterSecret();
        if (preMasterSecret == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        try
        {
            context.getSecurityParameters().masterSecret = TlsUtils.calculateMasterSecret(context, preMasterSecret);
        }
        finally
        {
            /*
             * RFC 2246 8.1. The pre_master_secret should be deleted from memory once the
             * master_secret has been computed.
             */
            preMasterSecret.destroy();
        }
    }

    protected static Hashtable readExtensions(ByteArrayInputStream input)
        throws IOException
    {
        if (input.available() < 1)
        {
            return null;
        }

        byte[] extBytes = TlsUtils.readOpaque16(input);

        assertEmpty(input);

        ByteArrayInputStream buf = new ByteArrayInputStream(extBytes);

        // Integer -> byte[]
        Hashtable extensions = new Hashtable();

        while (buf.available() > 0)
        {
            Integer extension_type = Integers.valueOf(TlsUtils.readUint16(buf));
            byte[] extension_data = TlsUtils.readOpaque16(buf);

            /*
             * RFC 3546 2.3 There MUST NOT be more than one extension of the same type.
             */
            if (null != extensions.put(extension_type, extension_data))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

        return extensions;
    }

    protected static Vector readSupplementalDataMessage(ByteArrayInputStream input)
        throws IOException
    {
        byte[] supp_data = TlsUtils.readOpaque24(input);

        assertEmpty(input);

        ByteArrayInputStream buf = new ByteArrayInputStream(supp_data);

        Vector supplementalData = new Vector();

        while (buf.available() > 0)
        {
            int supp_data_type = TlsUtils.readUint16(buf);
            byte[] data = TlsUtils.readOpaque16(buf);

            supplementalData.addElement(new SupplementalDataEntry(supp_data_type, data));
        }

        return supplementalData;
    }

    protected static TlsCredentials validateCredentials(TlsCredentials credentials)
        throws IOException
    {
        if (credentials != null)
        {
            int count = 0;
            count += (credentials instanceof TlsCredentialedAgreement) ? 1 : 0;
            count += (credentials instanceof TlsCredentialedDecryptor) ? 1 : 0;
            count += (credentials instanceof TlsCredentialedSigner) ? 1 : 0;
            if (count != 1)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
        return credentials;
    }

    protected static void writeExtensions(OutputStream output, Hashtable extensions)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        /*
         * NOTE: There are reports of servers that don't accept a zero-length extension as the last
         * one, so we write out any zero-length ones first as a best-effort workaround.
         */
        writeSelectedExtensions(buf, extensions, true);
        writeSelectedExtensions(buf, extensions, false);

        byte[] extBytes = buf.toByteArray();

        TlsUtils.writeOpaque16(extBytes, output);
    }

    protected static void writeSelectedExtensions(OutputStream output, Hashtable extensions, boolean selectEmpty)
        throws IOException
    {
        Enumeration keys = extensions.keys();
        while (keys.hasMoreElements())
        {
            Integer key = (Integer)keys.nextElement();
            int extension_type = key.intValue();
            byte[] extension_data = (byte[])extensions.get(key);

            if (selectEmpty == (extension_data.length == 0))
            {
                TlsUtils.checkUint16(extension_type);
                TlsUtils.writeUint16(extension_type, output);
                TlsUtils.writeOpaque16(extension_data, output);
            }
        }
    }

    protected static void writeSupplementalData(OutputStream output, Vector supplementalData)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        for (int i = 0; i < supplementalData.size(); ++i)
        {
            SupplementalDataEntry entry = (SupplementalDataEntry)supplementalData.elementAt(i);

            int supp_data_type = entry.getDataType();
            TlsUtils.checkUint16(supp_data_type);
            TlsUtils.writeUint16(supp_data_type, buf);
            TlsUtils.writeOpaque16(entry.getData(), buf);
        }

        byte[] supp_data = buf.toByteArray();

        TlsUtils.writeOpaque24(supp_data, output);
    }

    protected static int getPRFAlgorithm(TlsContext context, int cipherSuite) throws IOException
    {
        boolean isTLSv12 = TlsUtils.isTLSv12(context);

        switch (cipherSuite)
        {
        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
        {
            if (isTLSv12)
            {
                return PRFAlgorithm.tls_prf_sha256;
            }
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        {
            if (isTLSv12)
            {
                return PRFAlgorithm.tls_prf_sha384;
            }
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
        {
            if (isTLSv12)
            {
                return PRFAlgorithm.tls_prf_sha384;
            }
            return PRFAlgorithm.tls_prf_legacy;
        }

        default:
        {
            if (isTLSv12)
            {
                return PRFAlgorithm.tls_prf_sha256;
            }
            return PRFAlgorithm.tls_prf_legacy;
        }
        }
    }

    class HandshakeMessage extends ByteArrayOutputStream
    {
        HandshakeMessage(short handshakeType) throws IOException
        {
            this(handshakeType, 60);
        }

        HandshakeMessage(short handshakeType, int length) throws IOException
        {
            super(length + 4);
            TlsUtils.writeUint8(handshakeType, this);
            // Reserve space for length
            count += 3;
        }

        void writeToRecordStream() throws IOException
        {
            // Patch actual length back in
            int length = count - 4;
            TlsUtils.checkUint24(length);
            TlsUtils.writeUint24(length, buf, 1);
            writeHandshakeMessage(buf, 0, count);
            buf = null;
        }
    }
}
