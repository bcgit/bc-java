package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public abstract class TlsProtocol
{
    protected static final Integer EXT_RenegotiationInfo = Integers.valueOf(ExtensionType.renegotiation_info);
    protected static final Integer EXT_SessionTicket = Integers.valueOf(ExtensionType.session_ticket);

    private static final String TLS_ERROR_MESSAGE = "Internal TLS error, this could be an attack";

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
    protected SecureRandom secureRandom;

    private TlsInputStream tlsInputStream = null;
    private TlsOutputStream tlsOutputStream = null;

    private volatile boolean closed = false;
    private volatile boolean failedWithError = false;
    private volatile boolean appDataReady = false;
    private volatile boolean appDataSplitEnabled = true;
    private volatile int appDataSplitMode = ADS_MODE_1_Nsub1;
    private byte[] expected_verify_data = null;

    protected TlsSession tlsSession = null;
    protected SessionParameters sessionParameters = null;
    protected SecurityParameters securityParameters = null;
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
    
    public TlsProtocol(InputStream input, OutputStream output, SecureRandom secureRandom)
    {
        this.blocking = true;
        this.recordStream = new RecordStream(this, input, output);
        this.secureRandom = secureRandom;
    }
    
    public TlsProtocol(SecureRandom secureRandom)
    {
        this.blocking = false;
        this.inputBuffers = new ByteQueueInputStream();
        this.outputBuffer = new ByteQueueOutputStream();
        this.recordStream = new RecordStream(this, inputBuffers, outputBuffer);
        this.secureRandom = secureRandom;
    }

    protected abstract TlsContext getContext();

    abstract AbstractTlsContext getContextAdmin();

    protected abstract TlsPeer getPeer();

    protected void handleChangeCipherSpecMessage() throws IOException
    {
    }

    protected abstract void handleHandshakeMessage(short type, ByteArrayInputStream buf)
        throws IOException;

    protected void handleWarningMessage(short description)
        throws IOException
    {
    }

    protected void applyMaxFragmentLengthExtension()
        throws IOException
    {
        if (securityParameters.maxFragmentLength >= 0)
        {
            if (!MaxFragmentLength.isValid(securityParameters.maxFragmentLength))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error); 
            }
    
            int plainTextLimit = 1 << (8 + securityParameters.maxFragmentLength);
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

        this.securityParameters.clear();
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

            if (this.tlsSession != null)
            {
                if (this.sessionParameters == null)
                {
                    this.sessionParameters = new SessionParameters.Builder()
                        .setCipherSuite(this.securityParameters.getCipherSuite())
                        .setCompressionAlgorithm(this.securityParameters.getCompressionAlgorithm())
                        .setMasterSecret(this.securityParameters.getMasterSecret())
                        .setPeerCertificate(this.peerCertificate)
                        .setPSKIdentity(this.securityParameters.getPSKIdentity())
                        .setSRPIdentity(this.securityParameters.getSRPIdentity())
                        // TODO Consider filtering extensions that aren't relevant to resumed sessions
                        .setServerExtensions(this.serverExtensions)
                        .build();

                    this.tlsSession = new TlsSessionImpl(this.tlsSession.getSessionID(), this.sessionParameters);
                }

                getContextAdmin().setResumableSession(this.tlsSession);
            }

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
        while (queue.available() >= 4)
        {
            /*
             * We need the first 4 bytes, they contain type and length of the message.
             */
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
            byte[] tmp = alertQueue.removeData(2, 0);
            short level = tmp[0];
            short description = tmp[1];

            getPeer().notifyAlertReceived(level, description);

            if (level == AlertLevel.fatal)
            {
                /*
                 * RFC 2246 7.2.1. The session becomes unresumable if any connection is terminated
                 * without proper close_notify messages with level equal to warning.
                 */
                invalidateSession();

                this.failedWithError = true;
                this.closed = true;

                recordStream.safeClose();

                throw new IOException(TLS_ERROR_MESSAGE);
            }
            else
            {
                /*
                 * RFC 5246 7.2.1. The other party MUST respond with a close_notify alert of its own
                 * and close down the connection immediately, discarding any pending writes.
                 */
                if (description == AlertDescription.close_notify)
                {
                    if (!appDataReady)
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                    }
                    handleClose(false);
                }

                /*
                 * If it is just a warning, we continue.
                 */
                handleWarningMessage(description);
            }
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

    protected int applicationDataAvailable()
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
    protected int readApplicationData(byte[] buf, int offset, int len)
        throws IOException
    {
        if (len < 1)
        {
            return 0;
        }

        while (applicationDataQueue.available() == 0)
        {
            /*
             * We need to read some data.
             */
            if (this.closed)
            {
                if (this.failedWithError)
                {
                    /*
                     * Something went terribly wrong, we should throw an IOException
                     */
                    throw new IOException(TLS_ERROR_MESSAGE);
                }

                /*
                 * Connection has been closed, there is no more data to read.
                 */
                return -1;
            }

            safeReadRecord();
        }

        len = Math.min(len, applicationDataQueue.available());
        applicationDataQueue.removeData(buf, offset, len, 0);
        return len;
    }

    protected void safeCheckRecordHeader(byte[] recordHeader)
        throws IOException
    {
        try
        {
            recordStream.checkRecordHeader(recordHeader);
        }
        catch (TlsFatalAlert e)
        {
            this.failWithError(AlertLevel.fatal, e.getAlertDescription(), "Failed to read record", e);
            throw e;
        }
        catch (IOException e)
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to read record", e);
            throw e;
        }
        catch (RuntimeException e)
        {
            this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to read record", e);
            throw e;
        }
    }

    protected void safeReadRecord()
        throws IOException
    {
        try
        {
            if (!recordStream.readRecord())
            {
                if (!appDataReady)
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
                throw new TlsNoCloseNotifyException();
            }
        }
        catch (TlsFatalAlert e)
        {
            if (!closed)
            {
                this.failWithError(AlertLevel.fatal, e.getAlertDescription(), "Failed to read record", e);
            }
            throw e;
        }
        catch (IOException e)
        {
            if (!closed)
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to read record", e);
            }
            throw e;
        }
        catch (RuntimeException e)
        {
            if (!closed)
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to read record", e);
            }
            throw e;
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
            if (!closed)
            {
                this.failWithError(AlertLevel.fatal, e.getAlertDescription(), "Failed to write record", e);
            }
            throw e;
        }
        catch (IOException e)
        {
            if (!closed)
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to write record", e);
            }
            throw e;
        }
        catch (RuntimeException e)
        {
            if (!closed)
            {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error, "Failed to write record", e);
            }
            throw e;
        }
    }

    /**
     * Send some application data to the remote system.
     * <p>
     * The method will handle fragmentation internally.
     * </p>
     * @param buf    The buffer with the data.
     * @param offset The position in the buffer where the data is placed.
     * @param len    The length of the data.
     * @throws IOException If something goes wrong during sending.
     */
    protected void writeData(byte[] buf, int offset, int len)
        throws IOException
    {
        if (this.closed)
        {
            if (this.failedWithError)
            {
                throw new IOException(TLS_ERROR_MESSAGE);
            }

            throw new IOException("Sorry, connection has been closed, you cannot write more data");
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
        
        inputBuffers.addBytes(input);

        // loop while there are enough bytes to read the length of the next record
        while (inputBuffers.available() >= RecordStream.TLS_HEADER_SIZE)
        {
            byte[] recordHeader = new byte[RecordStream.TLS_HEADER_SIZE];
            inputBuffers.peek(recordHeader);

            int totalLength = TlsUtils.readUint16(recordHeader, RecordStream.TLS_HEADER_LENGTH_OFFSET) + RecordStream.TLS_HEADER_SIZE;
            if (inputBuffers.available() < totalLength)
            {
                // not enough bytes to read a whole record
                safeCheckRecordHeader(recordHeader);
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
        
        try
        {
            return readApplicationData(buffer, offset, Math.min(length, applicationDataAvailable()));
        }
        catch (IOException e)
        {
            // readApplicationData() only throws if there is no data available, so this should never happen
            throw new RuntimeException(e.toString()); // early JDK fix.
        }
    }

    /**
     * Offer output from an arbitrary source. Only allowed in non-blocking mode.<br>
     * <br>
     * After this method returns, the specified section of the buffer will have been
     * processed. Use {@link #readOutput(byte[], int, int)} to get the bytes to
     * transmit to the other peer.<br>
     * <br>
     * This method must not be called until after the handshake is complete! Attempting
     * to call it before the handshake is complete will result in an exception.
     * @param buffer The buffer containing application data to encrypt
     * @param offset The offset at which to begin reading data
     * @param length The number of bytes of data to read
     * @throws IOException If an error occurs encrypting the data, or the handshake is not complete
     */
    public void offerOutput(byte[] buffer, int offset, int length)
            throws IOException
    {
        if (blocking)
        {
            throw new IllegalStateException("Cannot use offerOutput() in blocking mode! Use getOutputStream() instead.");
        }
        
        if (!appDataReady)
        {
            throw new IOException("Application data cannot be sent until the handshake is complete!");
        }
        
        writeData(buffer, offset, length);
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

    /**
     * Terminate this connection with an alert. Can be used for normal closure too.
     * 
     * @param alertLevel
     *            See {@link AlertLevel} for values.
     * @param alertDescription
     *            See {@link AlertDescription} for values.
     * @throws IOException
     *             If alert was fatal.
     */
    protected void failWithError(short alertLevel, short alertDescription, String message, Throwable cause)
        throws IOException
    {
        /*
         * Check if the connection is still open.
         */
        if (!closed)
        {
            /*
             * Prepare the message
             */
            this.closed = true;

            if (alertLevel == AlertLevel.fatal)
            {
                /*
                 * RFC 2246 7.2.1. The session becomes unresumable if any connection is terminated
                 * without proper close_notify messages with level equal to warning.
                 */
                // TODO This isn't quite in the right place. Also, as of TLS 1.1 the above is obsolete.
                invalidateSession();

                this.failedWithError = true;
            }
            raiseAlert(alertLevel, alertDescription, message, cause);
            recordStream.safeClose();
            if (alertLevel != AlertLevel.fatal)
            {
                return;
            }
        }

        throw new IOException(TLS_ERROR_MESSAGE);
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
    }

    protected void raiseAlert(short alertLevel, short alertDescription, String message, Throwable cause)
        throws IOException
    {
        getPeer().notifyAlertRaised(alertLevel, alertDescription, message, cause);

        byte[] error = new byte[2];
        error[0] = (byte)alertLevel;
        error[1] = (byte)alertDescription;

        safeWriteRecord(ContentType.alert, error, 0, 2);
    }

    protected void raiseWarning(short alertDescription, String message)
        throws IOException
    {
        raiseAlert(AlertLevel.warning, alertDescription, message, null);
    }

    protected void sendCertificateMessage(Certificate certificate)
        throws IOException
    {
        if (certificate == null)
        {
            certificate = Certificate.EMPTY_CHAIN;
        }

        if (certificate.isEmpty())
        {
            TlsContext context = getContext();
            if (!context.isServer())
            {
                ProtocolVersion serverVersion = getContext().getServerVersion();
                if (serverVersion.isSSL())
                {
                    String errorMessage = serverVersion.toString() + " client didn't provide credentials";
                    raiseWarning(AlertDescription.no_certificate, errorMessage);
                    return;
                }
            }
        }

        HandshakeMessage message = new HandshakeMessage(HandshakeType.certificate);

        certificate.encode(message);

        message.writeToRecordStream();
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
        TlsContext context = getContext();
        String asciiLabel = isServer ? ExporterLabel.server_finished : ExporterLabel.client_finished;
        byte[] sslSender = isServer ? TlsUtils.SSL_SERVER : TlsUtils.SSL_CLIENT;
        byte[] hash = getCurrentPRFHash(context, recordStream.getHandshakeHash(), sslSender);
        return TlsUtils.calculateVerifyData(context, asciiLabel, hash);
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

    protected void handleClose(boolean user_canceled)
        throws IOException
    {
        if (!closed)
        {
            if (user_canceled && !appDataReady)
            {
                raiseWarning(AlertDescription.user_canceled, "User canceled handshake");
            }
            this.failWithError(AlertLevel.warning, AlertDescription.close_notify, "Connection closed", null);
        }
    }

    protected void flush()
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
        /*
         * RFC 5746 4.5 SSLv3 clients that refuse renegotiation SHOULD use a fatal
         * handshake_failure alert.
         */
        if (TlsUtils.isSSL(getContext()))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        raiseWarning(AlertDescription.no_renegotiation, "Renegotiation not supported");
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

    protected static byte[] createRandomBlock(boolean useGMTUnixTime, RandomGenerator randomGenerator)
    {
        byte[] result = new byte[32];
        randomGenerator.nextBytes(result);

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
        byte[] pre_master_secret = keyExchange.generatePremasterSecret();

        try
        {
            context.getSecurityParameters().masterSecret = TlsUtils.calculateMasterSecret(context, pre_master_secret);
        }
        finally
        {
            // TODO Is there a way to ensure the data is really overwritten?
            /*
             * RFC 2246 8.1. The pre_master_secret should be deleted from memory once the
             * master_secret has been computed.
             */
            if (pre_master_secret != null)
            {
                Arrays.fill(pre_master_secret, (byte)0);
            }
        }
    }

    /**
     * 'sender' only relevant to SSLv3
     */
    protected static byte[] getCurrentPRFHash(TlsContext context, TlsHandshakeHash handshakeHash, byte[] sslSender)
    {
        Digest d = handshakeHash.forkPRFHash();

        if (sslSender != null && TlsUtils.isSSL(context))
        {
            d.update(sslSender, 0, sslSender.length);
        }

        byte[] bs = new byte[d.getDigestSize()];
        d.doFinal(bs, 0);
        return bs;
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

    protected static int getPRFAlgorithm(TlsContext context, int ciphersuite) throws IOException
    {
        boolean isTLSv12 = TlsUtils.isTLSv12(context);

        switch (ciphersuite)
        {
        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
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
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
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
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
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
