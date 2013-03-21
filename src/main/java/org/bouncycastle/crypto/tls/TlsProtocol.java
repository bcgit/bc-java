package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/**
 * An implementation of all high level protocols in TLS 1.0/1.1.
 */
public abstract class TlsProtocol {

    protected static final Integer EXT_RenegotiationInfo = Integers
        .valueOf(ExtensionType.renegotiation_info);

    protected static final byte[] emptybuf = new byte[0];

    protected static final String TLS_ERROR_MESSAGE = "Internal TLS error, this could be an attack";

    /*
     * Our Connection states
     */
    protected static final short CS_START = 0;
    protected static final short CS_CLIENT_HELLO = 1;
    protected static final short CS_SERVER_HELLO = 2;
    protected static final short CS_SERVER_CERTIFICATE = 3;
    protected static final short CS_SERVER_KEY_EXCHANGE = 4;
    protected static final short CS_CERTIFICATE_REQUEST = 5;
    protected static final short CS_SERVER_HELLO_DONE = 6;
    protected static final short CS_CLIENT_CERTIFICATE = 7;
    protected static final short CS_CLIENT_KEY_EXCHANGE = 8;
    protected static final short CS_CERTIFICATE_VERIFY = 9;
    protected static final short CS_CLIENT_CHANGE_CIPHER_SPEC = 10;
    protected static final short CS_CLIENT_FINISHED = 11;
    protected static final short CS_SERVER_CHANGE_CIPHER_SPEC = 12;
    protected static final short CS_SERVER_FINISHED = 13;

    /*
     * Queues for data from some protocols.
     */
    private ByteQueue applicationDataQueue = new ByteQueue();
    private ByteQueue changeCipherSpecQueue = new ByteQueue();
    private ByteQueue alertQueue = new ByteQueue();
    private ByteQueue handshakeQueue = new ByteQueue();

    /*
     * The Record Stream we use
     */
    protected RecordStream rs;
    protected SecureRandom random;

    private TlsInputStream tlsInputStream = null;
    private TlsOutputStream tlsOutputStream = null;

    private volatile boolean closed = false;
    private volatile boolean failedWithError = false;
    private volatile boolean appDataReady = false;

    protected SecurityParameters securityParameters = null;

    protected short connection_state = CS_START;
    protected boolean secure_renegotiation = false;

    public TlsProtocol(InputStream is, OutputStream os, SecureRandom sr) {
        this.rs = new RecordStream(this, is, os);
        this.random = sr;
    }

    protected abstract TlsContext getContext();

    protected abstract void handleChangeCipherSpecMessage() throws IOException;

    protected abstract void handleHandshakeMessage(short type, byte[] buf) throws IOException;

    protected void handleWarningMessage(short description) {

    }

    protected void enableApplicationData() {
        /*
         * We are now ready to send and receive application data.
         */
        if (!appDataReady) {
            this.appDataReady = true;

            this.tlsInputStream = new TlsInputStream(this);
            this.tlsOutputStream = new TlsOutputStream(this);
        }
    }

    protected void processRecord(short protocol, byte[] buf, int offset, int len)
        throws IOException {
        /*
         * Have a look at the protocol type, and add it to the correct queue.
         */
        switch (protocol) {
        case ContentType.change_cipher_spec:
            changeCipherSpecQueue.addData(buf, offset, len);
            processChangeCipherSpec();
            break;
        case ContentType.alert:
            alertQueue.addData(buf, offset, len);
            processAlert();
            break;
        case ContentType.handshake:
            handshakeQueue.addData(buf, offset, len);
            processHandshake();
            break;
        case ContentType.application_data:
            if (!appDataReady) {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            applicationDataQueue.addData(buf, offset, len);
            processApplicationData();
            break;
        default:
            /*
             * Uh, we don't know this protocol.
             * 
             * RFC2246 defines on page 13, that we should ignore this.
             */
        }
    }

    private void processHandshake() throws IOException {
        boolean read;
        do {
            read = false;
            /*
             * We need the first 4 bytes, they contain type and length of the message.
             */
            if (handshakeQueue.size() >= 4) {
                byte[] beginning = new byte[4];
                handshakeQueue.read(beginning, 0, 4, 0);
                ByteArrayInputStream bis = new ByteArrayInputStream(beginning);
                short type = TlsUtils.readUint8(bis);
                int len = TlsUtils.readUint24(bis);

                /*
                 * Check if we have enough bytes in the buffer to read the full message.
                 */
                if (handshakeQueue.size() >= (len + 4)) {
                    /*
                     * Read the message.
                     */
                    byte[] buf = new byte[len];
                    handshakeQueue.read(buf, 0, len, 4);
                    handshakeQueue.removeData(len + 4);

                    /*
                     * RFC 2246 7.4.9. The value handshake_messages includes all handshake messages
                     * starting at client hello up to, but not including, this finished message.
                     * [..] Note: [Also,] Hello Request messages are omitted from handshake hashes.
                     */
                    switch (type) {
                    case HandshakeType.hello_request:
                    case HandshakeType.finished:
                        break;
                    default:
                        rs.updateHandshakeData(beginning, 0, 4);
                        rs.updateHandshakeData(buf, 0, len);
                        break;
                    }

                    /*
                     * Now, parse the message.
                     */
                    handleHandshakeMessage(type, buf);
                    read = true;
                }
            }
        } while (read);
    }

    private void processApplicationData() {
        /*
         * There is nothing we need to do here.
         * 
         * This function could be used for callbacks when application data arrives in the future.
         */
    }

    private void processAlert() throws IOException {
        while (alertQueue.size() >= 2) {
            /*
             * An alert is always 2 bytes. Read the alert.
             */
            byte[] tmp = new byte[2];
            alertQueue.read(tmp, 0, 2, 0);
            alertQueue.removeData(2);
            short level = tmp[0];
            short description = tmp[1];
            if (level == AlertLevel.fatal) {
                /*
                 * This is a fatal error.
                 */
                this.failedWithError = true;
                this.closed = true;
                /*
                 * Now try to close the stream, ignore errors.
                 */
                try {
                    rs.close();
                } catch (Exception e) {

                }
                throw new IOException(TLS_ERROR_MESSAGE);
            } else {
                /*
                 * This is just a warning.
                 */
                if (description == AlertDescription.close_notify) {
                    /*
                     * Close notify
                     */
                    this.failWithError(AlertLevel.warning, AlertDescription.close_notify);
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
     * @throws IOException
     *             If the message has an invalid content or the handshake is not in the correct
     *             state.
     */
    private void processChangeCipherSpec() throws IOException {
        while (changeCipherSpecQueue.size() > 0) {
            /*
             * A change cipher spec message is only one byte with the value 1.
             */
            byte[] b = new byte[1];
            changeCipherSpecQueue.read(b, 0, 1, 0);
            changeCipherSpecQueue.removeData(1);
            if (b[0] != 1) {
                /*
                 * This should never happen.
                 */
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }

            handleChangeCipherSpecMessage();
        }
    }

    /**
     * Read data from the network. The method will return immediately, if there is still some data
     * left in the buffer, or block until some application data has been read from the network.
     * 
     * @param buf
     *            The buffer where the data will be copied to.
     * @param offset
     *            The position where the data will be placed in the buffer.
     * @param len
     *            The maximum number of bytes to read.
     * @return The number of bytes read.
     * @throws IOException
     *             If something goes wrong during reading data.
     */
    protected int readApplicationData(byte[] buf, int offset, int len) throws IOException {
        while (applicationDataQueue.size() == 0) {
            /*
             * We need to read some data.
             */
            if (this.closed) {
                if (this.failedWithError) {
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
        len = Math.min(len, applicationDataQueue.size());
        applicationDataQueue.read(buf, offset, len, 0);
        applicationDataQueue.removeData(len);
        return len;
    }

    protected void safeReadRecord() throws IOException {
        try {
            rs.readRecord();
        } catch (TlsFatalAlert e) {
            if (!this.closed) {
                this.failWithError(AlertLevel.fatal, e.getAlertDescription());
            }
            throw e;
        } catch (IOException e) {
            if (!this.closed) {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
            }
            throw e;
        } catch (RuntimeException e) {
            if (!this.closed) {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
            }
            throw e;
        }
    }

    protected void safeWriteRecord(short type, byte[] buf, int offset, int len) throws IOException {
        try {
            rs.writeRecord(type, buf, offset, len);
        } catch (TlsFatalAlert e) {
            if (!this.closed) {
                this.failWithError(AlertLevel.fatal, e.getAlertDescription());
            }
            throw e;
        } catch (IOException e) {
            if (!closed) {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
            }
            throw e;
        } catch (RuntimeException e) {
            if (!closed) {
                this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
            }
            throw e;
        }
    }

    /**
     * Send some application data to the remote system.
     * <p/>
     * The method will handle fragmentation internally.
     * 
     * @param buf
     *            The buffer with the data.
     * @param offset
     *            The position in the buffer where the data is placed.
     * @param len
     *            The length of the data.
     * @throws IOException
     *             If something goes wrong during sending.
     */
    protected void writeData(byte[] buf, int offset, int len) throws IOException {
        if (this.closed) {
            if (this.failedWithError) {
                throw new IOException(TLS_ERROR_MESSAGE);
            }

            throw new IOException("Sorry, connection has been closed, you cannot write more data");
        }

        /*
         * Protect against known IV attack!
         * 
         * DO NOT REMOVE THIS LINE, EXCEPT YOU KNOW EXACTLY WHAT YOU ARE DOING HERE.
         */
        safeWriteRecord(ContentType.application_data, emptybuf, 0, 0);

        do {
            /*
             * We are only allowed to write fragments up to 2^14 bytes.
             */
            int toWrite = Math.min(len, 1 << 14);

            safeWriteRecord(ContentType.application_data, buf, offset, toWrite);

            offset += toWrite;
            len -= toWrite;
        } while (len > 0);

    }

    /**
     * @return An OutputStream which can be used to send data.
     */
    public OutputStream getOutputStream() {
        return this.tlsOutputStream;
    }

    /**
     * @return An InputStream which can be used to read data.
     */
    public InputStream getInputStream() {
        return this.tlsInputStream;
    }

    /**
     * Terminate this connection with an alert.
     * <p/>
     * Can be used for normal closure too.
     * 
     * @param alertLevel
     *            The level of the alert, an be AlertLevel.fatal or AL_warning.
     * @param alertDescription
     *            The exact alert message.
     * @throws IOException
     *             If alert was fatal.
     */
    protected void failWithError(short alertLevel, short alertDescription) throws IOException {
        /*
         * Check if the connection is still open.
         */
        if (!closed) {
            /*
             * Prepare the message
             */
            this.closed = true;

            if (alertLevel == AlertLevel.fatal) {
                /*
                 * This is a fatal message.
                 */
                this.failedWithError = true;
            }
            sendAlert(alertLevel, alertDescription);
            rs.close();
            if (alertLevel == AlertLevel.fatal) {
                throw new IOException(TLS_ERROR_MESSAGE);
            }
        } else {
            throw new IOException(TLS_ERROR_MESSAGE);
        }
    }

    protected void processFinishedMessage(ByteArrayInputStream buf) throws IOException {
        TlsContext context = getContext();

        /*
         * Read the checksum from the finished message, it has always 12 bytes for TLS 1.0 and 36
         * for SSLv3.
         */
        int checksumLength = context.getServerVersion().isSSL() ? 36 : 12;
        byte[] verify_data = new byte[checksumLength];
        TlsUtils.readFully(verify_data, buf);

        assertEmpty(buf);

        /*
         * Calculate our own checksum.
         */
        byte[] expected_verify_data = createVerifyData(!getContext().isServer());

        /*
         * Compare both checksums.
         */
        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data)) {
            /*
             * Wrong checksum in the finished message.
             */
            this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
        }
    }

    protected void sendAlert(short alertLevel, short alertDescription) throws IOException {
        byte[] error = new byte[2];
        error[0] = (byte) alertLevel;
        error[1] = (byte) alertDescription;

        safeWriteRecord(ContentType.alert, error, 0, 2);
    }

    protected void sendCertificateMessage(Certificate certificate) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.certificate, bos);

        // Reserve space for length
        TlsUtils.writeUint24(0, bos);

        certificate.encode(bos);
        byte[] message = bos.toByteArray();

        // Patch actual length back in
        TlsUtils.writeUint24(message.length - 4, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendChangeCipherSpecMessage() throws IOException {
        byte[] message = new byte[] { 1 };
        safeWriteRecord(ContentType.change_cipher_spec, message, 0, message.length);
    }

    protected void sendFinishedMessage() throws IOException {
        byte[] verify_data = createVerifyData(getContext().isServer());

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.finished, bos);
        TlsUtils.writeUint24(verify_data.length, bos);
        bos.write(verify_data);
        byte[] message = bos.toByteArray();

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected byte[] createVerifyData(boolean isServer) {
        TlsContext context = getContext();

        if (isServer) {
            return TlsUtils.calculateVerifyData(context, "server finished",
                rs.getCurrentHash(TlsUtils.SSL_SERVER));
        }

        return TlsUtils.calculateVerifyData(context, "client finished",
            rs.getCurrentHash(TlsUtils.SSL_CLIENT));
    }

    /**
     * Closes this connection.
     * 
     * @throws IOException
     *             If something goes wrong during closing.
     */
    public void close() throws IOException {
        if (!closed) {
            this.failWithError(AlertLevel.warning, AlertDescription.close_notify);
        }
    }

    protected void flush() throws IOException {
        rs.flush();
    }

    protected static boolean arrayContains(short[] a, short n) {
        for (int i = 0; i < a.length; ++i) {
            if (a[i] == n) {
                return true;
            }
        }
        return false;
    }

    protected static boolean arrayContains(int[] a, int n) {
        for (int i = 0; i < a.length; ++i) {
            if (a[i] == n) {
                return true;
            }
        }
        return false;
    }

    /**
     * Make sure the InputStream is now empty. Fail otherwise.
     * 
     * @param is
     *            The InputStream to check.
     * @throws IOException
     *             If is is not empty.
     */
    protected static void assertEmpty(ByteArrayInputStream is) throws IOException {
        if (is.available() > 0) {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
    }

    protected static byte[] createRenegotiationInfo(byte[] renegotiated_connection) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeOpaque8(renegotiated_connection, buf);
        return buf.toByteArray();
    }

    protected static Hashtable readExtensions(ByteArrayInputStream buf) throws IOException {

        if (buf.available() < 1) {
            return null;
        }

        byte[] extBytes = TlsUtils.readOpaque16(buf);

        // Integer -> byte[]
        Hashtable extensions = new Hashtable();

        ByteArrayInputStream ext = new ByteArrayInputStream(extBytes);
        while (ext.available() > 0) {
            Integer extType = Integers.valueOf(TlsUtils.readUint16(ext));
            byte[] extValue = TlsUtils.readOpaque16(ext);

            /*
             * RFC 3546 2.3 There MUST NOT be more than one extension of the same type.
             */
            if (extensions.containsKey(extType)) {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            extensions.put(extType, extValue);
        }

        return extensions;
    }

    protected static void writeExtensions(OutputStream output, Hashtable extensions) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        Enumeration keys = extensions.keys();
        while (keys.hasMoreElements()) {
            Integer extType = (Integer) keys.nextElement();
            byte[] extValue = (byte[]) extensions.get(extType);

            TlsUtils.writeUint16(extType.intValue(), output);
            TlsUtils.writeOpaque16(extValue, buf);
        }

        TlsUtils.writeOpaque16(buf.toByteArray(), output);
    }
}
