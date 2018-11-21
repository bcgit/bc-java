package org.bouncycastle.tls;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsNullNullCipher;

/**
 * An implementation of the TLS 1.0/1.1/1.2 record layer.
 */
class RecordStream
{
    private static int DEFAULT_PLAINTEXT_LIMIT = (1 << 14);

    private final Record inputRecord = new Record();

    private TlsProtocol handler;
    private InputStream input;
    private OutputStream output;
    private TlsContext context = null;
    private TlsCipher pendingCipher = null, readCipher = null, writeCipher = null;
    private SequenceNumber readSeqNo = new SequenceNumber(), writeSeqNo = new SequenceNumber();

    private TlsHandshakeHash handshakeHash = null;
    private SimpleOutputStream handshakeHashUpdater = new SimpleOutputStream()
    {
        public void write(byte[] buf, int off, int len) throws IOException
        {
            handshakeHash.update(buf, off, len);
        }
    };

    private ProtocolVersion writeVersion = null;

    private int plaintextLimit, ciphertextLimit;

    RecordStream(TlsProtocol handler, InputStream input, OutputStream output)
    {
        this.handler = handler;
        this.input = input;
        this.output = output;
    }

    void init(TlsContext context)
    {
        this.context = context;
        this.readCipher = new TlsNullNullCipher();
        this.writeCipher = this.readCipher;
        this.handshakeHash = new DeferredHash(context);

        setPlaintextLimit(DEFAULT_PLAINTEXT_LIMIT);
    }

    int getPlaintextLimit()
    {
        return plaintextLimit;
    }

    void setPlaintextLimit(int plaintextLimit)
    {
        this.plaintextLimit = plaintextLimit;
        this.ciphertextLimit = this.plaintextLimit + 1024;
    }

    void setWriteVersion(ProtocolVersion writeVersion)
    {
        this.writeVersion = writeVersion;
    }

    void setPendingConnectionState(TlsCipher tlsCipher)
    {
        this.pendingCipher = tlsCipher;
    }

    void sentWriteCipherSpec()
        throws IOException
    {
        if (pendingCipher == null)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        this.writeCipher = this.pendingCipher;
        this.writeSeqNo = new SequenceNumber();
    }

    void receivedReadCipherSpec()
        throws IOException
    {
        if (pendingCipher == null)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        this.readCipher = this.pendingCipher;
        this.readSeqNo = new SequenceNumber();
    }

    void finaliseHandshake()
        throws IOException
    {
        if (readCipher != pendingCipher || writeCipher != pendingCipher)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        this.pendingCipher = null;
        this.handshakeHash = new DeferredHash(context);
    }

    RecordPreview previewRecordHeader(byte[] recordHeader, boolean appDataReady) throws IOException
    {
        short type = TlsUtils.readUint8(recordHeader, RecordFormat.TYPE_OFFSET);

        if (!appDataReady && type == ContentType.application_data)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        /*
         * RFC 5246 6. If a TLS implementation receives an unexpected record type, it MUST send an
         * unexpected_message alert.
         */
        checkType(type, AlertDescription.unexpected_message);

        /*
         * legacy_record_version (2 octets at RecordFormat.VERSION_OFFSET) is ignored.
         */

        int length = TlsUtils.readUint16(recordHeader, RecordFormat.LENGTH_OFFSET);

        checkLength(length, ciphertextLimit, AlertDescription.record_overflow);

        int recordSize = RecordFormat.FRAGMENT_OFFSET + length;
        int applicationDataLimit = 0;

        if (type == ContentType.application_data)
        {
            applicationDataLimit = Math.min(getPlaintextLimit(), readCipher.getPlaintextLimit(length));
        }

        return new RecordPreview(recordSize, applicationDataLimit);
    }

    RecordPreview previewOutputRecord(int applicationDataSize)
    {
        int applicationDataLimit = Math.max(0, Math.min(getPlaintextLimit(), applicationDataSize));

        int recordSize = writeCipher.getCiphertextLimit(applicationDataLimit) + RecordFormat.FRAGMENT_OFFSET;

        return new RecordPreview(recordSize, applicationDataLimit);
    }

    boolean readFullRecord(byte[] input, int inputOff, int inputLen)
        throws IOException
    {
        if (inputLen < RecordFormat.FRAGMENT_OFFSET)
        {
            return false;
        }

        int length = TlsUtils.readUint16(input, inputOff + RecordFormat.LENGTH_OFFSET);
        if (inputLen != (RecordFormat.FRAGMENT_OFFSET + length))
        {
            return false;
        }

        short type = TlsUtils.readUint8(input, inputOff + RecordFormat.TYPE_OFFSET);

        /*
         * RFC 5246 6. If a TLS implementation receives an unexpected record type, it MUST send an
         * unexpected_message alert.
         */
        checkType(type, AlertDescription.unexpected_message);

        /*
         * legacy_record_version (2 octets at RecordFormat.VERSION_OFFSET) is ignored.
         */

        checkLength(length, ciphertextLimit, AlertDescription.record_overflow);

        byte[] plaintext = decodeAndVerify(type, input, inputOff + RecordFormat.FRAGMENT_OFFSET, length);
        handler.processRecord(type, plaintext, 0, plaintext.length);
        return true;
    }

    boolean readRecord()
        throws IOException
    {
        if (!inputRecord.readHeader(input))
        {
            return false;
        }

        short type = TlsUtils.readUint8(inputRecord.buf, RecordFormat.TYPE_OFFSET);

        /*
         * RFC 5246 6. If a TLS implementation receives an unexpected record type, it MUST send an
         * unexpected_message alert.
         */
        checkType(type, AlertDescription.unexpected_message);

        /*
         * legacy_record_version (2 octets at RecordFormat.VERSION_OFFSET) is ignored.
         */

        int length = TlsUtils.readUint16(inputRecord.buf, RecordFormat.LENGTH_OFFSET);

        checkLength(length, ciphertextLimit, AlertDescription.record_overflow);

        inputRecord.readFragment(input, length);

        byte[] plaintext;
        try
        {
            plaintext = decodeAndVerify(type, inputRecord.buf, RecordFormat.FRAGMENT_OFFSET, length);
        }
        finally
        {
            inputRecord.reset();
        }

        handler.processRecord(type, plaintext, 0, plaintext.length);
        return true;
    }

    byte[] decodeAndVerify(short type, byte[] ciphertext, int off, int len)
        throws IOException
    {
        long seqNo = readSeqNo.nextValue(AlertDescription.unexpected_message);
        byte[] decoded = readCipher.decodeCiphertext(seqNo, type, ciphertext, off, len);

        checkLength(decoded.length, plaintextLimit, AlertDescription.record_overflow);

        /*
         * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
         * or ChangeCipherSpec content types.
         */
        if (decoded.length < 1 && type != ContentType.application_data)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return decoded;
    }

    void writeRecord(short type, byte[] plaintext, int plaintextOffset, int plaintextLength)
        throws IOException
    {
        // Never send anything until a valid ClientHello has been received
        if (writeVersion == null)
        {
            return;
        }

        /*
         * RFC 5246 6. Implementations MUST NOT send record types not defined in this document
         * unless negotiated by some extension.
         */
        checkType(type, AlertDescription.internal_error);

        /*
         * RFC 5246 6.2.1 The length should not exceed 2^14.
         */
        checkLength(plaintextLength, plaintextLimit, AlertDescription.internal_error);

        /*
         * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
         * or ChangeCipherSpec content types.
         */
        if (plaintextLength < 1 && type != ContentType.application_data)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        long seqNo = writeSeqNo.nextValue(AlertDescription.internal_error);

        byte[] ciphertext = writeCipher.encodePlaintext(seqNo, type, plaintext, plaintextOffset, plaintextLength);

        /*
         * RFC 5246 6.2.3. The length may not exceed 2^14 + 2048.
         */
        checkLength(ciphertext.length, ciphertextLimit, AlertDescription.internal_error);

        byte[] record = new byte[RecordFormat.FRAGMENT_OFFSET + ciphertext.length];
        TlsUtils.writeUint8(type, record, RecordFormat.TYPE_OFFSET);
        TlsUtils.writeVersion(writeVersion, record, RecordFormat.VERSION_OFFSET);
        TlsUtils.writeUint16(ciphertext.length, record, RecordFormat.LENGTH_OFFSET);
        System.arraycopy(ciphertext, 0, record, RecordFormat.FRAGMENT_OFFSET, ciphertext.length);

        try
        {
            output.write(record);
        }
        catch (InterruptedIOException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        output.flush();
    }

    void notifyHelloComplete()
    {
        this.handshakeHash = handshakeHash.notifyPRFDetermined();
    }

    TlsHandshakeHash getHandshakeHash()
    {
        return handshakeHash;
    }

    OutputStream getHandshakeHashUpdater()
    {
        return handshakeHashUpdater;
    }

    TlsHandshakeHash prepareToFinish()
    {
        TlsHandshakeHash result = handshakeHash;
        this.handshakeHash = handshakeHash.stopTracking();
        return result;
    }

    void close() throws IOException
    {
        inputRecord.reset();

        IOException io = null;
        try
        {
            input.close();
        }
        catch (IOException e)
        {
            io = e;
        }

        try
        {
            output.close();
        }
        catch (IOException e)
        {
            if (io == null)
            {
                io = e;
            }
            else
            {
                // TODO[tls] Available from JDK 7
//                io.addSuppressed(e);
            }
        }

        if (io != null)
        {
            throw io;
        }
    }

    void flush()
        throws IOException
    {
        output.flush();
    }

    private static void checkType(short type, short alertDescription)
        throws IOException
    {
        switch (type)
        {
        case ContentType.application_data:
        case ContentType.alert:
        case ContentType.change_cipher_spec:
        case ContentType.handshake:
//        case ContentType.heartbeat:
            break;
        default:
            throw new TlsFatalAlert(alertDescription);
        }
    }

    private static void checkLength(int length, int limit, short alertDescription)
        throws IOException
    {
        if (length > limit)
        {
            throw new TlsFatalAlert(alertDescription);
        }
    }

    private static class Record
    {
        private final byte[] header = new byte[RecordFormat.FRAGMENT_OFFSET];

        volatile byte[] buf = header;
        volatile int pos = 0;

        void fillTo(InputStream input, int length) throws IOException
        {
            while (pos < length)
            {
                try
                {
                    int numRead = input.read(buf, pos, length - pos);
                    if (numRead < 0)
                    {
                        break;
                    }
                    pos += numRead;
                }
                catch (InterruptedIOException e)
                {
                    /*
                     * Although modifying the bytesTransferred doesn't seem ideal, it's the simplest
                     * way to make sure we don't break client code that depends on the exact type,
                     * e.g. in Apache's httpcomponents-core-4.4.9, BHttpConnectionBase.isStale
                     * depends on the exception type being SocketTimeoutException (or a subclass).
                     *
                     * We can set to 0 here because the only relevant callstack (via
                     * TlsProtocol.readApplicationData) only ever processes one non-empty record (so
                     * interruption after partial output cannot occur).
                     */
                    pos += e.bytesTransferred;
                    e.bytesTransferred = 0;
                    throw e;
                }
            }
        }

        void readFragment(InputStream input, int fragmentLength) throws IOException
        {
            int recordLength = RecordFormat.FRAGMENT_OFFSET + fragmentLength;
            resize(recordLength);
            fillTo(input, recordLength);
            if (pos < recordLength)
            {
                throw new EOFException();
            }
        }

        boolean readHeader(InputStream input) throws IOException
        {
            fillTo(input, RecordFormat.FRAGMENT_OFFSET);
            if (pos == 0)
            {
                return false;
            }
            if (pos < RecordFormat.FRAGMENT_OFFSET)
            {
                throw new EOFException();
            }
            return true;
        }

        void reset()
        {
            buf = header;
            pos = 0;
        }

        private void resize(int length)
        {
            if (buf.length < length)
            {
                byte[] tmp = new byte[length];
                System.arraycopy(buf, 0, tmp, 0, pos);
                buf = tmp;
            }
        }
    }

    private static class SequenceNumber
    {
        private long value = 0L;
        private boolean exhausted = false;

        synchronized long nextValue(short alertDescription) throws TlsFatalAlert
        {
            if (exhausted)
            {
                throw new TlsFatalAlert(alertDescription);
            }
            long result = value;
            if (++value == 0)
            {
                exhausted = true;
            }
            return result;
        }
    }
}
