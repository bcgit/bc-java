package org.bouncycastle.tls;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsNullNullCipher;

/**
 * An implementation of the TLS 1.0/1.1/1.2 record layer.
 */
class RecordStream
{
    private static int DEFAULT_PLAINTEXT_LIMIT = (1 << 14);

    private final Record inputRecord = new Record();
    private final SequenceNumber readSeqNo = new SequenceNumber(), writeSeqNo = new SequenceNumber();

    private TlsProtocol handler;
    private InputStream input;
    private OutputStream output;
    private TlsCipher pendingCipher = null;
    private TlsCipher readCipher = TlsNullNullCipher.INSTANCE;
    private TlsCipher readCipherDeferred = null;
    private TlsCipher writeCipher = TlsNullNullCipher.INSTANCE;

    private ProtocolVersion writeVersion = null;

    private int plaintextLimit = DEFAULT_PLAINTEXT_LIMIT;
    private int ciphertextLimit = DEFAULT_PLAINTEXT_LIMIT;
    private boolean ignoreChangeCipherSpec = false;

    RecordStream(TlsProtocol handler, InputStream input, OutputStream output)
    {
        this.handler = handler;
        this.input = input;
        this.output = output;
    }

    int getPlaintextLimit()
    {
        return plaintextLimit;
    }

    void setPlaintextLimit(int plaintextLimit)
    {
        this.plaintextLimit = plaintextLimit;
        this.ciphertextLimit = readCipher.getCiphertextDecodeLimit(plaintextLimit);
    }

    void setWriteVersion(ProtocolVersion writeVersion)
    {
        this.writeVersion = writeVersion;
    }

    void setIgnoreChangeCipherSpec(boolean ignoreChangeCipherSpec)
    {
        this.ignoreChangeCipherSpec = ignoreChangeCipherSpec;
    }

    void setPendingCipher(TlsCipher tlsCipher)
    {
        this.pendingCipher = tlsCipher;
    }

    void notifyChangeCipherSpecReceived()
        throws IOException
    {
        if (pendingCipher == null)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        enablePendingCipherRead(false);
    }

    void enablePendingCipherRead(boolean deferred)
        throws IOException
    {
        if (pendingCipher == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        if (readCipherDeferred != null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        if (deferred)
        {
            this.readCipherDeferred = pendingCipher;
        }
        else
        {
            this.readCipher = pendingCipher;
            this.ciphertextLimit = readCipher.getCiphertextDecodeLimit(plaintextLimit);
            readSeqNo.reset();
        }
    }

    void enablePendingCipherWrite()
        throws IOException
    {
        if (pendingCipher == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        this.writeCipher = this.pendingCipher;
        writeSeqNo.reset();
    }

    void finaliseHandshake()
        throws IOException
    {
        if (readCipher != pendingCipher || writeCipher != pendingCipher)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        this.pendingCipher = null;
    }

    boolean needsKeyUpdate()
    {
        return writeSeqNo.currentValue() >= (1L << 20);
    }

    void notifyKeyUpdateReceived() throws IOException
    {
        readCipher.rekeyDecoder();
        readSeqNo.reset();
    }

    void notifyKeyUpdateSent() throws IOException
    {
        writeCipher.rekeyEncoder();
        writeSeqNo.reset();
    }

    RecordPreview previewRecordHeader(byte[] recordHeader) throws IOException
    {
        short recordType = checkRecordType(recordHeader, RecordFormat.TYPE_OFFSET);

//        ProtocolVersion recordVersion = TlsUtils.readVersion(recordHeader, RecordFormat.VERSION_OFFSET);

        int length = TlsUtils.readUint16(recordHeader, RecordFormat.LENGTH_OFFSET);

        checkLength(length, ciphertextLimit, AlertDescription.record_overflow);

        int recordSize = RecordFormat.FRAGMENT_OFFSET + length;
        int applicationDataLimit = 0;

        // NOTE: For TLS 1.3, this only MIGHT be application data
        if (ContentType.application_data == recordType && handler.isApplicationDataReady())
        {
            applicationDataLimit = Math.max(0, Math.min(plaintextLimit, readCipher.getPlaintextLimit(length)));
        }

        return new RecordPreview(recordSize, applicationDataLimit);
    }

    RecordPreview previewOutputRecord(int contentLength)
    {
        int contentLimit = Math.max(0, Math.min(plaintextLimit, contentLength));
        int recordSize = previewOutputRecordSize(contentLimit);
        return new RecordPreview(recordSize, contentLimit);
    }

    int previewOutputRecordSize(int contentLength)
    {
//        assert contentLength <= plaintextLimit
        return RecordFormat.FRAGMENT_OFFSET + writeCipher.getCiphertextEncodeLimit(contentLength, plaintextLimit);
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

        short recordType = checkRecordType(input, inputOff + RecordFormat.TYPE_OFFSET);

        ProtocolVersion recordVersion = TlsUtils.readVersion(input, inputOff + RecordFormat.VERSION_OFFSET);

        checkLength(length, ciphertextLimit, AlertDescription.record_overflow);

        if (ignoreChangeCipherSpec && ContentType.change_cipher_spec == recordType)
        {
            checkChangeCipherSpec(input, inputOff + RecordFormat.FRAGMENT_OFFSET, length);
            return true;
        }

        TlsDecodeResult decoded = decodeAndVerify(recordType, recordVersion, input,
            inputOff + RecordFormat.FRAGMENT_OFFSET, length);

        handler.processRecord(decoded.contentType, decoded.buf, decoded.off, decoded.len);
        return true;
    }

    boolean readRecord()
        throws IOException
    {
        if (!inputRecord.readHeader(input))
        {
            return false;
        }

        short recordType = checkRecordType(inputRecord.buf, RecordFormat.TYPE_OFFSET);

        ProtocolVersion recordVersion = TlsUtils.readVersion(inputRecord.buf, RecordFormat.VERSION_OFFSET);

        int length = TlsUtils.readUint16(inputRecord.buf, RecordFormat.LENGTH_OFFSET);

        checkLength(length, ciphertextLimit, AlertDescription.record_overflow);

        inputRecord.readFragment(input, length);

        TlsDecodeResult decoded;
        try
        {
            if (ignoreChangeCipherSpec && ContentType.change_cipher_spec == recordType)
            {
                checkChangeCipherSpec(inputRecord.buf, RecordFormat.FRAGMENT_OFFSET, length);
                return true;
            }

            decoded = decodeAndVerify(recordType, recordVersion, inputRecord.buf, RecordFormat.FRAGMENT_OFFSET, length);
        }
        finally
        {
            inputRecord.reset();
        }

        handler.processRecord(decoded.contentType, decoded.buf, decoded.off, decoded.len);
        return true;
    }

    TlsDecodeResult decodeAndVerify(short recordType, ProtocolVersion recordVersion, byte[] ciphertext, int off, int len)
        throws IOException
    {
        long seqNo = readSeqNo.nextValue(AlertDescription.unexpected_message);
        TlsDecodeResult decoded = readCipher.decodeCiphertext(seqNo, recordType, recordVersion, ciphertext, off, len);

        checkLength(decoded.len, plaintextLimit, AlertDescription.record_overflow);

        /*
         * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
         * or ChangeCipherSpec content types.
         */
        if (decoded.len < 1 && decoded.contentType != ContentType.application_data)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return decoded;
    }

    void writeRecord(short contentType, byte[] plaintext, int plaintextOffset, int plaintextLength)
        throws IOException
    {
        // Never send anything until a valid ClientHello has been received
        if (writeVersion == null)
        {
            return;
        }

        /*
         * RFC 5246 6.2.1 The length should not exceed 2^14.
         */
        checkLength(plaintextLength, plaintextLimit, AlertDescription.internal_error);

        /*
         * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
         * or ChangeCipherSpec content types.
         */
        if (plaintextLength < 1 && contentType != ContentType.application_data)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        long seqNo = writeSeqNo.nextValue(AlertDescription.internal_error);
        ProtocolVersion recordVersion = writeVersion;

        TlsEncodeResult encoded = writeCipher.encodePlaintext(seqNo, contentType, recordVersion,
            RecordFormat.FRAGMENT_OFFSET, plaintext, plaintextOffset, plaintextLength);

        int ciphertextLength = encoded.len - RecordFormat.FRAGMENT_OFFSET;
        TlsUtils.checkUint16(ciphertextLength);

        TlsUtils.writeUint8(encoded.recordType, encoded.buf, encoded.off + RecordFormat.TYPE_OFFSET);
        TlsUtils.writeVersion(recordVersion, encoded.buf, encoded.off + RecordFormat.VERSION_OFFSET);
        TlsUtils.writeUint16(ciphertextLength, encoded.buf, encoded.off + RecordFormat.LENGTH_OFFSET);

        try
        {
            output.write(encoded.buf, encoded.off, encoded.len);
        }
        catch (InterruptedIOException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }

        output.flush();
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

    private void checkChangeCipherSpec(byte[] buf, int off, int len)
        throws IOException
    {
        if (1 != len || (byte)ChangeCipherSpec.change_cipher_spec != buf[off])
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    private short checkRecordType(byte[] buf, int off)
        throws IOException
    {
        short recordType = TlsUtils.readUint8(buf, off);

        if (null != readCipherDeferred && recordType == ContentType.application_data)
        {
            this.readCipher = readCipherDeferred;
            this.readCipherDeferred = null;
            this.ciphertextLimit = readCipher.getCiphertextDecodeLimit(plaintextLimit);
            readSeqNo.reset();
        }
        else if (readCipher.usesOpaqueRecordType())
        {
            if (ContentType.application_data != recordType)
            {
                if (ignoreChangeCipherSpec && ContentType.change_cipher_spec == recordType)
                {
                    // See RFC 8446 D.4.
                }
                else
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message, ContentType.getText(recordType));
                }
            }
        }
        else
        {
            switch (recordType)
            {
            case ContentType.application_data:
            {
                if (!handler.isApplicationDataReady())
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
                break;
            }
            case ContentType.alert:
            case ContentType.change_cipher_spec:
            case ContentType.handshake:
    //        case ContentType.heartbeat:
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        return recordType;
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

        synchronized long currentValue()
        {
            return value;
        }

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

        synchronized void reset()
        {
            this.value = 0L;
            this.exhausted = false;
        }
    }
}
