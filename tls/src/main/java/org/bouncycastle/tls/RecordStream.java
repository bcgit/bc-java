package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
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
    private TlsCompression pendingCompression = null, readCompression = null, writeCompression = null;
    private TlsCipher pendingCipher = null, readCipher = null, writeCipher = null;
    private SequenceNumber readSeqNo = new SequenceNumber(), writeSeqNo = new SequenceNumber();
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private TlsHandshakeHash handshakeHash = null;
    private SimpleOutputStream handshakeHashUpdater = new SimpleOutputStream()
    {
        public void write(byte[] buf, int off, int len) throws IOException
        {
            handshakeHash.update(buf, off, len);
        }
    };

    private ProtocolVersion readVersion = null, writeVersion = null;
    private boolean restrictReadVersion = true;

    private int plaintextLimit, compressedLimit, ciphertextLimit;

    RecordStream(TlsProtocol handler, InputStream input, OutputStream output)
    {
        this.handler = handler;
        this.input = input;
        this.output = output;
        this.readCompression = new TlsNullCompression();
        this.writeCompression = this.readCompression;
    }

    void init(TlsContext context)
    {
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
        this.compressedLimit = this.plaintextLimit + 1024;
        this.ciphertextLimit = this.compressedLimit + 1024;
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

    /**
     * RFC 5246 E.1. "Earlier versions of the TLS specification were not fully clear on what the
     * record layer version number (TLSPlaintext.version) should contain when sending ClientHello
     * (i.e., before it is known which version of the protocol will be employed). Thus, TLS servers
     * compliant with this specification MUST accept any value {03,XX} as the record layer version
     * number for ClientHello."
     */
    void setRestrictReadVersion(boolean enabled)
    {
        this.restrictReadVersion = enabled;
    }

    void setPendingConnectionState(TlsCompression tlsCompression, TlsCipher tlsCipher)
    {
        this.pendingCompression = tlsCompression;
        this.pendingCipher = tlsCipher;
    }

    void sentWriteCipherSpec()
        throws IOException
    {
        if (pendingCompression == null || pendingCipher == null)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        this.writeCompression = this.pendingCompression;
        this.writeCipher = this.pendingCipher;
        this.writeSeqNo = new SequenceNumber();
    }

    void receivedReadCipherSpec()
        throws IOException
    {
        if (pendingCompression == null || pendingCipher == null)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        this.readCompression = this.pendingCompression;
        this.readCipher = this.pendingCipher;
        this.readSeqNo = new SequenceNumber();
    }

    void finaliseHandshake()
        throws IOException
    {
        if (readCompression != pendingCompression || writeCompression != pendingCompression
            || readCipher != pendingCipher || writeCipher != pendingCipher)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        this.pendingCompression = null;
        this.pendingCipher = null;
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

        if (!restrictReadVersion)
        {
            int version = TlsUtils.readVersionRaw(recordHeader, RecordFormat.VERSION_OFFSET);
            if ((version & 0xffffff00) != 0x0300)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
        else
        {
            ProtocolVersion version = TlsUtils.readVersion(recordHeader, RecordFormat.VERSION_OFFSET);
            if (readVersion == null)
            {
                // Will be set later in 'readRecord'
            }
            else if (!version.equals(readVersion))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

        int length = TlsUtils.readUint16(recordHeader, RecordFormat.LENGTH_OFFSET);

        checkLength(length, ciphertextLimit, AlertDescription.record_overflow);

        int recordSize = RecordFormat.FRAGMENT_OFFSET + length;
        int applicationDataLimit = 0;

        if (type == ContentType.application_data)
        {
            applicationDataLimit = getPlaintextLimit();

            if (readCompression.getClass() == TlsNullCompression.class)
            {
                applicationDataLimit = Math.min(applicationDataLimit, readCipher.getPlaintextLimit(length));
            }
        }

        return new RecordPreview(recordSize, applicationDataLimit);
    }

    RecordPreview previewOutputRecord(int applicationDataSize)
    {
        int applicationDataLimit = Math.max(0, Math.min(getPlaintextLimit(), applicationDataSize));

        int recordSize = applicationDataLimit;
        if (writeCompression.getClass() != TlsNullCompression.class)
        {
            recordSize += 1024;
        }

        recordSize = writeCipher.getCiphertextLimit(recordSize) + RecordFormat.FRAGMENT_OFFSET;

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

        if (!restrictReadVersion)
        {
            int version = TlsUtils.readVersionRaw(input, inputOff + RecordFormat.VERSION_OFFSET);
            if ((version & 0xffffff00) != 0x0300)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
        else
        {
            ProtocolVersion version = TlsUtils.readVersion(input, inputOff + RecordFormat.VERSION_OFFSET);
            if (readVersion == null)
            {
                readVersion = version;
            }
            else if (!version.equals(readVersion))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

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

        if (!restrictReadVersion)
        {
            int version = TlsUtils.readVersionRaw(inputRecord.buf, RecordFormat.VERSION_OFFSET);
            if ((version & 0xffffff00) != 0x0300)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
        else
        {
            ProtocolVersion version = TlsUtils.readVersion(inputRecord.buf, RecordFormat.VERSION_OFFSET);
            if (readVersion == null)
            {
                readVersion = version;
            }
            else if (!version.equals(readVersion))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

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

        checkLength(decoded.length, compressedLimit, AlertDescription.record_overflow);

        /*
         * TODO RFC 5246 6.2.2. Implementation note: Decompression functions are responsible for
         * ensuring that messages cannot cause internal buffer overflows.
         */
        OutputStream cOut = readCompression.decompress(buffer);
        if (cOut != buffer)
        {
            cOut.write(decoded, 0, decoded.length);
            cOut.flush();
            decoded = getBufferContents();
        }

        /*
         * RFC 5246 6.2.2. If the decompression function encounters a TLSCompressed.fragment that
         * would decompress to a length in excess of 2^14 bytes, it should report a fatal
         * decompression failure error.
         */
        checkLength(decoded.length, plaintextLimit, AlertDescription.decompression_failure);

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

        OutputStream cOut = writeCompression.compress(buffer);

        long seqNo = writeSeqNo.nextValue(AlertDescription.internal_error);

        byte[] ciphertext;
        if (cOut == buffer)
        {
            ciphertext = writeCipher.encodePlaintext(seqNo, type, plaintext, plaintextOffset, plaintextLength);
        }
        else
        {
            cOut.write(plaintext, plaintextOffset, plaintextLength);
            cOut.flush();
            byte[] compressed = getBufferContents();

            /*
             * RFC 5246 6.2.2. Compression must be lossless and may not increase the content length
             * by more than 1024 bytes.
             */
            checkLength(compressed.length, plaintextLength + 1024, AlertDescription.internal_error);

            ciphertext = writeCipher.encodePlaintext(seqNo, type, compressed, 0, compressed.length);
        }

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

    private byte[] getBufferContents()
    {
        byte[] contents = buffer.toByteArray();
        buffer.reset();
        return contents;
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
