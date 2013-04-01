package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.Digest;

/**
 * An implementation of the TLS 1.0 record layer, allowing downgrade to SSLv3.
 */
class RecordStream {
    private TlsProtocol handler;
    private InputStream input;
    private OutputStream output;
    private TlsCompression pendingCompression = null, readCompression = null, writeCompression = null;
    private TlsCipher pendingCipher = null, readCipher = null, writeCipher = null;
    private long readSeqNo = 0, writeSeqNo = 0;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private TlsContext context = null;
    private CombinedHash hash = null;

    private ProtocolVersion readVersion = null, writeVersion = null;
    private boolean restrictReadVersion = true;

    RecordStream(TlsProtocol handler, InputStream input, OutputStream output) {
        this.handler = handler;
        this.input = input;
        this.output = output;
        this.readCompression = new TlsNullCompression();
        this.writeCompression = this.readCompression;
        this.readCipher = new TlsNullCipher(context);
        this.writeCipher = this.readCipher;
    }

    void init(TlsContext context) {
        this.context = context;
        this.hash = new CombinedHash(context);
    }

    ProtocolVersion getReadVersion() {
        return readVersion;
    }

    void setReadVersion(ProtocolVersion readVersion) {
        this.readVersion = readVersion;
    }

    void setWriteVersion(ProtocolVersion writeVersion) {
        this.writeVersion = writeVersion;
    }

    /**
     * RFC 5246 E.1. "Earlier versions of the TLS specification were not fully clear on what the
     * record layer version number (TLSPlaintext.version) should contain when sending ClientHello
     * (i.e., before it is known which version of the protocol will be employed). Thus, TLS servers
     * compliant with this specification MUST accept any value {03,XX} as the record layer version
     * number for ClientHello."
     */
    void setRestrictReadVersion(boolean enabled) {
        this.restrictReadVersion = enabled;
    }

    void setPendingConnectionState(TlsCompression tlsCompression, TlsCipher tlsCipher) {
        this.pendingCompression = tlsCompression;
        this.pendingCipher = tlsCipher;
    }

    void sentWriteCipherSpec() throws IOException {
        if (pendingCompression == null || pendingCipher == null) {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        this.writeCompression = this.pendingCompression;
        this.writeCipher = this.pendingCipher;
        this.writeSeqNo = 0;
    }

    void receivedReadCipherSpec() throws IOException {
        if (pendingCompression == null || pendingCipher == null) {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        this.readCompression = this.pendingCompression;
        this.readCipher = this.pendingCipher;
        this.readSeqNo = 0;
    }

    void finaliseHandshake() throws IOException {
        if (readCompression != pendingCompression || writeCompression != pendingCompression
            || readCipher != pendingCipher || writeCipher != pendingCipher) {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        pendingCompression = null;
        pendingCipher = null;
    }

    public void readRecord() throws IOException {
        short type = TlsUtils.readUint8(input);

        if (!restrictReadVersion) {
            int version = TlsUtils.readVersionRaw(input);
            if ((version & 0xffffff00) != 0x0300) {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        } else {
            ProtocolVersion version = TlsUtils.readVersion(input);
            if (readVersion == null) {
                readVersion = version;
            } else if (!version.equals(readVersion)) {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

        int size = TlsUtils.readUint16(input);
        byte[] buf = decodeAndVerify(type, input, size);
        handler.processRecord(type, buf, 0, buf.length);
    }

    protected byte[] decodeAndVerify(short type, InputStream input, int len) throws IOException {

        byte[] buf = TlsUtils.readFully(len, input);
        byte[] decoded = readCipher.decodeCiphertext(readSeqNo++, type, buf, 0, buf.length);

        /*
         * TODO RFC5264 6.2.2. If the decompression function encounters a TLSCompressed.fragment
         * that would decompress to a length in excess of 2^14 bytes, it MUST report a fatal
         * decompression failure error. [..] Implementation note: Decompression functions are
         * responsible for ensuring that messages cannot cause internal buffer overflows.
         */
        OutputStream cOut = readCompression.decompress(buffer);

        if (cOut == buffer) {
            return decoded;
        }

        cOut.write(decoded, 0, decoded.length);
        cOut.flush();
        return getBufferContents();
    }

    protected void writeRecord(short type, byte[] message, int offset, int len) throws IOException {

        /*
         * RFC 5264 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
         * or ChangeCipherSpec content types.
         */
        if (len < 1 && type != ContentType.application_data) {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (type == ContentType.handshake) {
            updateHandshakeData(message, offset, len);
        }

        /*
         * TODO RFC5264 6.2.2. Compression must be lossless and may not increase the content length
         * by more than 1024 bytes.
         */
        OutputStream cOut = writeCompression.compress(buffer);

        byte[] ciphertext;
        if (cOut == buffer) {
            ciphertext = writeCipher.encodePlaintext(writeSeqNo++, type, message, offset, len);
        } else {
            cOut.write(message, offset, len);
            cOut.flush();
            byte[] compressed = getBufferContents();
            ciphertext = writeCipher.encodePlaintext(writeSeqNo++, type, compressed, 0, compressed.length);
        }

        byte[] writeMessage = new byte[ciphertext.length + 5];
        TlsUtils.writeUint8(type, writeMessage, 0);
        TlsUtils.writeVersion(writeVersion, writeMessage, 1);
        TlsUtils.writeUint16(ciphertext.length, writeMessage, 3);
        System.arraycopy(ciphertext, 0, writeMessage, 5, ciphertext.length);
        output.write(writeMessage);
        output.flush();
    }

    void updateHandshakeData(byte[] message, int offset, int len) {
        hash.update(message, offset, len);
    }

    /**
     * 'sender' only relevant to SSLv3
     */
    byte[] getCurrentHash(byte[] sender) {
        Digest d = new CombinedHash(hash);

        if (context.getServerVersion().isSSL()) {
            if (sender != null) {
                d.update(sender, 0, sender.length);
            }
        }

        return doFinal(d);
    }

    protected void close() throws IOException {
        IOException e = null;
        try {
            input.close();
        } catch (IOException ex) {
            e = ex;
        }
        try {
            output.close();
        } catch (IOException ex) {
            e = ex;
        }
        if (e != null) {
            throw e;
        }
    }

    protected void flush() throws IOException {
        output.flush();
    }

    private byte[] getBufferContents() {
        byte[] contents = buffer.toByteArray();
        buffer.reset();
        return contents;
    }

    private static byte[] doFinal(Digest d) {
        byte[] bs = new byte[d.getDigestSize()];
        d.doFinal(bs, 0);
        return bs;
    }
}
