package org.bouncycastle.crypto.tls;

import java.io.IOException;

class DTLSRecordLayer implements DatagramTransport {

    private static final int RECORD_HEADER_LENGTH = 13;

    private final DatagramTransport transport;
    private final TlsClientContext clientContext;
    private final short contentType;

    private final ByteQueue recordQueue = new ByteQueue();
    private final DTLSReplayWindow replayWindow = new DTLSReplayWindow();

    private int epoch_read = 0, epoch_write = 0;
    private long sequence_number = 0;
    private volatile ProtocolVersion discoveredServerVersion = null;
    private TlsCipher activeReadCipher, activeWriteCipher, pendingReadCipher, pendingWriteCipher;

    DTLSRecordLayer(DatagramTransport transport, TlsClientContext clientContext, short contentType) {
        this.transport = transport;
        this.clientContext = clientContext;
        this.contentType = contentType;

        this.activeReadCipher = new TlsNullCipher();
        this.activeWriteCipher = this.activeReadCipher;
        this.pendingReadCipher = null;
        this.pendingWriteCipher = null;
    }

    ProtocolVersion getDiscoveredServerVersion() {
        return discoveredServerVersion;
    }

    void setPendingCipher(TlsCipher pendingCipher) {
        this.pendingReadCipher = pendingCipher;
        this.pendingWriteCipher = pendingCipher;
    }

    public int getReceiveLimit() throws IOException {
        // TODO Needs to be adjusted for possible block-alignment once cipher is in place
        return transport.getReceiveLimit() - RECORD_HEADER_LENGTH;
    }

    public int getSendLimit() throws IOException {
        // TODO Needs to be adjusted for possible block-alignment once cipher is in place
        return transport.getSendLimit() - RECORD_HEADER_LENGTH;
    }

    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {

        byte[] record = null;

        for (;;) {

            int receiveLimit = Math.min(len, getReceiveLimit()) + RECORD_HEADER_LENGTH;
            if (record == null || record.length < receiveLimit) {
                record = new byte[receiveLimit];
            }

            try {
                int received = receiveRecord(record, 0, receiveLimit, waitMillis);
                if (received < RECORD_HEADER_LENGTH) {
                    // TODO What kind of exception?
                    continue;
                }
                int length = TlsUtils.readUint16(record, 11);
                if (received != (length + RECORD_HEADER_LENGTH)) {
                    // TODO What kind of exception?
                    continue;
                }
                int epoch = TlsUtils.readUint16(record, 3);
                if (epoch != epoch_read) {
                    // TODO What kind of exception?
                    continue;
                }

                long seq = TlsUtils.readUint48(record, 5);
                if (replayWindow.shouldDiscard(seq))
                    continue;

                // TODO Validate contentType
                short type = TlsUtils.readUint8(record, 0);

                ProtocolVersion version = TlsUtils.readVersion(record, 1);
                if (discoveredServerVersion != null && !discoveredServerVersion.equals(version)) {
                    // TODO What exception?
                    // throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                byte[] plaintext = activeReadCipher.decodeCiphertext(getMacSequenceNumber(epoch_read, seq), type,
                    record, RECORD_HEADER_LENGTH, received - RECORD_HEADER_LENGTH);

                replayWindow.reportAuthenticated(seq);

                if (discoveredServerVersion == null) {
                    discoveredServerVersion = version;
                }

                if (type == ContentType.alert) {
                    // TODO Figure out approach to sending/receiving alerts
                }

                if (type == ContentType.change_cipher_spec) {
                    // Implicitly receive change_cipher_spec and change to pending cipher state

                    if (plaintext.length != 1 || plaintext[0] != 1) {
                        // TODO What exception?
                        continue;
                    }

                    if (pendingReadCipher == null) {
                        // TODO Exception?
                    }

                    /*
                     * TODO "In order to ensure that any given sequence/epoch pair is unique,
                     * implementations MUST NOT allow the same epoch value to be reused within two times
                     * the TCP maximum segment lifetime."
                     */

                    // TODO Check for overflow
                    ++epoch_read;

                    replayWindow.reset();

                    activeReadCipher = pendingReadCipher;
                    pendingReadCipher = null;

                    continue;
                }

                System.arraycopy(plaintext, 0, buf, off, plaintext.length);
                return plaintext.length;
            } catch (IOException e) {
                // NOTE: Assume this is a timeout for the moment
                throw e;
            }
        }
    }

    public void send(byte[] buf, int off, int len) throws IOException {

        if (this.contentType == ContentType.handshake) {
            short handshakeType = TlsUtils.readUint8(buf, off);
            if (handshakeType == HandshakeType.finished) {
                if (pendingWriteCipher == null) {
                    // TODO Exception?
                }

                // Implicitly send change_cipher_spec and change to pending cipher state

                byte[] data = new byte[] { 1 };
                sendRecord(ContentType.change_cipher_spec, data, 0, data.length);

                /*
                 * TODO "In order to ensure that any given sequence/epoch pair is unique,
                 * implementations MUST NOT allow the same epoch value to be reused within two times
                 * the TCP maximum segment lifetime."
                 */

                // TODO Check for overflow
                ++epoch_write;

                sequence_number = 0;

                activeWriteCipher = pendingWriteCipher;
                pendingWriteCipher = null;
            }
        }

        sendRecord(this.contentType, buf, off, len);
    }

    private int receiveRecord(byte[] buf, int off, int len, int waitMillis) throws IOException {
        if (recordQueue.size() > 0) {
            int length = 0;
            if (recordQueue.size() >= RECORD_HEADER_LENGTH) {
                byte[] lengthBytes = new byte[2];
                recordQueue.read(lengthBytes, 0, 2, 11);
                length = TlsUtils.readUint16(lengthBytes, 0);
            }

            int received = Math.min(recordQueue.size(), RECORD_HEADER_LENGTH + length);
            recordQueue.read(buf, off, received, 0);
            recordQueue.removeData(received);
            return received;
        }

        int received = transport.receive(buf, off, len, waitMillis);
        if (received >= RECORD_HEADER_LENGTH) {
            int fragmentLength = TlsUtils.readUint16(buf, off + 11);
            int recordLength = RECORD_HEADER_LENGTH + fragmentLength;
            if (received > recordLength) {
                recordQueue.addData(buf, off + recordLength, received - recordLength);
                received = recordLength;
            }
        }

        return received;
    }

    private void sendRecord(short contentType, byte[] buf, int off, int len) throws IOException {

        // TODO Check for overflow
        long recordSequenceNumber = sequence_number++;

        byte[] ciphertext = activeWriteCipher.encodePlaintext(
            getMacSequenceNumber(epoch_write, recordSequenceNumber), contentType, buf, off, len);

        byte[] record = new byte[ciphertext.length + RECORD_HEADER_LENGTH];
        TlsUtils.writeUint8(contentType, record, 0);
        ProtocolVersion version = discoveredServerVersion != null ? discoveredServerVersion
            : clientContext.getClientVersion();
        TlsUtils.writeVersion(version, record, 1);
        TlsUtils.writeUint16(epoch_write, record, 3);
        TlsUtils.writeUint48(recordSequenceNumber, record, 5);
        TlsUtils.writeUint16(ciphertext.length, record, 11);
        System.arraycopy(ciphertext, 0, record, RECORD_HEADER_LENGTH, ciphertext.length);

        transport.send(record, 0, record.length);
    }

    private static long getMacSequenceNumber(int epoch, long sequence_number) {
        return ((long) epoch << 48) | sequence_number;
    }
}
