package org.bouncycastle.crypto.tls;

import java.io.IOException;

class DTLSRecordLayer implements DatagramTransport {

    private static final int RECORD_HEADER_LENGTH = 13;
    private static final int MAX_FRAGMENT_LENGTH = 1 << 14;

    private final DatagramTransport transport;
    private final TlsContext context;

    private final ByteQueue recordQueue = new ByteQueue();

    private volatile ProtocolVersion discoveredPeerVersion = null;
    private volatile boolean inHandshake;
    private DTLSEpoch currentEpoch, pendingEpoch;
    private DTLSEpoch readEpoch, writeEpoch;

    DTLSRecordLayer(DatagramTransport transport, TlsContext context, short contentType) {
        this.transport = transport;
        this.context = context;

        this.inHandshake = true;

        this.currentEpoch = new DTLSEpoch(0, new TlsNullCipher(context));
        this.pendingEpoch = null;
        this.readEpoch = currentEpoch;
        this.writeEpoch = currentEpoch;
    }

    ProtocolVersion getDiscoveredPeerVersion() {
        return discoveredPeerVersion;
    }

    void initPendingEpoch(TlsCipher pendingCipher) {
        if (pendingEpoch != null) {
            // TODO
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

    void handshakeSuccessful() {
        if (readEpoch == currentEpoch || writeEpoch == currentEpoch) {
            // TODO
            throw new IllegalStateException();
        }
        this.inHandshake = false;
        this.currentEpoch = pendingEpoch;
        this.pendingEpoch = null;
    }

    void resetWriteEpoch() {
        this.writeEpoch = currentEpoch;
    }

    public int getReceiveLimit() throws IOException {
        return Math.min(
            MAX_FRAGMENT_LENGTH,
            readEpoch.getCipher().getPlaintextLimit(
                transport.getReceiveLimit() - RECORD_HEADER_LENGTH));
    }

    public int getSendLimit() throws IOException {
        return Math.min(
            MAX_FRAGMENT_LENGTH,
            writeEpoch.getCipher().getPlaintextLimit(
                transport.getSendLimit() - RECORD_HEADER_LENGTH));
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
                if (received < 0) {
                    return received;
                }
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
                if (epoch != readEpoch.getEpoch()) {
                    // TODO What kind of exception?
                    continue;
                }

                long seq = TlsUtils.readUint48(record, 5);
                if (readEpoch.getReplayWindow().shouldDiscard(seq))
                    continue;

                short type = TlsUtils.readUint8(record, 0);

                // TODO Support user-specified custom protocols?
                switch (type) {
                case ContentType.alert:
                case ContentType.application_data:
                case ContentType.change_cipher_spec:
                case ContentType.handshake:
                    break;
                default:
                    // TODO Exception?
                    continue;
                }

                ProtocolVersion version = TlsUtils.readVersion(record, 1);
                if (discoveredPeerVersion != null && !discoveredPeerVersion.equals(version)) {
                    // TODO What exception?
                    // throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                byte[] plaintext = readEpoch.getCipher().decodeCiphertext(
                    getMacSequenceNumber(readEpoch.getEpoch(), seq), type, record,
                    RECORD_HEADER_LENGTH, received - RECORD_HEADER_LENGTH);

                readEpoch.getReplayWindow().reportAuthenticated(seq);

                if (discoveredPeerVersion == null) {
                    discoveredPeerVersion = version;
                }

                switch (type) {
                case ContentType.alert: {
                    // TODO Figure out approach to sending/receiving alerts
                    break;
                }
                case ContentType.application_data: {
                    if (inHandshake) {
                        // TODO Consider buffering application data for new epoch that arrives
                        // out-of-order with the Finished message
                        continue;
                    }
                    break;
                }
                case ContentType.change_cipher_spec: {
                    // Implicitly receive change_cipher_spec and change to pending cipher state

                    if (plaintext.length != 1 || plaintext[0] != 1) {
                        // TODO What exception?
                        continue;
                    }

                    if (pendingEpoch == null) {
                        // TODO Exception?
                    } else {

                        readEpoch = pendingEpoch;
                    }

                    continue;
                }
                case ContentType.handshake: {
                    if (!inHandshake) {
                        // TODO Consider support for HelloRequest
                        continue;
                    }
                }
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

        short contentType = ContentType.application_data;

        if (this.inHandshake) {

            contentType = ContentType.handshake;

            short handshakeType = TlsUtils.readUint8(buf, off);
            if (handshakeType == HandshakeType.finished) {
                if (pendingEpoch == null) {
                    // TODO Exception?
                } else {

                    // Implicitly send change_cipher_spec and change to pending cipher state

                    // TODO Send change_cipher_spec and finished records in single datagram?
                    byte[] data = new byte[] { 1 };
                    sendRecord(ContentType.change_cipher_spec, data, 0, data.length);

                    writeEpoch = pendingEpoch;
                }
            }
        }

        sendRecord(contentType, buf, off, len);
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

        int recordEpoch = writeEpoch.getEpoch();
        long recordSequenceNumber = writeEpoch.allocateSequenceNumber();

        byte[] ciphertext = writeEpoch.getCipher().encodePlaintext(
            getMacSequenceNumber(recordEpoch, recordSequenceNumber), contentType, buf, off, len);

        if (ciphertext.length > MAX_FRAGMENT_LENGTH) {
            // TODO Exception
        }

        byte[] record = new byte[ciphertext.length + RECORD_HEADER_LENGTH];
        TlsUtils.writeUint8(contentType, record, 0);
        ProtocolVersion version = discoveredPeerVersion != null ? discoveredPeerVersion : context
            .getClientVersion();
        TlsUtils.writeVersion(version, record, 1);
        TlsUtils.writeUint16(recordEpoch, record, 3);
        TlsUtils.writeUint48(recordSequenceNumber, record, 5);
        TlsUtils.writeUint16(ciphertext.length, record, 11);
        System.arraycopy(ciphertext, 0, record, RECORD_HEADER_LENGTH, ciphertext.length);

        transport.send(record, 0, record.length);
    }

    private static long getMacSequenceNumber(int epoch, long sequence_number) {
        return ((long) epoch << 48) | sequence_number;
    }
}
