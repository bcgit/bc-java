package org.bouncycastle.crypto.tls;

import java.io.IOException;

class DTLSRecordLayer implements DatagramTransport {

    private final DatagramTransport transport;
    private final TlsClientContext clientContext;
    private final short contentType;

    private final DTLSReplayWindow replayWindow = new DTLSReplayWindow();

    private int epoch_read = 0, epoch_write = 0;
    private long sequence_number = 0;
    private ProtocolVersion discoveredServerVersion = null;

    DTLSRecordLayer(DatagramTransport transport, TlsClientContext clientContext, short contentType) {
        this.transport = transport;
        this.clientContext = clientContext;
        this.contentType = contentType;
    }

    ProtocolVersion getDiscoveredServerVersion() {
        return discoveredServerVersion;
    }

    public int getReceiveLimit() throws IOException {
        // TODO Needs to be adjusted for possible block-alignment once cipher is in place
        return transport.getReceiveLimit() - 13;
    }

    public int getSendLimit() throws IOException {
        // TODO Needs to be adjusted for possible block-alignment once cipher is in place
        return transport.getSendLimit() - 13;
    }

    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {

        byte[] record = null;

        for (;;) {

            int receiveLimit = Math.min(len, getReceiveLimit()) + 13;
            if (record == null || record.length < receiveLimit) {
                record = new byte[receiveLimit];
            }

            try {
                int received = transport.receive(record, 0, receiveLimit, waitMillis);
                if (received < 13) {
                    // TODO What kind of exception?
                }
                int length = TlsUtils.readUint16(record, 11);
                if (received != (length + 13)) {
                    // TODO What kind of exception?
                }
                int epoch = TlsUtils.readUint16(record, 3);
                if (epoch != epoch_read) {
                    // TODO What kind of exception?
                }

                long seq = TlsUtils.readUint48(record, 5);
                if (!replayWindow.shouldDiscard(seq)) {

                    ProtocolVersion version = TlsUtils.readVersion(record, 1);
                    if (discoveredServerVersion != null && !discoveredServerVersion.equals(version)) {
                        // TODO What exception?
//                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                    }

                    // TODO Decrypt, decompress
                    System.arraycopy(record, 13, buf, off, length);

                    replayWindow.reportAuthenticated(seq);

                    if (discoveredServerVersion == null) {
                        discoveredServerVersion = version;
                    }

                    return length;
                }
            } catch (IOException e) {
                // NOTE: Assume this is a timeout for the moment
            }
        }
    }

    public void send(byte[] buf, int off, int len) throws IOException {

        // TODO Compress, encrypt

        byte[] record = new byte[len + 13];
        TlsUtils.writeUint8(contentType, record, 0);
        ProtocolVersion version = discoveredServerVersion != null ? discoveredServerVersion
            : clientContext.getClientVersion();
        TlsUtils.writeVersion(version, record, 1);
        TlsUtils.writeUint16(epoch_write, record, 3);
        TlsUtils.writeUint48(sequence_number++, record, 5);
        TlsUtils.writeUint16(len, record, 11);
        System.arraycopy(buf, off, record, 13, len);

        transport.send(record, 0, record.length);
    }
}
