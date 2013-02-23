package org.bouncycastle.crypto.tls;

import java.io.IOException;

class DTLSRecordLayer implements DatagramTransport {

    private final DatagramTransport transport;
    private final TlsClientContext clientContext;
    private final short contentType;

    private int epoch = 0;
    private long sequence_number = 0;
    private ProtocolVersion discoveredServerVersion = null;

    DTLSRecordLayer(DatagramTransport transport, TlsClientContext clientContext, short contentType) {
        this.transport = transport;
        this.clientContext = clientContext;
        this.contentType = contentType;
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

        return transport.receive(buf, off, len, waitMillis);

        // TODO Process record format, anti-replay, decrypt, decompress
        
//        short type = TlsUtils.readUint8(is);
//
//        ProtocolVersion version = TlsUtils.readVersion(is);
//        if (discoveredServerVersion == null)
//        {
//            discoveredServerVersion = version;
//        }
//        else if (!version.equals(discoveredServerVersion))
//        {
//            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
//        }
//
//        int size = TlsUtils.readUint16(is);
//        byte[] buf = decodeAndVerify(type, is, size);
//        handler.processData(type, buf, 0, buf.length);

    }

    public void send(byte[] buf, int off, int len) throws IOException {

        // TODO Compress, encrypt

        byte[] record = new byte[len + 13];
        TlsUtils.writeUint8(contentType, record, 0);
        ProtocolVersion version = discoveredServerVersion != null ? discoveredServerVersion : clientContext.getClientVersion();
        TlsUtils.writeVersion(version, record, 1);
        TlsUtils.writeUint16(epoch, record, 3);
        TlsUtils.writeUint48(sequence_number++, record, 5);
        TlsUtils.writeUint16(len, record, 11);
        System.arraycopy(buf, off, record, 13, len);

        transport.send(record, 0, record.length);
    }
}
