package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

class HandshakeMessageOutput
    extends ByteArrayOutputStream
{
    private final TlsProtocol protocol;

    HandshakeMessageOutput(TlsProtocol protocol, short handshakeType) throws IOException
    {
        this(protocol, handshakeType, 60);
    }

    HandshakeMessageOutput(TlsProtocol protocol, short handshakeType, int length) throws IOException
    {
        super(length + 4);
        TlsUtils.writeUint8(handshakeType, this);
        // Reserve space for length
        count += 3;

        this.protocol = protocol;
    }

    void writeToRecordStream() throws IOException
    {
        // Patch actual length back in
        int length = count - 4;
        TlsUtils.checkUint24(length);
        TlsUtils.writeUint24(length, buf, 1);
        protocol.writeHandshakeMessage(buf, 0, count);
        buf = null;
    }
}
