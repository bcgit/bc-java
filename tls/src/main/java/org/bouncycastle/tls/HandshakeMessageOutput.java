package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

class HandshakeMessageOutput
    extends ByteArrayOutputStream
{
    static void send(TlsProtocol protocol, short handshakeType, byte[] body)
        throws IOException
    {
        HandshakeMessageOutput message = new HandshakeMessageOutput(handshakeType, body.length);
        message.write(body);
        message.send(protocol);
    }

    HandshakeMessageOutput(short handshakeType) throws IOException
    {
        this(handshakeType, 60);
    }

    HandshakeMessageOutput(short handshakeType, int length) throws IOException
    {
        super(length + 4);
        TlsUtils.checkUint8(handshakeType);
        TlsUtils.writeUint8(handshakeType, this);
        // Reserve space for length
        count += 3;
    }

    void send(TlsProtocol protocol) throws IOException
    {
        // Patch actual length back in
        int length = count - 4;
        TlsUtils.checkUint24(length);
        TlsUtils.writeUint24(length, buf, 1);
        protocol.writeHandshakeMessage(buf, 0, count);
        buf = null;
    }
}
