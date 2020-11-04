package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

class HandshakeMessageOutput
    extends ByteArrayOutputStream
{
    static int getLength(int bodyLength)
    {
        return 4 + bodyLength;
    }

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

    HandshakeMessageOutput(short handshakeType, int bodyLength) throws IOException
    {
        super(getLength(bodyLength));
        TlsUtils.checkUint8(handshakeType);
        TlsUtils.writeUint8(handshakeType, this);
        // Reserve space for length
        count += 3;
    }

    void send(TlsProtocol protocol) throws IOException
    {
        // Patch actual length back in
        int bodyLength = count - 4;
        TlsUtils.checkUint24(bodyLength);
        TlsUtils.writeUint24(bodyLength, buf, 1);
        protocol.writeHandshakeMessage(buf, 0, count);
        buf = null;
    }
}
