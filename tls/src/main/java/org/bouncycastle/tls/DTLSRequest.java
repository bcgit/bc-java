package org.bouncycastle.tls;

public class DTLSRequest
{
    private final byte[] message;
    private final ClientHello clientHello;

    DTLSRequest(byte[] message, ClientHello clientHello)
    {
        this.message = message;
        this.clientHello = clientHello;
    }

    ClientHello getClientHello()
    {
        return clientHello;
    }

    byte[] getMessage()
    {
        return message;
    }

    int getMessageSeq()
    {
        return TlsUtils.readUint16(message, 4);
    }
}
