package org.bouncycastle.tls;

public class DTLSRequest
{
    private final long recordSeq;
    private final byte[] message;
    private final ClientHello clientHello;

    DTLSRequest(long recordSeq, byte[] message, ClientHello clientHello)
    {
        this.recordSeq = recordSeq;
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

    long getRecordSeq()
    {
        return recordSeq;
    }
}
