package org.bouncycastle.kmip.wire.message;

import java.util.Date;

public class KMIPResponseHeader
    extends KMIPHeader
{
    private KMIPNonce nonce;                      // Optional
    private byte[] serverHashedPassword;       // Required if Hashed Password is used

    public KMIPResponseHeader(KMIPProtocolVersion protocolVersion, Date timeStamp, int batchCount)
    {
        super(protocolVersion, batchCount);
        this.timeStamp = timeStamp;
    }

    public KMIPNonce getNonce()
    {
        return nonce;
    }

    public void setNonce(KMIPNonce nonce)
    {
        this.nonce = nonce;
    }

    public byte[] getServerHashedPassword()
    {
        return serverHashedPassword;
    }

    public void setServerHashedPassword(byte[] serverHashedPassword)
    {
        this.serverHashedPassword = serverHashedPassword;
    }
}
