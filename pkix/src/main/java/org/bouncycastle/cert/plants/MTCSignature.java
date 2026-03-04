package org.bouncycastle.cert.plants;

public class MTCSignature
{
    final byte[] cosignerId;
    final byte[] signature;

    public MTCSignature(byte[] cosignerId, byte[] signature)
    {
        this.cosignerId = cosignerId;
        this.signature = signature;
    }

    public byte[] getCosignerId()
    {
        return cosignerId;
    }

    public byte[] getSignature()
    {
        return signature;
    }
}
