package org.bouncycastle.pqc.crypto;

public class ExhaustedPrivateKeyException
    extends IllegalStateException
{
    public ExhaustedPrivateKeyException(String msg)
    {
        super(msg);
    }
}
