package org.bouncycastle.pqc.crypto.lms;

public class ExtraInfo
{
    final boolean lastSignature;

    public ExtraInfo(boolean lastSignature)
    {
        this.lastSignature = lastSignature;
    }
}
