package org.bouncycastle.pqc.crypto.lms;

public enum LMOtsType
{
    LMOTS_SHA256_N32_W1(0x00000001),
    LMOTS_SHA256_N32_W2(0x00000002),
    LMOTS_SHA256_N32_W4(0x00000003),
    LMOTS_SHA256_N32_W8(0x00000004);

    final int type;

    LMOtsType(int type)
    {
        this.type = type;
    }

    public int getType()
    {
        return type;
    }
}
