package org.bouncycastle.pqc.crypto.falcon;

class FalconBitlen
{

    int avg;
    int std;

    FalconBitlen(int avg, int std)
    {
        this.avg = avg;
        this.std = std;
    }

    static final FalconBitlen[] BITLENGTH = {
        new FalconBitlen(4, 0),
        new FalconBitlen(11, 1),
        new FalconBitlen(24, 1),
        new FalconBitlen(50, 1),
        new FalconBitlen(102, 1),
        new FalconBitlen(202, 2),
        new FalconBitlen(401, 4),
        new FalconBitlen(794, 5),
        new FalconBitlen(1577, 8),
        new FalconBitlen(3138, 13),
        new FalconBitlen(6308, 25)
    };
}
