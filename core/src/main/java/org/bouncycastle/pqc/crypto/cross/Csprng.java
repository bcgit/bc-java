package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.util.Pack;

class Csprng
{
    int size;
    int bitsFor;
    private final byte[] CSPRNG_buffer;
    int bitsInSubBuf = 64;
    int posInBuf = 8;
    int posRemaining;
    long subBuffer;
    long mask;

    public Csprng(int size, int bufferSize, CrossEngine engine)
    {
        this.size = size;
        this.bitsFor = Utils.bitsToRepresent(size - 1);
        this.CSPRNG_buffer = engine.randomBytes(bufferSize);
        this.posRemaining = bufferSize - posInBuf;
        this.mask = (1L << bitsFor) - 1;
        this.subBuffer = Pack.littleEndianToLong(CSPRNG_buffer, 0);
    }

    public Csprng(int size, int bufferSize, int bitsFor, CrossEngine engine)
    {
        this.size = size;
        this.bitsFor = bitsFor;
        this.CSPRNG_buffer = engine.randomBytes(bufferSize);
        this.posRemaining = bufferSize - posInBuf;
        this.mask = (1L << bitsFor) - 1;
        this.subBuffer = Pack.littleEndianToLong(CSPRNG_buffer, 0);
    }

    public long next()
    {
        if (bitsInSubBuf <= 32 && posRemaining > 0)
        {
            int refreshAmount = Math.min(4, posRemaining);
            long refreshBuf = Pack.littleEndianToLong(CSPRNG_buffer, posInBuf);
            posInBuf += refreshAmount;
            posRemaining -= refreshAmount;
            subBuffer |= refreshBuf << bitsInSubBuf;
            bitsInSubBuf += 8 * refreshAmount;
        }
        long elementLong = subBuffer & mask;
        subBuffer >>>= bitsFor;
        bitsInSubBuf -= bitsFor;
        return elementLong;
    }
}
