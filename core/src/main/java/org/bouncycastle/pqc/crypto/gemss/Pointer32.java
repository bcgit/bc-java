package org.bouncycastle.pqc.crypto.gemss;

class Pointer32
    extends Pointer
{
    private int remainder;

//    public Pointer32(Pointer p)
//    {
//        super(p);
//        remainder = 0;
//    }

    public Pointer32()
    {
        super();
        remainder = 0;
    }

    public Pointer32(int p)
    {
        super(p);
        remainder = 0;
    }

    @Override
    public void set(long v)
    {
        array[cp] = (v & (0xFFFFL << (remainder << 4))) | (array[cp] & ((0xFFFFL << ((1 - remainder) << 4))));
    }

    @Override
    public void set(int p, long v)
    {
        int r = remainder + p;
        int q = (r >>> 1) + cp;
        r &= 1;
        array[q] = (v & (0xFFFFL << (r << 4))) | (array[q] & ((0xFFFFL << ((1 - r) << 4))));
    }

    public int getInteger()
    {
        return (int)(array[cp] >>> (remainder << 4));
    }

//    public int getInteger(int p)
//    {
//        int r = remainder + p;
//        int q = (r >>> 1) + cp;
//        r &= 1;
//        return (int)(array[q] >>> (r << 4));
//    }
}
