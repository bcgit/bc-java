package org.bouncycastle.crypto.modes.gcm;

import java.util.Vector;

public class Tables1kGCMExponentiator
    implements GCMExponentiator
{
    // A lookup table of the power-of-two powers of 'x'
    // - lookupPowX2[i] = x^(2^i)
    private Vector lookupPowX2;

    public void init(byte[] x)
    {
        long[] y = GCMUtil.asLongs(x);
        if (lookupPowX2 != null && 0L != GCMUtil.areEqual(y, (long[])lookupPowX2.elementAt(0)))
        {
            return;
        }

        lookupPowX2 = new Vector(8);
        lookupPowX2.addElement(y);
    }

    public void exponentiateX(long pow, byte[] output)
    {
        long[] y = GCMUtil.oneAsLongs();
        int bit = 0;
        while (pow > 0)
        {
            if ((pow & 1L) != 0)
            {
                ensureAvailable(bit);
                GCMUtil.multiply(y, (long[])lookupPowX2.elementAt(bit));
            }
            ++bit;
            pow >>>= 1;
        }

        GCMUtil.asBytes(y, output);
    }

    private void ensureAvailable(int bit)
    {
        int last = lookupPowX2.size() - 1;
        if (last < bit)
        {
            long[] prev = (long[])lookupPowX2.elementAt(last);
            do
            {
                long[] next = new long[GCMUtil.SIZE_LONGS];
                GCMUtil.square(prev, next);
                lookupPowX2.addElement(next);
                prev = next;
            }
            while (++last < bit);
        }
    }
}
