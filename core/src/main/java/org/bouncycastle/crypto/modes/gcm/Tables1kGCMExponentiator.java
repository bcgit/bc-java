package org.bouncycastle.crypto.modes.gcm;

import java.util.Vector;

import org.bouncycastle.util.Arrays;

public class Tables1kGCMExponentiator implements GCMExponentiator
{
    // A lookup table of the power-of-two powers of 'x'
    // - lookupPowX2[i] = x^(2^i)
    private Vector lookupPowX2;

    public void init(byte[] x)
    {
        if (lookupPowX2 != null && Arrays.areEqual(x, (byte[])lookupPowX2.elementAt(0)))
        {
            return;
        }

        lookupPowX2 = new Vector(8);
        lookupPowX2.addElement(Arrays.clone(x));
    }

    public void exponentiateX(long pow, byte[] output)
    {
        byte[] y = GCMUtil.oneAsBytes();
        int bit = 0;
        while (pow > 0)
        {
            if ((pow & 1L) != 0)
            {
                ensureAvailable(bit);
                GCMUtil.multiply(y, (byte[])lookupPowX2.elementAt(bit));
            }
            ++bit;
            pow >>>= 1;
        }

        System.arraycopy(y, 0, output, 0, 16);
    }

    private void ensureAvailable(int bit)
    {
        int count = lookupPowX2.size();
        if (count <= bit)
        {
            byte[] tmp = (byte[])lookupPowX2.elementAt(count - 1);
            do
            {
                tmp = Arrays.clone(tmp);
                GCMUtil.multiply(tmp, tmp);
                lookupPowX2.addElement(tmp);
            }
            while (++count <= bit);
        }
    }
}
