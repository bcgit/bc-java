package org.bouncycastle.math.ec.rfc8032;

abstract class Wnaf
{
    static void getSignedVar(int[] n, int width, byte[] ws)
    {
//        assert 2 <= width && width <= 8;

        int[] t = new int[n.length * 2];
        {
            int c = n[n.length - 1] >> 31, i = n.length, tPos = t.length;
            while (--i >= 0)
            {
                int next = n[i];
                t[--tPos] = (next >>> 16) | (c << 16);
                t[--tPos] = c = next;
            }
        }

        final int lead = 32 - width;

        int j = 0, carry = 0;
        for (int i = 0; i < t.length; ++i, j -= 16)
        {
            int word = t[i];
            while (j < 16)
            {
                int word16 = word >>> j;

                // TODO Consider trailing-zeros approach from bc-csharp
                int bit = word16 & 1;
                if (bit == carry)
                {
                    ++j;
                    continue;
                }

                int digit = (word16 | 1) << lead;
                carry = digit >>> 31;

                ws[(i << 4) + j] = (byte)(digit >> lead);

                j += width;
            }
        }

//        assert carry == n[n.length - 1] >>> 31;
    }
}
