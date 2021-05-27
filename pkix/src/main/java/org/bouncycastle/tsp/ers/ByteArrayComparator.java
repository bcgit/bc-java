package org.bouncycastle.tsp.ers;

import java.util.Comparator;

/**
 * Comparator for byte arrays for ERS hash sorting.
 */
class ByteArrayComparator
    implements Comparator
{
    public int compare(Object l, Object r)
    {
        byte[] left = (byte[])l;
        byte[] right = (byte[])r;
        for (int i = 0; i < left.length && i < right.length; i++)
        {
            int a = (left[i] & 0xff);
            int b = (right[i] & 0xff);

            if (a != b)
            {
                return a - b;
            }
        }
        return left.length - right.length;
    }
}
