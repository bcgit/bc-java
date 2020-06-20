package org.bouncycastle.crypto.digests;

public class XofUtils
{
    public static byte[] leftEncode(long strLen)
    {
    	byte n = 1;

        long v = strLen;
    	while ((v >>= 8) != 0)
        {
    		n++;
    	}

        byte[] b = new byte[n + 1];

    	b[0] = n;

    	for (int i = 1; i <= n; i++)
    	{
    		b[i] = (byte)(strLen >> (8 * (n - i)));
    	}

    	return b;
    }

    public static byte[] rightEncode(long strLen)
    {
        byte n = 1;

        long v = strLen;
        while ((v >>= 8) != 0)
        {
            n++;
        }

        byte[] b = new byte[n + 1];

        b[n] = n;

        for (int i = 0; i < n; i++)
        {
            b[i] = (byte)(strLen >> (8 * (n - i - 1)));
        }

        return b;
    }
}
