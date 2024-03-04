package org.bouncycastle.bcpg.sig;

public class Utils
{
    /**
     * Convert the given boolean value into a one-entry byte array, where true is represented by a 1 and false is a 0.
     * mentioned in https://github.com/bcgit/bc-java/pull/1575/
     * @param  value
     * @return byte array
     */
    static byte[] booleanToByteArray(boolean value)
    {
        byte[] data = new byte[1];

        if (value)
        {
            data[0] = 1;
        }
        return data;
    }

    protected static byte[] timeToBytes(
        long    t)
    {
        byte[]    data = new byte[4];

        data[0] = (byte)(t >> 24);
        data[1] = (byte)(t >> 16);
        data[2] = (byte)(t >> 8);
        data[3] = (byte)t;

        return data;
    }
}
