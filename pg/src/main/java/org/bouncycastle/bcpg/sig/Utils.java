package org.bouncycastle.bcpg.sig;

class Utils
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

    /**
     * Convert a one-entry byte array into a boolean.
     * If the byte array doesn't have one entry, or if this entry is neither a 0 nor 1, this method throws an
     * {@link IllegalArgumentException}.
     * A 1 is translated into true, a 0 into false.
     *
     * @param bytes byte array
     * @return boolean
     */
    static boolean booleanFromByteArray(byte[] bytes)
    {
        if (bytes.length != 1)
        {
            throw new IllegalStateException("Byte array has unexpected length. Expected length 1, got " + bytes.length);
        }
        if (bytes[0] == 0)
        {
            return false;
        }
        else if (bytes[0] == 1)
        {
            return true;
        }
        else
        {
            throw new IllegalStateException("Unexpected byte value for boolean encoding: " + bytes[0]);
        }
    }

    static long timeFromBytes(byte[] bytes)
    {
        if (bytes.length != 4)
        {
            throw new IllegalStateException("Byte array has unexpected length. Expected length 4, got " + bytes.length);
        }

        return ((long)(bytes[0] & 0xff) << 24)
            |  ((bytes[1] & 0xff) << 16)
            |  ((bytes[2] & 0xff) << 8)
            |   (bytes[3] & 0xff);
    }

    static byte[] timeToBytes(long t)
    {
        byte[] data = new byte[4];
        data[0] = (byte)(t >> 24);
        data[1] = (byte)(t >> 16);
        data[2] = (byte)(t >> 8);
        data[3] = (byte)t;
        return data;
    }
}
