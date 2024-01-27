package org.bouncycastle.util;

public class Booleans {

    /**
     * Convert the given boolean value into a one-entry byte array, where true is represented by a 1 and false is a 0.
     * @param bool boolean value
     * @return byte array
     */
    public static byte[] toByteArray(boolean bool)
    {
        byte[] bytes = new byte[1];
        if (bool)
        {
            bytes[0] = 1;
        }
        return bytes;
    }

    /**
     * Convert a one-entry byte array into a boolean.
     * If the byte array doesn't have one entry, or if this entry is neither a 0 nor 1, this method throws an
     * {@link IllegalArgumentException}.
     * A 1 is translated into true, a 0 into false.
     * @param bytes byte array
     * @return boolean
     */
    public static boolean fromByteArray(byte[] bytes)
    {
        if (bytes.length != 1)
        {
            throw new IllegalArgumentException("Byte array has unexpected length. Expected length 1, got " + bytes.length);
        }
        if (bytes[0] == 0)
        {
            return false;
        }
        else if (bytes[0] == 1)
        {
            return true;
        }
        else throw new IllegalArgumentException("Unexpected byte value for boolean encoding: " + bytes[0]);
    }
}
