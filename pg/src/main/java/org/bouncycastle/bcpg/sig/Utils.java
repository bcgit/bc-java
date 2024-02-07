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
}
