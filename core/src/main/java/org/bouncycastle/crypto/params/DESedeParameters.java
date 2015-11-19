package org.bouncycastle.crypto.params;

public class DESedeParameters
    extends DESParameters
{
    /*
     * DES-EDE Key length in bytes.
     */
    static public final int DES_EDE_KEY_LENGTH = 24;

    public DESedeParameters(
        byte[]  key)
    {
        super(key);

        if (isWeakKey(key, 0, key.length))
        {
            throw new IllegalArgumentException("attempt to create weak DESede key");
        }
    }

    /**
     * return true if the passed in key is a DES-EDE weak key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     * @param length number of bytes making up the key
     */
    public static boolean isWeakKey(
        byte[]  key,
        int     offset,
        int     length)
    {
        for (int i = offset; i < length; i += DES_KEY_LENGTH)
        {
            if (DESParameters.isWeakKey(key, i))
            {
                return true;
            }
        }

        return false;
    }

    /**
     * return true if the passed in key is a DES-EDE weak key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     */
    public static boolean isWeakKey(
        byte[]  key,
        int     offset)
    {
        return isWeakKey(key, offset, key.length - offset);
    }

    /**
     * return true if the passed in key is a real 2/3 part DES-EDE key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     */
    public static boolean isRealEDEKey(byte[] key, int offset)
    {
        return key.length == 16 ? isReal2Key(key, offset) : isReal3Key(key, offset);
    }

    /**
     * return true if the passed in key is a real 2 part DES-EDE key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     */
    public static boolean isReal2Key(byte[] key, int offset)
    {
        boolean isValid = false;
        for (int i = offset; i != offset + 8; i++)
        {
            if (key[i] != key[i + 8])
            {
                isValid = true;
            }
        }

        return isValid;
    }

    /**
     * return true if the passed in key is a real 3 part DES-EDE key.
     *
     * @param key bytes making up the key
     * @param offset offset into the byte array the key starts at
     */
    public static boolean isReal3Key(byte[] key, int offset)
    {
        boolean diff12 = false, diff13 = false, diff23 = false;
        for (int i = offset; i != offset + 8; i++)
        {
            diff12 |= (key[i] != key[i + 8]);
            diff13 |= (key[i] != key[i + 16]);
            diff23 |= (key[i + 8] != key[i + 16]);
        }
        return diff12 && diff13 && diff23;
    }
}
