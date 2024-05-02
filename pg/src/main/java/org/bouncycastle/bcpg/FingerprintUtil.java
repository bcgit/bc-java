package org.bouncycastle.bcpg;

public class FingerprintUtil
{

    /**
     * Derive a 64 bit key-id from a version 6 OpenPGP fingerprint.
     * For v6 keys, the key-id corresponds to the left-most 8 octets of the fingerprint.
     *
     * @param v6Fingerprint 32 byte fingerprint
     * @return key-id
     */
    public static long keyIdFromV6Fingerprint(byte[] v6Fingerprint)
    {
        return longFromLeftMostBytes(v6Fingerprint);
    }

    /**
     * Derive a 64 bit key-id from a version 5 LibrePGP fingerprint.
     * For such keys, the key-id corresponds to the left-most 8 octets of the fingerprint.
     *
     * @param v5Fingerprint 32 byte fingerprint
     * @return key-id
     */
    public static long keyIdFromLibrePgpFingerprint(byte[] v5Fingerprint)
    {
        return longFromLeftMostBytes(v5Fingerprint);
    }

    /**
     * Derive a 64 bit key-id from a version 4 OpenPGP fingerprint.
     * For v4 keys, the key-id corresponds to the right-most 8 octets of the fingerprint.
     *
     * @param v4Fingerprint 20 byte fingerprint
     * @return key-id
     */
    public static long keyIdFromV4Fingerprint(byte[] v4Fingerprint)
    {
        return longFromRightMostBytes(v4Fingerprint);
    }

    /**
     * Convert the left-most 8 bytes from the given array to a long.
     *
     * @param bytes bytes
     * @return long
     */
    public static long longFromLeftMostBytes(byte[] bytes)
    {
        if (bytes.length < 8)
        {
            throw new IllegalArgumentException("Byte array MUST contain at least 8 bytes");
        }
        return ((bytes[0] & 0xffL) << 56) |
            ((bytes[1] & 0xffL) << 48) |
            ((bytes[2] & 0xffL) << 40) |
            ((bytes[3] & 0xffL) << 32) |
            ((bytes[4] & 0xffL) << 24) |
            ((bytes[5] & 0xffL) << 16) |
            ((bytes[6] & 0xffL) << 8) |
            ((bytes[7] & 0xffL));
    }

    /**
     * Convert the right-most 8 bytes from the given array to a long.
     *
     * @param bytes bytes
     * @return long
     */
    public static long longFromRightMostBytes(byte[] bytes)
    {
        if (bytes.length < 8)
        {
            throw new IllegalArgumentException("Byte array MUST contain at least 8 bytes");
        }
        int i = bytes.length;
        return ((bytes[i - 8] & 0xffL) << 56) |
            ((bytes[i - 7] & 0xffL) << 48) |
            ((bytes[i - 6] & 0xffL) << 40) |
            ((bytes[i - 5] & 0xffL) << 32) |
            ((bytes[i - 4] & 0xffL) << 24) |
            ((bytes[i - 3] & 0xffL) << 16) |
            ((bytes[i - 2] & 0xffL) << 8) |
            ((bytes[i - 1] & 0xffL));
    }
}
