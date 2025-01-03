package org.bouncycastle.bcpg;

import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import java.util.Locale;

public class FingerprintUtil
{

    /**
     * Derive a key-id from the given key fingerprint.
     * This method can derive key-ids from v4, v5 (LibrePGP) and v6 keys.
     * For keys with other versions (2,3) it will return 0.
     *
     * @param keyVersion version of the key
     * @param fingerprint fingerprint of the key
     * @return derived key-id
     */
    public static long keyIdFromFingerprint(int keyVersion, byte[] fingerprint)
    {
        switch (keyVersion)
        {
            case PublicKeyPacket.VERSION_4:
                return keyIdFromV4Fingerprint(fingerprint);
            case PublicKeyPacket.LIBREPGP_5:
                return keyIdFromLibrePgpFingerprint(fingerprint);
            case PublicKeyPacket.VERSION_6:
                return keyIdFromV6Fingerprint(fingerprint);
            default:
                return 0;
        }
    }

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
        return readKeyID(bytes);
    }

    /**
     * Convert the right-most 8 bytes from the given array to a long.
     *
     * @param bytes bytes
     * @return long
     */
    public static long longFromRightMostBytes(byte[] bytes)
    {
        return readKeyID(bytes, bytes.length - 8);
    }

    /**
     * Read a key-ID from the first 8 octets of the given byte array.
     * @param bytes byte array
     * @return key-ID
     */
    public static long readKeyID(byte[] bytes)
    {
        return readKeyID(bytes, 0);
    }

    /**
     * Read a key-ID from 8 octets of the given byte array starting at offset.
     * @param bytes byte array
     * @param offset offset
     * @return key-ID
     */
    public static long readKeyID(byte[] bytes, int offset)
    {
        if (bytes.length < 8)
        {
            throw new IllegalArgumentException("Byte array MUST contain at least 8 bytes");
        }
        return Pack.bigEndianToLong(bytes, offset);
    }

    /**
     * Write the key-ID encoded as 8 octets to the given byte array, starting at index offset.
     * @param keyID keyID
     * @param bytes byte array
     * @param offset starting offset
     */
    public static void writeKeyID(long keyID, byte[] bytes, int offset)
    {
        if (bytes.length - offset < 8)
        {
            throw new IllegalArgumentException("Not enough space to write key-ID to byte array.");
        }
        Pack.longToBigEndian(keyID, bytes, offset);
    }

    /**
     * Write the key-ID to the first 8 octets of the given byte array.
     * @param keyID keyID
     * @param bytes byte array
     */
    public static void writeKeyID(long keyID, byte[] bytes)
    {
        writeKeyID(keyID, bytes, 0);
    }

    public static String prettifyFingerprint(byte[] fingerprint)
    {
        // -DM Hex.toHexString
        char[] hex = Hex.toHexString(fingerprint).toUpperCase(Locale.getDefault()).toCharArray();
        StringBuilder sb = new StringBuilder();
        switch (hex.length)
        {
            case 32:
                // v3 keys
                for (int i = 0; i < 4; i++)
                {
                    sb.append(hex, i * 4, 4).append(' ');
                }
                sb.append(' ');
                for (int i = 4; i < 7; i++)
                {
                    sb.append(hex, i * 4, 4).append(' ');
                }
                sb.append(hex, 28, 4);
                return sb.toString();
            case 40:
                // v4 keys
                for (int i = 0; i <= 4; i++)
                {
                    sb.append(hex, i * 4, 4).append(' ');
                }
                sb.append(' ');
                for (int i = 5; i <= 8; i++)
                { 
                    sb.append(hex, i * 4, 4).append(' ');
                }
                sb.append(hex, 36, 4);
                return sb.toString();
            case 64:
                // v5, v6 keys
                for (int i = 0; i < 4; i++)
                {
                    sb.append(hex, i * 8, 8).append(' ');
                }
                sb.append(' ');
                for (int i = 4; i < 7; i++)
                {
                    sb.append(hex, i * 8, 8).append(' ');
                }
                sb.append(hex, 56, 8);
                return sb.toString();
            default:
                return new String(hex);
        }
    }
}
