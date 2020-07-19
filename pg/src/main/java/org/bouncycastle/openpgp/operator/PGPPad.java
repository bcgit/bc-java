package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

/**
 * Utility class that provides padding addition and removal for PGP session keys.
 */
public class PGPPad
{
    private PGPPad()
    {

    }

    public static byte[] padSessionData(byte[] sessionInfo)
    {
        return padSessionData(sessionInfo, true);
    }

    public static byte[] padSessionData(byte[] sessionInfo, boolean obfuscate)
    {
        int length = sessionInfo.length;
        int paddedLength = ((length >>> 3) + 1) << 3;

        if (obfuscate)
        {
            paddedLength = Math.max(40, paddedLength);
        }

        int padCount = paddedLength - length;
        byte padByte = (byte)padCount;

        byte[] result = new byte[paddedLength];
        System.arraycopy(sessionInfo, 0, result, 0, length);
        for (int i = length; i < paddedLength; ++i)
        {
            result[i] = padByte;
        }
        return result;
    }

    public static byte[] unpadSessionData(byte[] encoded)
        throws PGPException
    {
        int paddedLength = encoded.length;
        byte padByte = encoded[paddedLength - 1];
        int padCount = padByte & 0xFF;
        int length = paddedLength - padCount;
        int last = length - 1;

        int diff = 0;
        for (int i = 0; i < paddedLength; ++i)
        {
            int mask = (last - i) >> 31;
            diff |= (padByte ^ encoded[i]) & mask;
        }

        diff |= paddedLength & 7;
        diff |= (40 - paddedLength) >> 31;

        if (diff != 0)
        {
            throw new PGPException("bad padding found in session data");
        }

        byte[] result = new byte[length];
        System.arraycopy(encoded, 0, result, 0, length);
        return result;
    }
}
