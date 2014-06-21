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
        byte[] result = new byte[40];

        System.arraycopy(sessionInfo, 0, result, 0, sessionInfo.length);

        byte padValue = (byte)(result.length - sessionInfo.length);

        for (int i =  sessionInfo.length; i != result.length; i++)
        {
            result[i] = padValue;
        }

        return result;
    }

    public static byte[] unpadSessionData(byte[] encoded)
        throws PGPException
    {
        byte padValue = encoded[encoded.length - 1];

        for (int i = encoded.length - padValue; i != encoded.length; i++)
        {
            if (encoded[i] != padValue)
            {
                throw new PGPException("bad padding found in session data");
            }
        }

        byte[] taggedKey = new byte[encoded.length - padValue];

        System.arraycopy(encoded, 0, taggedKey, 0, taggedKey.length);

        return taggedKey;
    }
}
