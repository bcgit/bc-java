package org.bouncycastle.openpgp;

import org.bouncycastle.util.encoders.Hex;

public class PGPSessionKey
{
    private final int algorithm;
    private final byte[] sessionKey;

    public PGPSessionKey(int algorithm, byte[] sessionKey)
    {
        this.algorithm = algorithm;
        this.sessionKey = sessionKey;
    }

    public int getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getKey()
    {
        byte[] copy = new byte[sessionKey.length];
        System.arraycopy(sessionKey, 0, copy, 0, sessionKey.length);
        return copy;
    }

    public String toString()
    {
        return algorithm + ":" + sessionKey;
    }

    public static PGPSessionKey fromAsciiRepresentation(String ascii)
    {
        int idx = ascii.indexOf(':');
        if (idx < 0)
        {
            throw new IllegalArgumentException("Provided ascii encoding does not match expected format <algo-num>:<hex-key>");
        }

        return new PGPSessionKey(Integer.parseInt(ascii.substring(0, idx)), Hex.decode(ascii.substring(idx + 1)));
    }
}
