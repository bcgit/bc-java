package org.bouncycastle.openpgp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    @SuppressWarnings("ArrayToString")
    public String toString()
    {
        // mote: we only print the reference to sessionKey to prevent accidental disclosure of the actual key value.
        return algorithm + ":" + sessionKey;
    }

    public static PGPSessionKey fromAsciiRepresentation(String ascii)
    {
        Pattern pattern = Pattern.compile("(\\d{1,3}):([0-9A-Fa-f]+)");
        Matcher matcher = pattern.matcher(ascii);
        if (!matcher.matches())
        {
            throw new IllegalArgumentException("Provided ascii encoding does not match expected format <algo-num>:<hex-key>");
        }
        String alg = matcher.group(1);
        String hexKey = matcher.group(2);

        return new PGPSessionKey(Integer.parseInt(alg), Hex.decode(hexKey));
    }
}
