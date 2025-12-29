package org.bouncycastle.openpgp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class PGPSessionKey
{
    private static final Pattern ASCII_ENCODING_PATTERN = Pattern.compile("(\\d{1,3}):([0-9A-Fa-f]+)");

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
        return Arrays.clone(sessionKey);
    }

    public String toString()
    {
        // NOTE: Avoid disclosing the sessionKey value.
        String sessionKeyHashCode = Integer.toHexString(System.identityHashCode(sessionKey));

        return algorithm + ":" + sessionKey.getClass().getName() + "@" + sessionKeyHashCode;
    }

    public static PGPSessionKey fromAsciiRepresentation(String ascii)
    {
        Matcher matcher = ASCII_ENCODING_PATTERN.matcher(ascii);
        if (!matcher.matches())
        {
            throw new IllegalArgumentException("Provided ascii encoding does not match expected format <algo-num>:<hex-key>");
        }
        String alg = matcher.group(1);
        String hexKey = matcher.group(2);

        return new PGPSessionKey(Integer.parseInt(alg), Hex.decode(hexKey));
    }
}
