package org.bouncycastle.jcajce;

import javax.crypto.interfaces.PBEKey;

import org.bouncycastle.crypto.CharToByteConverter;
import org.bouncycastle.util.Arrays;

public class PBKDF1KeyWithParameters
    extends PBKDF1Key implements PBEKey
{
    private final byte[] salt;
    private final int iterationCount;

    /**
     * Basic constructor for a password based key with generation parameters for PBKDF1.
     *
     * @param password password to use.
     * @param converter the converter to use to turn the char array into octets.
     * @param salt salt for generation algorithm
     * @param iterationCount iteration count for generation algorithm.
     */
    public PBKDF1KeyWithParameters(char[] password, CharToByteConverter converter, byte[] salt, int iterationCount)
    {
        super(password, converter);

        this.salt = Arrays.clone(salt);
        this.iterationCount = iterationCount;
    }

    public byte[] getSalt()
    {
        return salt;
    }

    public int getIterationCount()
    {
        return iterationCount;
    }
}
