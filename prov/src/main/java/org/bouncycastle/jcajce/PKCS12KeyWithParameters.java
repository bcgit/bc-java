package org.bouncycastle.jcajce;

import javax.crypto.interfaces.PBEKey;

public class PKCS12KeyWithParameters
    extends PKCS12Key implements PBEKey
{
    private final byte[] salt;
    private final int iterationCount;

    /**
     * Basic constructor for a password based key with generation parameters.
     *
     * @param password password to use.
     * @param salt salt for generation algorithm
     * @param iterationCount iteration count for generation algorithm.
     */
    public PKCS12KeyWithParameters(char[] password, byte[] salt, int iterationCount)
    {
        super(password);

        this.salt = salt.clone();
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
