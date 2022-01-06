package org.bouncycastle.jcajce;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

/**
 * Carrier class for a KEM/KTS secret key plus its encapsulation.
 */
public final class SecretKeyWithEncapsulation
    implements SecretKey
{
    private final SecretKey secretKey;
    private final byte[] encapsulation;

    /**
     * Basic constructor.
     *
     * @param secretKey the secret key that was arrived at.
     * @param encapsulation the encapsulation the key data was carried in.
     */
    public SecretKeyWithEncapsulation(SecretKey secretKey, byte[] encapsulation)
    {
        this.secretKey = secretKey;
        this.encapsulation = Arrays.clone(encapsulation);
    }

    /**
     * Return the algorithm for the agreed secret key.
     *
     * @return the secret key value.
     */
    public String getAlgorithm()
    {
        return secretKey.getAlgorithm();
    }

    /**
     * Return the format for the agreed secret key.
     *
     * @return the secret key format.
     */
    public String getFormat()
    {
        return secretKey.getFormat();
    }

    /**
     * Return the encoding of the agreed secret key.
     *
     * @return the secret key encoding.
     */
    public byte[] getEncoded()
    {
        return secretKey.getEncoded();
    }

    /**
     * Return the encapsulation that carried the key material used in creating the agreed secret key.
     *
     * @return the encrypted encapsulation of the agreed secret key.
     */
    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }

    public boolean equals(Object o)
    {
        return secretKey.equals(o);
    }

    public int hashCode()
    {
        return secretKey.hashCode();
    }
}
