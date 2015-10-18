package org.bouncycastle.openpgp.operator;

import java.security.SecureRandom;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;

public abstract class PBESecretKeyEncryptor
{
    protected int encAlgorithm;
    protected char[] passPhrase;
    protected PGPDigestCalculator s2kDigestCalculator;
    protected int s2kCount;
    protected S2K s2k;

    protected SecureRandom random;

    protected PBESecretKeyEncryptor(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator, SecureRandom random, char[] passPhrase)
    {
        this(encAlgorithm, s2kDigestCalculator, 0x60, random, passPhrase);
    }

    protected PBESecretKeyEncryptor(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator, int s2kCount, SecureRandom random, char[] passPhrase)
    {
        this.encAlgorithm = encAlgorithm;
        this.passPhrase = passPhrase;
        this.random = random;
        this.s2kDigestCalculator = s2kDigestCalculator;

        if (s2kCount < 0 || s2kCount > 0xff)
        {
            throw new IllegalArgumentException("s2kCount value outside of range 0 to 255.");
        }

        this.s2kCount = s2kCount;
    }

    public int getAlgorithm()
    {
        return encAlgorithm;
    }

    public int getHashAlgorithm()
    {
        if (s2kDigestCalculator != null)
        {
            return s2kDigestCalculator.getAlgorithm();
        }

        return -1;
    }

    public byte[] getKey()
        throws PGPException
    {
        return PGPUtil.makeKeyFromPassPhrase(s2kDigestCalculator, encAlgorithm, s2k, passPhrase);
    }

    public S2K getS2K()
    {
        return s2k;
    }

    /**
     * Key encryption method invoked for V4 keys and greater.
     *
     * @param keyData raw key data
     * @param keyOff offset into raw key data
     * @param keyLen length of key data to use.
     * @return an encryption of the passed in keyData.
     * @throws PGPException on error in the underlying encryption process.
     */
    public byte[] encryptKeyData(byte[] keyData, int keyOff, int keyLen)
        throws PGPException
    {
        if (s2k == null)
        {
            byte[] iv = new byte[8];

            random.nextBytes(iv);

            s2k = new S2K(s2kDigestCalculator.getAlgorithm(), iv, s2kCount);
        }

        return encryptKeyData(getKey(), keyData, keyOff, keyLen);
    }

    public abstract byte[] encryptKeyData(byte[] key, byte[] keyData, int keyOff, int keyLen)
        throws PGPException;

    /**
     * Encrypt the passed in keyData using the key and the iv provided.
     * <p>
     * This method is only used for processing version 3 keys.
     * </p>
     */
    public byte[] encryptKeyData(byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
        throws PGPException
    {
        throw new PGPException("encryption of version 3 keys not supported.");
    }

    public abstract byte[] getCipherIV();
}
