package org.bouncycastle.openpgp.operator;

import java.security.SecureRandom;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;

/**
 * Class responsible for encrypting secret key material or data packets using a passphrase.
 * <p>
 * RFC9580 recommends the following S2K specifiers + usages:
 * <table border="1">
 * <tr>
 *     <th>S2K Specifier</th>
 *     <th>S2K Usage</th>
 *     <th>Note</th>
 * </tr>
 * <tr>
 *     <td>{@link S2K#ARGON_2}</td>
 *     <td>{@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_AEAD}</td>
 *     <td>RECOMMENDED; Argon2 MUST be used with AEAD</td>
 * </tr>
 * <tr>
 *     <td>{@link S2K#SALTED_AND_ITERATED}</td>
 *     <td>{@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_SHA1}</td>
 *     <td>MAY be used if Argon2 is not available; Take care to use high octet count + strong passphrase</td>
 * </tr>
 * <tr>
 *     <td>none</td>
 *     <td>{@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_NONE}</td>
 *     <td>Unprotected</td>
 * </tr>
 * </table>
 * <p>
 * Additionally, implementations MAY use the following combinations with caution:
 * <table>
 * <tr>
 *     <th>S2K Specifier</th>
 *     <th>S2K Usage</th>
 *     <th>Note</th>
 * </tr>
 * <tr>
 *     <td>{@link S2K#SALTED_AND_ITERATED}</td>
 *     <td>{@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_AEAD}</td>
 *     <td>Does not provide memory hardness</td>
 * </tr>
 * <tr>
 *     <td>{@link S2K#SIMPLE}</td>
 *     <td>{@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_SHA1}</td>
 *     <td>Only for reading secret keys in backwards compatibility mode</td>
 * </tr>
 * </table>
 */
public abstract class PBESecretKeyEncryptor
{
    protected int encAlgorithm;
    protected int aeadAlgorithm;
    protected char[] passPhrase;
    protected PGPDigestCalculator s2kDigestCalculator;
    protected int s2kCount;
    protected S2K s2k;

    protected SecureRandom random;

    protected PBESecretKeyEncryptor(int encAlgorithm, int aeadAlgorithm, S2K.Argon2Params argon2Params, SecureRandom random, char[] passPhrase)
    {
        this.encAlgorithm = encAlgorithm;
        this.aeadAlgorithm = aeadAlgorithm;
        this.passPhrase = passPhrase;
        this.s2k = S2K.argon2S2K(argon2Params);
        this.random = random;
    }

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

    public int getAeadAlgorithm()
    {
        return aeadAlgorithm;
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
