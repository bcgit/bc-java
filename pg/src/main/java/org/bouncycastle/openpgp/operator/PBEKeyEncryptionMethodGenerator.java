package org.bouncycastle.openpgp.operator;

import java.security.SecureRandom;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;

/**
 * PGP style PBE encryption method.
 * <p>
 * A pass phrase is used to generate an encryption key using the PGP {@link S2K string-to-key}
 * method. This class always uses the {@link S2K#SALTED_AND_ITERATED salted and iterated form of the
 * S2K algorithm}.
 * </p><p>
 * Note that the iteration count provided to this method is a single byte as described by the
 * {@link S2K} algorithm, and the actual iteration count ranges exponentially from
 * <code>0x01</code> == 1088 to <code>0xFF</code> == 65,011,712.
 * </p>
 */
public abstract class PBEKeyEncryptionMethodGenerator
    extends PGPKeyEncryptionMethodGenerator
{
    private char[] passPhrase;
    private PGPDigestCalculator s2kDigestCalculator;
    private S2K s2k;
    private SecureRandom random;
    private int s2kCount;

    /**
     * Construct a PBE key generator using the default iteration count (<code>0x60</code> == 65536
     * iterations).
     * 
     * @param passPhrase the pass phrase to encrypt with.
     * @param s2kDigestCalculator a digest calculator to use in the string-to-key function.
     */
    protected PBEKeyEncryptionMethodGenerator(
        char[] passPhrase,
        PGPDigestCalculator s2kDigestCalculator)
    {
        this(passPhrase, s2kDigestCalculator, 0x60);
    }

    /**
     * Construct a PBE key generator using a specific iteration level.
     *
     * @param passPhrase the pass phrase to encrypt with.
     * @param s2kDigestCalculator a digest calculator to use in the string-to-key function.
     * @param s2kCount a single byte {@link S2K} iteration count specifier, which is translated to
     *            an actual iteration count by the S2K class.
     */
    protected PBEKeyEncryptionMethodGenerator(
        char[] passPhrase,
        PGPDigestCalculator s2kDigestCalculator,
        int s2kCount)
    {
        this.passPhrase = passPhrase;
        this.s2kDigestCalculator = s2kDigestCalculator;

        if (s2kCount < 0 || s2kCount > 0xff)
        {
            throw new IllegalArgumentException("s2kCount value outside of range 0 to 255.");
        }

        this.s2kCount = s2kCount;
    }

    /**
     * Sets a user defined source of randomness.
     * <p>
     * If no SecureRandom is configured, a default SecureRandom will be used.
     * </p>
     * @return the current generator.
     */
    public PBEKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    /**
     * Generate a key for a symmetric encryption algorithm using the PBE configuration in this
     * method.
     *
     * @param encAlgorithm the {@link SymmetricKeyAlgorithmTags encryption algorithm} to generate
     *            the key for.
     * @return the bytes of the generated key.
     * @throws PGPException if an error occurs performing the string-to-key generation.
     */
    public byte[] getKey(int encAlgorithm)
        throws PGPException
    {
        if (s2k == null)
        {
            byte[]        iv = new byte[8];

            if (random == null)
            {
                random = new SecureRandom();
            }

            random.nextBytes(iv);

            s2k = new S2K(s2kDigestCalculator.getAlgorithm(), iv, s2kCount);
        }

        return PGPUtil.makeKeyFromPassPhrase(s2kDigestCalculator, encAlgorithm, s2k, passPhrase);
    }

    public ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
        throws PGPException
    {
        byte[] key = getKey(encAlgorithm);

        if (sessionInfo == null)
        {
            return new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, null);
        }

        //
        // the passed in session info has the an RSA/ElGamal checksum added to it, for PBE this is not included.
        //
        byte[] nSessionInfo = new byte[sessionInfo.length - 2];

        System.arraycopy(sessionInfo, 0, nSessionInfo, 0, nSessionInfo.length);

        return new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, encryptSessionInfo(encAlgorithm, key, nSessionInfo));
    }

    abstract protected byte[]  encryptSessionInfo(int encAlgorithm, byte[] key, byte[] sessionInfo)
        throws PGPException;
}
