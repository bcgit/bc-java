package org.bouncycastle.openpgp.operator;

import java.security.SecureRandom;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.Arrays;

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
    private int wrapAlg = -1;

    /**
     * Construct a PBE key generator using the default iteration count (<code>0x60</code> == 65536
     * iterations).
     *
     * @param passPhrase          the pass phrase to encrypt with.
     * @param s2kDigestCalculator a digest calculator to use in the string-to-key function.
     */
    protected PBEKeyEncryptionMethodGenerator(
        char[] passPhrase,
        PGPDigestCalculator s2kDigestCalculator)
    {
        this(passPhrase, s2kDigestCalculator, 0x60);
    }

    /**
     * Construct a PBE key generator using Argon2 as S2K mechanism.
     *
     * @param passPhrase passphrase
     * @param params     argon2 parameters
     */
    protected PBEKeyEncryptionMethodGenerator(
        char[] passPhrase, S2K.Argon2Params params)
    {
        this.passPhrase = passPhrase;
        this.s2k = new S2K(params);
    }

    /**
     * Construct a PBE key generator using a specific iteration level.
     *
     * @param passPhrase          the pass phrase to encrypt with.
     * @param s2kDigestCalculator a digest calculator to use in the string-to-key function.
     * @param s2kCount            a single byte {@link S2K} iteration count specifier, which is translated to
     *                            an actual iteration count by the S2K class.
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
     *
     * @return the current generator.
     */
    public PBEKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    /**
     * Set a specific algorithm to be used where this PBE method generator is
     * used to wrap a session key for encrypting data, rather than providing the
     * encryption key for the data.
     * <p>
     * The default wrapping algorithm is the same algorithm as the one specified for
     * data encryption with the PGPEncryptedDataGenerator used.
     * </p>
     *
     * @return the current generator.
     */
    public PBEKeyEncryptionMethodGenerator setSessionKeyWrapperAlgorithm(int wrapAlg)
    {
        this.wrapAlg = wrapAlg;

        return this;
    }

    /**
     * Return the key wrapping algorithm this PBE key method is associated with.
     *
     * @param defaultWrapAlg the default wrapping algorithm if none was set.
     * @return the PBE method's wrapping algorithm, defaultWrapAlg is setSessionKeyWrapperAlgorithm was not called.
     */
    public int getSessionKeyWrapperAlgorithm(int defaultWrapAlg)
    {
        if (wrapAlg < 0)
        {
            return defaultWrapAlg;
        }

        return wrapAlg;
    }

    /**
     * Generate a key for a symmetric encryption algorithm using the PBE configuration in this
     * method.
     *
     * @param encAlgorithm the {@link SymmetricKeyAlgorithmTags encryption algorithm} to generate
     *                     the key for.
     * @return the bytes of the generated key.
     * @throws PGPException if an error occurs performing the string-to-key generation.
     */
    public byte[] getKey(int encAlgorithm)
        throws PGPException
    {
        if (s2k == null)
        {
            byte[] iv = new byte[8];

            if (random == null)
            {
                random = new SecureRandom();
            }

            random.nextBytes(iv);

            s2k = new S2K(s2kDigestCalculator.getAlgorithm(), iv, s2kCount);
        }

        return PGPUtil.makeKeyFromPassPhrase(s2kDigestCalculator, encAlgorithm, s2k, passPhrase);
    }

    @Override
    public ContainedPacket generateV5(int kekAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
            throws PGPException
    {
        return generate(kekAlgorithm, sessionInfo);
        // TODO: Implement v5 SKESK creation properly.
        // return generateV5ESK(kekAlgorithm, aeadAlgorithm, sessionInfo);
    }

    @Override
    public ContainedPacket generateV6(int kekAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
        throws PGPException
    {
        return generateV6ESK(kekAlgorithm, aeadAlgorithm, sessionInfo);
    }

    // If we use this method, roundtripping v5 AEAD is broken.
    //  TODO: Investigate
    private ContainedPacket generateV5ESK(int kekAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
            throws PGPException
    {
        byte[] ikm = getKey(kekAlgorithm);
        byte[] info = new byte[] {
                (byte) 0xC3,
                (byte) SymmetricKeyEncSessionPacket.VERSION_5,
                (byte) kekAlgorithm,
                (byte) aeadAlgorithm
        };

        byte[] iv = new byte[AEADUtils.getIVLength(aeadAlgorithm)];
        random.nextBytes(iv);

        int tagLen = AEADUtils.getAuthTagLength(aeadAlgorithm);
        byte[] eskAndTag = getEskAndTag(kekAlgorithm, aeadAlgorithm, sessionInfo, ikm, iv, info);
        byte[] esk = Arrays.copyOfRange(eskAndTag, 0, eskAndTag.length - tagLen);
        byte[] tag = Arrays.copyOfRange(eskAndTag, esk.length, eskAndTag.length);

        return SymmetricKeyEncSessionPacket.createV5Packet(kekAlgorithm, aeadAlgorithm, iv, s2k, esk, tag);
    }

    private ContainedPacket generateV6ESK(int kekAlgorithm, int aeadAlgorithm, byte[] sessionInfo)
            throws PGPException
    {
        byte[] ikm = getKey(kekAlgorithm);
        byte[] info = new byte[] {
                (byte) 0xC3,
                (byte) SymmetricKeyEncSessionPacket.VERSION_6,
                (byte) kekAlgorithm,
                (byte) aeadAlgorithm
        };
        byte[] kek = generateV6KEK(kekAlgorithm, ikm, info);

        byte[] iv = new byte[AEADUtils.getIVLength(aeadAlgorithm)];
        random.nextBytes(iv);

        int tagLen = AEADUtils.getAuthTagLength(aeadAlgorithm);
        byte[] eskAndTag = getEskAndTag(kekAlgorithm, aeadAlgorithm, sessionInfo, kek, iv, info);
        byte[] esk = Arrays.copyOfRange(eskAndTag, 0, eskAndTag.length - tagLen);
        byte[] tag = Arrays.copyOfRange(eskAndTag, esk.length, eskAndTag.length);

        return SymmetricKeyEncSessionPacket.createV6Packet(kekAlgorithm, aeadAlgorithm, iv, s2k, esk, tag);
    }

    /**
     * Generate a V4 SKESK packet.
     *
     * @param encAlgorithm the {@link SymmetricKeyAlgorithmTags encryption algorithm} being used
     * @param sessionInfo session data generated by the encrypted data generator.
     * @return v4 SKESK packet
     * @throws PGPException
     */
    public ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
        throws PGPException
    {
        if (sessionInfo == null)
        {
            return SymmetricKeyEncSessionPacket.createV4Packet(encAlgorithm, s2k, null);
        }

        byte[] key = getKey(encAlgorithm);
        //
        // the passed in session info has the an RSA/ElGamal checksum added to it, for PBE this is not included.
        //
        byte[] nSessionInfo = new byte[sessionInfo.length - 2];

        System.arraycopy(sessionInfo, 0, nSessionInfo, 0, nSessionInfo.length);

        return SymmetricKeyEncSessionPacket.createV4Packet(encAlgorithm, s2k, encryptSessionInfo(encAlgorithm, key, nSessionInfo));
    }

    abstract protected byte[] encryptSessionInfo(int encAlgorithm, byte[] key, byte[] sessionInfo)
        throws PGPException;

    abstract protected byte[] getEskAndTag(int kekAlgorithm, int aeadAlgorithm, byte[] sessionInfo, byte[] key, byte[] iv, byte[] info)
        throws PGPException;

    abstract protected byte[] generateV6KEK(int kekAlgorithm, byte[] ikm, byte[] info)
        throws PGPException;
}
