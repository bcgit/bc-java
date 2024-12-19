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
 * method.
 * </p><p>
 * Note that the iteration count provided to this method is a single byte as described by the
 * {@link S2K} algorithm, and the actual iteration count ranges exponentially from
 * <code>0x01</code> == 1088 to <code>0xFF</code> == 65,011,712.
 * </p>
 */
public abstract class PBEKeyEncryptionMethodGenerator
    implements PGPKeyEncryptionMethodGenerator
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

    /**
     * Generates a version 4 Symmetric-Key-Encrypted-Session-Key (SKESK) packet, encoding the encrypted
     * session-key for this method.
     * SKESKv4 packets are used by Symmetrically-Encrypted-Integrity-Protected-Data (SEIPD) packets
     * of version 1, or by (deprecated) Symmetrically-Encrypted-Data (SED) packets.
     * <p/>
     * Generates a version 5 Symmetric-Key-Encrypted-Session-Key (SKESK) packet, encoding the encrypted
     * session-key for this method.
     * SKESKv5 packets are used with {@link org.bouncycastle.bcpg.AEADEncDataPacket OCB-Encrypted Data (OED) packets}
     * only.
     * AEAD algorithm ID (MUST be {@link org.bouncycastle.bcpg.AEADAlgorithmTags#OCB})
     * <p/>
     * Generates a version 6 Symmetric-Key-Encrypted-Session-Key (SKESK) packet, encoding the encrypted
     * session-key for this method.
     * SKESKv6 packets are used with Symmetrically-Encrypted Integrity-Protected Data (SEIPD) packets of
     * version 2 only.
     * A SKESKv6 packet MUST NOT precede a SEIPDv1, OED or SED packet.
     *
     * @param sessionKey session data generated by the encrypted data generator.
     * @return a packet encoding the provided information and the configuration of this instance.
     * @throws PGPException if an error occurs constructing the packet.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-4-symmetric-key-enc">
     * RFC9580 - Symmetric-Key Encrypted Session-Key Packet version 4</a>
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-02.html#section-5.3-8">
     * LibrePGP - Symmetric-Key Encrypted Session-Key Packet version 5</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-symmetric-key-enc">
     * RFC9580 - Symmetric-Key Encrypted Session-Key Packet version 6</a>
     */
    public ContainedPacket generate(PGPDataEncryptorBuilder dataEncryptorBuilder, byte[] sessionKey)
        throws PGPException
    {
        int kekAlgorithm = getSessionKeyWrapperAlgorithm(dataEncryptorBuilder.getAlgorithm());
        if (dataEncryptorBuilder.getAeadAlgorithm() <= 0)
        {
            if (sessionKey == null)
            {
                return SymmetricKeyEncSessionPacket.createV4Packet(kekAlgorithm, s2k, null);
            }

            byte[] key = getKey(kekAlgorithm);

            return SymmetricKeyEncSessionPacket.createV4Packet(kekAlgorithm, s2k, encryptSessionInfo(kekAlgorithm, key,
                Arrays.prepend(sessionKey, (byte)dataEncryptorBuilder.getAlgorithm())));
        }
        else
        {
            int aeadAlgorithm = dataEncryptorBuilder.getAeadAlgorithm();
            int version = dataEncryptorBuilder.isV5StyleAEAD() ? SymmetricKeyEncSessionPacket.VERSION_5 : SymmetricKeyEncSessionPacket.VERSION_6;
            byte[] ikm = getKey(kekAlgorithm);
            byte[] info = new byte[]{
                (byte)0xC3,
                (byte)version,
                (byte)kekAlgorithm,
                (byte)aeadAlgorithm
            };

            if (version == 6)
            {
                ikm = generateV6KEK(kekAlgorithm, ikm, info); // ikm is kek
            }

            byte[] iv = new byte[AEADUtils.getIVLength(aeadAlgorithm)];
            random.nextBytes(iv);

            int tagLen = AEADUtils.getAuthTagLength(aeadAlgorithm);
            byte[] eskAndTag = getEskAndTag(kekAlgorithm, aeadAlgorithm, sessionKey, ikm, iv, info);
            byte[] esk = Arrays.copyOfRange(eskAndTag, 0, eskAndTag.length - tagLen);
            byte[] tag = Arrays.copyOfRange(eskAndTag, esk.length, eskAndTag.length);

            if (version == SymmetricKeyEncSessionPacket.VERSION_5)
            {
                return SymmetricKeyEncSessionPacket.createV5Packet(kekAlgorithm, aeadAlgorithm, iv, s2k, esk, tag);
            }
            else
            {
                return SymmetricKeyEncSessionPacket.createV6Packet(kekAlgorithm, aeadAlgorithm, iv, s2k, esk, tag);
            }
        }
    }

    abstract protected byte[] encryptSessionInfo(int encAlgorithm, byte[] key, byte[] sessionInfo)
        throws PGPException;

    abstract protected byte[] getEskAndTag(int kekAlgorithm, int aeadAlgorithm, byte[] sessionKey, byte[] key, byte[] iv, byte[] info)
        throws PGPException;

    abstract protected byte[] generateV6KEK(int kekAlgorithm, byte[] ikm, byte[] info)
        throws PGPException;
}
