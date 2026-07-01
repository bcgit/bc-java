package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;

/**
 * A factory for performing PBE decryption operations.
 * The purpose of this class is to act as an abstract factory, whose subclasses can decide, which concrete
 * implementation to use for symmetric decryption of SKESK (symmetric-key-encrypted session-key) packets.
 */
public abstract class PBEDataDecryptorFactory
    implements PGPDataDecryptorFactory
{
    private char[] passPhrase;
    private PGPDigestCalculatorProvider calculatorProvider;
    private PGPS2KCalculator s2kCalculator;

    /**
     * Construct a PBE data decryptor factory.
     *
     * @param passPhrase the pass phrase to generate decryption keys with.
     * @param calculatorProvider the digest to use in key generation.
     */
    protected PBEDataDecryptorFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
    {
        this(passPhrase, calculatorProvider, null);
    }

    /**
     * Construct a PBE data decryptor factory.
     *
     * @param passPhrase the pass phrase to generate decryption keys with.
     * @param calculatorProvider the digest to use in hash-based key generation.
     * @param s2kCalculator the calculator to use for memory-hard (Argon2) S2K key generation; may be
     *                      null if Argon2 S2K specifiers are not expected.
     */
    protected PBEDataDecryptorFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider, PGPS2KCalculator s2kCalculator)
    {
        this.passPhrase = passPhrase;
        this.calculatorProvider = calculatorProvider;
        this.s2kCalculator = s2kCalculator;
    }

    /**
     * Generates an encryption key using the pass phrase and digest calculator configured for this
     * factory.
     *
     * @param keyAlgorithm the {@link SymmetricKeyAlgorithmTags encryption algorithm} to generate a
     *            key for.
     * @param s2k the string-to-key specification to use to generate the key.
     * @return the key bytes for the encryption algorithm, generated using the pass phrase of this
     *         factory.
     * @throws PGPException if an error occurs generating the key.
     */
    public byte[] makeKeyFromPassPhrase(int keyAlgorithm, S2K s2k)
        throws PGPException
    {
        if (s2k.getType() == S2K.ARGON_2)
        {
            return PGPUtil.makeKeyFromPassPhrase(s2kCalculator, keyAlgorithm, s2k, passPhrase);
        }
        return PGPUtil.makeKeyFromPassPhrase(new PGPUtil.HashBasedS2KCalculator(calculatorProvider.get(s2k.getHashAlgorithm())), keyAlgorithm, s2k, passPhrase);
    }

    /**
     * Decrypts session data from a {@link SymmetricKeyEncSessionPacket#VERSION_4 v4 SKESK} packet.
     * These are used in OpenPGP v4.
     *
     * @param keyAlgorithm the {@link SymmetricKeyAlgorithmTags encryption algorithm} used to
     *            encrypt the session data.
     * @param key the key bytes for the encryption algorithm.
     * @param seckKeyData the encrypted session data to decrypt.
     * @return the decrypted session data.
     * @throws PGPException if an error occurs decrypting the session data.
     */
    public abstract byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] seckKeyData)
        throws PGPException;

    /**
     * Recover the session data of a {@link SymmetricKeyEncSessionPacket#VERSION_5 v5 SKESK} or
     * {@link SymmetricKeyEncSessionPacket#VERSION_6 v6 SKESK} packet.
     * These are used in OpenPGP v5 and v6.
     *
     * @param keyData v5 or v6 SKESK packet
     * @param ikm initial keying material (e.g. S2K result)
     * @return session key
     * @throws PGPException
     */
    public abstract byte[] recoverAEADEncryptedSessionData(SymmetricKeyEncSessionPacket keyData, byte[] ikm)
            throws PGPException;
}
