package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;

/**
 * A factory for performing PBE decryption operations.
 */
public abstract class PBEDataDecryptorFactory
    implements PGPDataDecryptorFactory
{
    private char[] passPhrase;
    private PGPDigestCalculatorProvider calculatorProvider;

    /**
     * Construct a PBE data decryptor factory.
     *
     * @param passPhrase the pass phrase to generate decryption keys with.
     * @param calculatorProvider the digest to use in key generation.
     */
    protected PBEDataDecryptorFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
    {
        this.passPhrase = passPhrase;
        this.calculatorProvider = calculatorProvider;
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
        return PGPUtil.makeKeyFromPassPhrase(calculatorProvider, keyAlgorithm, s2k, passPhrase);
    }

    /**
     * Decrypts session data from an encrypted data packet.
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
}
