package org.bouncycastle.openpgp.operator.bc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * A BC lightweight method generator for supporting PBE based encryption operations.
 */
public class BcPBEKeyEncryptionMethodGenerator
    extends PBEKeyEncryptionMethodGenerator
{
    /**
     *  Create a PBE encryption method generator using the provided calculator for key calculation.
     *
     * @param passPhrase  the passphrase to use as the primary source of key material.
     * @param s2kDigestCalculator  the digest calculator to use for key calculation.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator)
    {
        super(passPhrase, s2kDigestCalculator);
    }

    /**
     * Create a PBE encryption method generator using the default SHA-1 digest calculator for key calculation.
     *
     * @param passPhrase  the passphrase to use as the primary source of key material.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase)
    {
        this(passPhrase, new SHA1PGPDigestCalculator());
    }

    /**
     *  Create a PBE encryption method generator using the provided calculator and S2K count for key calculation.
     *
     * @param passPhrase  the passphrase to use as the primary source of key material.
     * @param s2kDigestCalculator  the digest calculator to use for key calculation.
     * @param s2kCount the S2K count to use.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator, int s2kCount)
    {
        super(passPhrase, s2kDigestCalculator, s2kCount);
    }

    /**
     * Create a PBE encryption method generator using the default SHA-1 digest calculator and
     * a S2K count other than the default of 0x60  for key calculation.
     *
     * @param passPhrase the passphrase to use as the primary source of key material.
     * @param s2kCount the S2K count to use.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, int s2kCount)
    {
        super(passPhrase, new SHA1PGPDigestCalculator(), s2kCount);
    }

    /**
     * Provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current generator.
     */
    public PBEKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        super.setSecureRandom(random);

        return this;
    }

    protected byte[] encryptSessionInfo(int encAlgorithm, byte[] key, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);
            BufferedBlockCipher cipher = BcUtil.createSymmetricKeyWrapper(true, engine, key, new byte[engine.getBlockSize()]);

            byte[] out = new byte[sessionInfo.length];

            int len = cipher.processBytes(sessionInfo, 0, sessionInfo.length, out, 0);

            len += cipher.doFinal(out, len);

            return out;
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("encryption failed: " + e.getMessage(), e);
        }
    }
}
