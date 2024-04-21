package org.bouncycastle.openpgp.operator.bc;

import java.security.SecureRandom;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
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
     * Create a PBE encryption method generator using the provided digest and the default S2K count
     * for key generation.
     *
     * @param passPhrase          the passphrase to use as the primary source of key material.
     * @param s2kDigestCalculator the digest calculator to use for key calculation.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator)
    {
        super(passPhrase, s2kDigestCalculator);
    }

    /**
     * Create a PBE encryption method generator using the default SHA-1 digest and the default S2K
     * count for key generation.
     *
     * @param passPhrase the passphrase to use as the primary source of key material.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase)
    {
        this(passPhrase, new SHA1PGPDigestCalculator());
    }

    /**
     * Create a PBE encryption method generator using Argon2 for S2K key generation.
     *
     * @param passPhrase   passphrase
     * @param argon2Params parameters for argon2
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, S2K.Argon2Params argon2Params)
    {
        super(passPhrase, argon2Params);
    }

    /**
     * Create a PBE encryption method generator using the provided calculator and S2K count for key
     * generation.
     *
     * @param passPhrase          the passphrase to use as the primary source of key material.
     * @param s2kDigestCalculator the digest calculator to use for key calculation.
     * @param s2kCount            the single byte {@link S2K} count to use.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator, int s2kCount)
    {
        super(passPhrase, s2kDigestCalculator, s2kCount);
    }

    /**
     * Create a PBE encryption method generator using the default SHA-1 digest calculator and a S2K
     * count other than the default for key generation.
     *
     * @param passPhrase the passphrase to use as the primary source of key material.
     * @param s2kCount   the single byte {@link S2K} count to use.
     */
    public BcPBEKeyEncryptionMethodGenerator(char[] passPhrase, int s2kCount)
    {
        super(passPhrase, new SHA1PGPDigestCalculator(), s2kCount);
    }

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

    protected byte[] generateV6KEK(int kekAlgorithm, byte[] ikm, byte[] info)
        throws PGPException
    {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, null, info));

        int kekLen = SymmetricKeyUtils.getKeyLengthInOctets(kekAlgorithm);
        byte[] kek = new byte[kekLen];
        hkdf.generateBytes(kek, 0, kek.length);
        return kek;
    }

    protected byte[] getEskAndTag(int kekAlgorithm, int aeadAlgorithm, byte[] sessionInfo, byte[] key, byte[] iv, byte[] info)
        throws PGPException
    {
        byte[] sessionKey = new byte[sessionInfo.length - 3];
        System.arraycopy(sessionInfo, 1, sessionKey, 0, sessionKey.length);

        AEADCipher aeadCipher = BcAEADUtil.createAEADCipher(kekAlgorithm, aeadAlgorithm);
        aeadCipher.init(true, new AEADParameters(new KeyParameter(key), 128, iv, info));
        int outLen = aeadCipher.getOutputSize(sessionKey.length);
        byte[] eskAndTag = new byte[outLen];
        int len = aeadCipher.processBytes(sessionKey, 0, sessionKey.length, eskAndTag, 0);
        try
        {
            len += aeadCipher.doFinal(eskAndTag, len);
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("cannot encrypt session info", e);
        }
        return eskAndTag;
    }
}
