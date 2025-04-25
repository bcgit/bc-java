package org.bouncycastle.openpgp.operator.jcajce;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * JCE based generator for password based encryption (PBE) data protection methods.
 */
public class JcePBEKeyEncryptionMethodGenerator
    extends PBEKeyEncryptionMethodGenerator
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    /**
     * Create a PBE encryption method generator using the provided digest and the default S2K count
     * for key generation.
     *
     * @param passPhrase          the passphrase to use as the primary source of key material.
     * @param s2kDigestCalculator the digest calculator to use for key calculation.
     */
    public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator)
    {
        super(passPhrase, s2kDigestCalculator);
    }

    /**
     * Create a PBE encryption method generator using the default SHA-1 digest and the default S2K
     * count for key generation.
     *
     * @param passPhrase the passphrase to use as the primary source of key material.
     */
    public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase)
    {
        this(passPhrase, new SHA1PGPDigestCalculator());
    }

    /**
     * Create a PBE encryption method generator using the provided calculator and S2K count for key
     * generation.
     *
     * @param passPhrase          the passphrase to use as the primary source of key material.
     * @param s2kDigestCalculator the digest calculator to use for key calculation.
     * @param s2kCount            the single byte {@link S2K} count to use.
     */
    public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator, int s2kCount)
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
    public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase, int s2kCount)
    {
        super(passPhrase, new SHA1PGPDigestCalculator(), s2kCount);
    }

    public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase, S2K.Argon2Params params)
    {
        super(passPhrase, params);
    }

    /**
     * Sets the JCE provider to source cryptographic primitives from.
     *
     * @param provider the JCE provider to use.
     * @return the current generator.
     */
    public JcePBEKeyEncryptionMethodGenerator setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    /**
     * Sets the JCE provider to source cryptographic primitives from.
     *
     * @param providerName the name of the JCE provider to use.
     * @return the current generator.
     */
    public JcePBEKeyEncryptionMethodGenerator setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
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
            String cName = PGPUtil.getSymmetricCipherName(encAlgorithm);
            Cipher c = helper.createCipher(cName + "/CFB/NoPadding");
            SecretKey sKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));
            c.init(Cipher.ENCRYPT_MODE, sKey, new IvParameterSpec(new byte[c.getBlockSize()]));

            return c.doFinal(sessionInfo, 0, sessionInfo.length);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new PGPException("illegal block size: " + e.getMessage(), e);
        }
        catch (BadPaddingException e)
        {
            throw new PGPException("bad padding: " + e.getMessage(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new PGPException("IV invalid: " + e.getMessage(), e);
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("key invalid: " + e.getMessage(), e);
        }
    }

    protected byte[] generateV6KEK(int kekAlgorithm, byte[] ikm, byte[] info)
    {
        return JceAEADUtil.generateHKDFBytes(ikm, null, info, SymmetricKeyUtils.getKeyLengthInOctets(kekAlgorithm));
    }

    protected byte[] getEskAndTag(int kekAlgorithm, int aeadAlgorithm, byte[] sessionKey, byte[] key, byte[] iv, byte[] info)
        throws PGPException
    {
        String algorithm = getBaseAEADAlgorithm(kekAlgorithm);

        Cipher aeadCipher = createAEADCipher(algorithm, aeadAlgorithm);

        try
        {
            aeadCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm), new AEADParameterSpec(iv, 128, info));
            int outLen = aeadCipher.getOutputSize(sessionKey.length);
            byte[] eskAndTag = new byte[outLen];

            int len = aeadCipher.update(sessionKey, 0, sessionKey.length, eskAndTag, 0);

            len += aeadCipher.doFinal(eskAndTag, len);

            if (len < eskAndTag.length)
            {
                byte[] rv = new byte[len];
                System.arraycopy(eskAndTag, 0, rv, 0, len);
                return rv;
            }

            return eskAndTag;
        }
        catch (GeneralSecurityException e)
        {
            throw new PGPException("cannot encrypt session info", e);
        }
    }

    private static String getBaseAEADAlgorithm(int encAlgorithm)
        throws PGPException
    {
        if (encAlgorithm == SymmetricKeyAlgorithmTags.AES_128
            || encAlgorithm == SymmetricKeyAlgorithmTags.AES_192
            || encAlgorithm == SymmetricKeyAlgorithmTags.AES_256)
        {
            return "AES";
        }
        else if (encAlgorithm == SymmetricKeyAlgorithmTags.CAMELLIA_128
            || encAlgorithm == SymmetricKeyAlgorithmTags.CAMELLIA_192
            || encAlgorithm == SymmetricKeyAlgorithmTags.CAMELLIA_256)
        {
            return "Camellia";
        }
        throw new PGPException("AEAD only supported for AES and Camellia based algorithms");
    }

    private Cipher createAEADCipher(String algorithm, int aeadAlgorithm)
        throws PGPException
    {
        // Block Cipher must work on 16 byte blocks
        switch (aeadAlgorithm)
        {
        case AEADAlgorithmTags.EAX:
            return helper.createCipher(algorithm + "/EAX/NoPadding");
        case AEADAlgorithmTags.OCB:
            return helper.createCipher(algorithm + "/OCB/NoPadding");
        case AEADAlgorithmTags.GCM:
            return helper.createCipher(algorithm + "/GCM/NoPadding");
        default:
            throw new PGPException("unrecognised AEAD algorithm: " + aeadAlgorithm);
        }
    }
}
