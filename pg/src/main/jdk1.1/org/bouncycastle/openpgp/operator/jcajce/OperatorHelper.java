package org.bouncycastle.openpgp.operator.jcajce;

import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

class OperatorHelper
{
    private JcaJceHelper helper;

    OperatorHelper(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    MessageDigest createDigest(int algorithm)
        throws GeneralSecurityException, PGPException
    {
        MessageDigest dig;

        try
        {
            dig = helper.createDigest(PGPUtil.getDigestName(algorithm));
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new PGPException("cannot find algorithm: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new PGPException("cannot find provider: " + e.getMessage(), e);
        }

        return dig;
    }

    KeyFactory createKeyFactory(String algorithm)
        throws GeneralSecurityException, PGPException
    {
        try
        {
            return helper.createKeyFactory(algorithm);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new PGPException("cannot find algorithm: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new PGPException("cannot find provider: " + e.getMessage(), e);
        }
    }

    public KeyAgreement createKeyAgreement(String algorithm)
        throws GeneralSecurityException
    {
        try
        {
            return helper.createKeyAgreement(algorithm);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new GeneralSecurityException("cannot find algorithm: " + e.getMessage());
        }
        catch (NoSuchProviderException e)
        {
            throw new GeneralSecurityException("cannot find provider: " + e.getMessage());
        }
    }

    public KeyPairGenerator createKeyPairGenerator(String algorithm)
        throws GeneralSecurityException
    {
        try
        {
            return helper.createKeyPairGenerator(algorithm);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new GeneralSecurityException("cannot find algorithm: " + e.getMessage());
        }
        catch (NoSuchProviderException e)
        {
            throw new GeneralSecurityException("cannot find provider: " + e.getMessage());
        }
    }

    PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        try
        {
            SecretKey secretKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));

            final Cipher c = createStreamCipher(encAlgorithm, withIntegrityPacket);

            if (withIntegrityPacket)
            {
                byte[] iv = new byte[c.getBlockSize()];

                c.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
            else
            {
                c.init(Cipher.DECRYPT_MODE, secretKey);
            }

            return new PGPDataDecryptor()
            {
                public InputStream getInputStream(InputStream in)
                {
                    return new CipherInputStream(in, c);
                }

                public int getBlockSize()
                {
                    return c.getBlockSize();
                }

                public PGPDigestCalculator getIntegrityCalculator()
                {
                    return new SHA1PGPDigestCalculator();
                }
            };
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }

    Cipher createStreamCipher(int encAlgorithm, boolean withIntegrityPacket)
        throws PGPException
    {
        String mode = (withIntegrityPacket)
            ? "CFB"
            : "OpenPGPCFB";

        String cName = PGPUtil.getSymmetricCipherName(encAlgorithm)
            + "/" + mode + "/NoPadding";

        return createCipher(cName);
    }

    Cipher createCipher(String cipherName)
        throws PGPException
    {
        try
        {
            return helper.createCipher(cipherName);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new PGPException("cannot create cipher: " + e.getMessage(), e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new PGPException("cannot create cipher: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new PGPException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    Cipher createPublicKeyCipher(int encAlgorithm)
        throws PGPException
    {
        switch (encAlgorithm)
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
            return createCipher("RSA/ECB/PKCS1Padding");
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            return createCipher("ElGamal/ECB/PKCS1Padding");
        case PGPPublicKey.DSA:
            throw new PGPException("Can't use DSA for encryption.");
        case PGPPublicKey.ECDSA:
            throw new PGPException("Can't use ECDSA for encryption.");
        default:
            throw new PGPException("unknown asymmetric algorithm: " + encAlgorithm);
        }
    }

    Cipher createKeyWrapper(int encAlgorithm)
        throws PGPException
    {
        try
        {
            switch (encAlgorithm)
            {
            case SymmetricKeyAlgorithmTags.AES_128:
            case SymmetricKeyAlgorithmTags.AES_192:
            case SymmetricKeyAlgorithmTags.AES_256:
                return helper.createCipher("AESWrap");
            case SymmetricKeyAlgorithmTags.CAMELLIA_128:
            case SymmetricKeyAlgorithmTags.CAMELLIA_192:
            case SymmetricKeyAlgorithmTags.CAMELLIA_256:
                return helper.createCipher("CamelliaWrap");
            default:
                throw new PGPException("unknown wrap algorithm: " + encAlgorithm);
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new PGPException("cannot create cipher: " + e.getMessage(), e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new PGPException("cannot create cipher: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new PGPException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    private Signature createSignature(String cipherName)
        throws PGPException
    {
        try
        {
            return helper.createSignature(cipherName);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new PGPException("cannot create signature: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new PGPException("cannot create signature: " + e.getMessage(), e);
        }
    }

    public Signature createSignature(int keyAlgorithm, int hashAlgorithm)
        throws PGPException
    {
        String     encAlg;

        switch (keyAlgorithm)
        {
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        case PublicKeyAlgorithmTags.RSA_SIGN:
            encAlg = "RSA";
            break;
        case PublicKeyAlgorithmTags.DSA:
            encAlg = "DSA";
            break;
        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT: // in some malformed cases.
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            encAlg = "ElGamal";
            break;
        case PublicKeyAlgorithmTags.ECDSA:
            encAlg = "ECDSA";
            break;
        case PublicKeyAlgorithmTags.EDDSA:
            return createSignature("Ed25519");
        default:
            throw new PGPException("unknown algorithm tag in signature:" + keyAlgorithm);
        }

        return createSignature(PGPUtil.getDigestName(hashAlgorithm) + "with" + encAlg);
    }

    public AlgorithmParameters createAlgorithmParameters(String algorithm)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        return helper.createAlgorithmParameters(algorithm);
    }
}
