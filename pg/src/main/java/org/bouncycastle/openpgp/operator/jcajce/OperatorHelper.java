package org.bouncycastle.openpgp.operator.jcajce;

import java.io.ByteArrayInputStream;
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
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.io.Streams;

class OperatorHelper
{
    private JcaJceHelper helper;

    OperatorHelper(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    /**
     * Return an appropriate name for the hash algorithm represented by the passed
     * in hash algorithm ID number (JCA message digest naming convention).
     *
     * @param hashAlgorithm the algorithm ID for a hash algorithm.
     * @return a String representation of the hash name.
     */
    String getDigestName(
        int hashAlgorithm)
        throws PGPException
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithmTags.SHA1:
            return "SHA-1";
        case HashAlgorithmTags.MD2:
            return "MD2";
        case HashAlgorithmTags.MD5:
            return "MD5";
        case HashAlgorithmTags.RIPEMD160:
            return "RIPEMD160";
        case HashAlgorithmTags.SHA256:
            return "SHA-256";
        case HashAlgorithmTags.SHA384:
            return "SHA-384";
        case HashAlgorithmTags.SHA512:
            return "SHA-512";
        case HashAlgorithmTags.SHA224:
            return "SHA-224";
        case HashAlgorithmTags.TIGER_192:
            return "TIGER";
        default:
            throw new PGPException("unknown hash algorithm tag in getDigestName: " + hashAlgorithm);
        }
    }

    MessageDigest createDigest(int algorithm)
        throws GeneralSecurityException, PGPException
    {
        MessageDigest dig;

        String digestName = getDigestName(algorithm);
        try
        {
            dig = helper.createMessageDigest(digestName);
        }
        catch (NoSuchAlgorithmException e)
        {
            if (algorithm >= HashAlgorithmTags.SHA256 && algorithm <= HashAlgorithmTags.SHA224)
            {
                dig = helper.createMessageDigest("SHA" + digestName.substring(4));
            }
            else
            {
                throw e;
            }
        }

        return dig;
    }

    KeyFactory createKeyFactory(String algorithm)
        throws GeneralSecurityException, PGPException
    {
        return helper.createKeyFactory(algorithm);
    }

    public KeyAgreement createKeyAgreement(String algorithm)
        throws GeneralSecurityException
    {
        return helper.createKeyAgreement(algorithm);
    }

    public KeyPairGenerator createKeyPairGenerator(String algorithm)
        throws GeneralSecurityException
    {
        return helper.createKeyPairGenerator(algorithm);
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

    long getChunkLength(int chunkSize)
    {
        return 1L << (chunkSize + 6);
    }

    PGPDataDecryptor createDataDecryptor(final int aeadAlgorithm, final byte[] iv, final int chunkSize, final int encAlgorithm, byte[] key)
        throws PGPException
    {
        try
        {
            final SecretKey secretKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));

            final Cipher c = createAEADCipher(encAlgorithm, aeadAlgorithm);

            // TODO: get this working for more than one chunk!
            return new PGPDataDecryptor()
            {
                public InputStream getInputStream(InputStream in)
                {
                    long chunkIndex = 0;
                    byte[] data;
                    try
                    {
                        data = Streams.readAllLimited(in, (int)getChunkLength(chunkSize));

                        c.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, getNonce(iv, chunkIndex)));  // always full tag.

                        byte[] adata = new byte[13];

                        adata[0] = (byte)(0xC0 | PacketTags.AEAD_ENC_DATA);
                        adata[1] = 0x01;   // packet version
                        adata[2] = (byte)encAlgorithm;
                        adata[3] = (byte)aeadAlgorithm;
                        adata[4] = (byte)chunkSize;

                        xorChunkId(adata, chunkIndex);

                        c.updateAAD(adata);

                        byte[] decData = c.doFinal(data, 0, data.length - 16);

                        chunkIndex++;

                        adata = new byte[13];

                        adata[0] = (byte)(0xC0 | PacketTags.AEAD_ENC_DATA);
                        adata[1] = 0x01;  // packet version
                        adata[2] = (byte)encAlgorithm;
                        adata[3] = (byte)aeadAlgorithm;
                        adata[4] = (byte)chunkSize;

                        xorChunkId(adata, chunkIndex);

                        c.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, getNonce(iv, chunkIndex)));

                        c.updateAAD(adata);
                        c.updateAAD(Pack.longToBigEndian(decData.length));

                        c.doFinal(data, data.length - 16, 16); // check final tag

                        return new ByteArrayInputStream(decData);
                    }
                    catch (Exception e)
                    {
                        throw new IllegalStateException("unable to read AEAD data");
                    }
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

    Cipher createAEADCipher(int encAlgorithm, int aeadAlgorithm)
        throws PGPException
    {
        String mode;
        switch (aeadAlgorithm)
        {
        case AEADAlgorithmTags.EAX:
            mode = "EAX";
            break;
        case AEADAlgorithmTags.OCB:
            mode = "OCB";
            break;
        case AEADAlgorithmTags.GCM:
            mode = "GCM";
            break;
        default:
            throw new PGPException("encountered unknown AEAD algorithm: " + aeadAlgorithm);
        }

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
        catch (GeneralSecurityException e)
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
        case PGPPublicKey.EDDSA:
            throw new PGPException("Can't use EDDSA for encryption.");
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
        catch (GeneralSecurityException e)
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
        catch (GeneralSecurityException e)
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

    public byte[] getNonce(byte[] iv, long chunkIndex)
    {
        byte[] nonce = Arrays.clone(iv);

        xorChunkId(nonce, chunkIndex);

        return nonce;
    }

    private void xorChunkId(byte[] nonce, long chunkIndex)
    {
        int index = nonce.length - 8;

        nonce[index++] ^= (byte)(chunkIndex >> 56);
        nonce[index++] ^= (byte)(chunkIndex >> 48);
        nonce[index++] ^= (byte)(chunkIndex >> 40);
        nonce[index++] ^= (byte)(chunkIndex >> 32);
        nonce[index++] ^= (byte)(chunkIndex >> 24);
        nonce[index++] ^= (byte)(chunkIndex >> 16);
        nonce[index++] ^= (byte)(chunkIndex >> 8);
        nonce[index++] ^= (byte)(chunkIndex);
    }
}
