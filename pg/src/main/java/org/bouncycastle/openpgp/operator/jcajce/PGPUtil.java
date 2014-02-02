package org.bouncycastle.openpgp.operator.jcajce;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;

/**
 * Basic utility class
 */
class PGPUtil
{
    static String getDigestName(
        int        hashAlgorithm)
        throws PGPException
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithmTags.SHA1:
            return "SHA1";
        case HashAlgorithmTags.MD2:
            return "MD2";
        case HashAlgorithmTags.MD5:
            return "MD5";
        case HashAlgorithmTags.RIPEMD160:
            return "RIPEMD160";
        case HashAlgorithmTags.SHA256:
            return "SHA256";
        case HashAlgorithmTags.SHA384:
            return "SHA384";
        case HashAlgorithmTags.SHA512:
            return "SHA512";
        case HashAlgorithmTags.SHA224:
            return "SHA224";
        case HashAlgorithmTags.TIGER_192:
            return "TIGER";
        default:
            throw new PGPException("unknown hash algorithm tag in getDigestName: " + hashAlgorithm);
        }
    }
    
    static String getSignatureName(
        int        keyAlgorithm,
        int        hashAlgorithm)
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
        default:
            throw new PGPException("unknown algorithm tag in signature:" + keyAlgorithm);
        }

        return getDigestName(hashAlgorithm) + "with" + encAlg;
    }
    
    static String getSymmetricCipherName(
        int    algorithm)
    {
        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.NULL:
            return null;
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            return "DESEDE";
        case SymmetricKeyAlgorithmTags.IDEA:
            return "IDEA";
        case SymmetricKeyAlgorithmTags.CAST5:
            return "CAST5";
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            return "Blowfish";
        case SymmetricKeyAlgorithmTags.SAFER:
            return "SAFER";
        case SymmetricKeyAlgorithmTags.DES:
            return "DES";
        case SymmetricKeyAlgorithmTags.AES_128:
            return "AES";
        case SymmetricKeyAlgorithmTags.AES_192:
            return "AES";
        case SymmetricKeyAlgorithmTags.AES_256:
            return "AES";
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
            return "Camellia";
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
            return "Camellia";
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            return "Camellia";
        case SymmetricKeyAlgorithmTags.TWOFISH:
            return "Twofish";
        default:
            throw new IllegalArgumentException("unknown symmetric algorithm: " + algorithm);
        }
    }
    
    public static SecretKey makeSymmetricKey(
        int             algorithm,
        byte[]          keyBytes)
        throws PGPException
    {
        String    algName = getSymmetricCipherName(algorithm);

        if (algName == null)
        {
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }

        return new SecretKeySpec(keyBytes, algName);
    }

    public static byte[] padSessionData(byte[] sessionInfo)
    {
        byte[] result = new byte[40];

        System.arraycopy(sessionInfo, 0, result, 0, sessionInfo.length);

        byte padValue = (byte)(result.length -sessionInfo.length);

        for (int i =  sessionInfo.length; i != result.length; i++)
        {
            result[i] = padValue;
        }

        return result;
    }

    public static byte[] unpadSessionData(byte[] encoded)
        throws PGPException
    {
        byte padValue = encoded[encoded.length - 1];

        for (int i = encoded.length - padValue; i != encoded.length; i++)
        {
            if (encoded[i] != padValue)
            {
                throw new PGPException("bad padding found in session data");
            }
        }

        byte[] taggedKey = new byte[encoded.length - padValue];

        System.arraycopy(encoded, 0, taggedKey, 0, taggedKey.length);

        return taggedKey;
    }
}
