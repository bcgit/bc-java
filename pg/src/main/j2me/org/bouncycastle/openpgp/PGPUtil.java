package org.bouncycastle.openpgp;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

/**
 * Basic utility class
 */
public class PGPUtil
    implements HashAlgorithmTags
{
    static MPInteger[] dsaSigToMpi(
        byte[] encoding) 
        throws PGPException
    {
        ASN1InputStream aIn = new ASN1InputStream(encoding);

        ASN1Integer i1;
        ASN1Integer i2;

        try
        {
            ASN1Sequence s = (ASN1Sequence)aIn.readObject();

            i1 = (ASN1Integer)s.getObjectAt(0);
            i2 = (ASN1Integer)s.getObjectAt(1);
        }
        catch (IOException e)
        {
            throw new PGPException("exception encoding signature", e);
        }

        MPInteger[] values = new MPInteger[2];
        
        values[0] = new MPInteger(i1.getValue());
        values[1] = new MPInteger(i2.getValue());
        
        return values;
    }
    
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

    public static byte[] makeRandomKey(
        int             algorithm,
        SecureRandom    random) 
        throws PGPException
    {
        int        keySize = 0;
        
        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            keySize = 192;
            break;
        case SymmetricKeyAlgorithmTags.IDEA:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.CAST5:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.SAFER:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.DES:
            keySize = 64;
            break;
        case SymmetricKeyAlgorithmTags.AES_128:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.AES_192:
            keySize = 192;
            break;
        case SymmetricKeyAlgorithmTags.AES_256:
            keySize = 256;
            break;
        case SymmetricKeyAlgorithmTags.TWOFISH:
            keySize = 256;
            break;
        default:
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }
        
        byte[]    keyBytes = new byte[(keySize + 7) / 8];
        
        random.nextBytes(keyBytes);
        
        return keyBytes;
    }
}
