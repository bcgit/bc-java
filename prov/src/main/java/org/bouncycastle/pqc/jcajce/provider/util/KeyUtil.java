package org.bouncycastle.pqc.jcajce.provider.util;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;

public class KeyUtil
{
    public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, ASN1Encodable keyData)
    {
        try
        {
            return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, byte[] keyData)
    {
        try
        {
            return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(SubjectPublicKeyInfo info)
    {
         try
         {
             return info.getEncoded(ASN1Encoding.DER);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
    {
        if (publicKey.isPrivate())
        {
            throw new IllegalArgumentException("private key found");
        }

        try
        {
            return getEncodedSubjectPublicKeyInfo(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static byte[] getEncodedPrivateKeyInfo(AlgorithmIdentifier algId, ASN1Encodable privKey)
    {
         try
         {
             PrivateKeyInfo info = new PrivateKeyInfo(algId, privKey.toASN1Primitive());

             return getEncodedPrivateKeyInfo(info);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    public static byte[] getEncodedPrivateKeyInfo(PrivateKeyInfo info)
    {
         try
         {
             return info.getEncoded(ASN1Encoding.DER);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    public static byte[] getEncodedPrivateKeyInfo(AlgorithmParameterSpec paramSpec, byte[] seed, ASN1Set attributes)
    {
        byte[] enc = null;

        try
        {
            if (paramSpec instanceof MLDSAParameterSpec)
            {
                String name = ((MLDSAParameterSpec)paramSpec).getName();
                if (name.equals(MLDSAParameterSpec.ml_dsa_44.getName()) || name.equals(MLDSAParameterSpec.ml_dsa_44_with_sha512.getName()))
                {
                    enc = new PrivateKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.id_id_alg_ml_dsa_44_seed), seed, attributes).getEncoded();
                }
                else if (name.equals(MLDSAParameterSpec.ml_dsa_65.getName()) || name.equals(MLDSAParameterSpec.ml_dsa_65_with_sha512.getName()))
                {
                    enc = new PrivateKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.id_id_alg_ml_dsa_65_seed), seed, attributes).getEncoded();
                }
                else if (name.equals(MLDSAParameterSpec.ml_dsa_87.getName()) || name.equals(MLDSAParameterSpec.ml_dsa_87_with_sha512.getName()))
                {
                    enc = new PrivateKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.id_id_alg_ml_dsa_87_seed), seed, attributes).getEncoded();
                }
                else
                {
                    throw new IllegalStateException("unknown ML-DSA algorithm");
                }
            }
        }
        catch (IllegalStateException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            return null;
        }

        return enc;
    }

    public static byte[] getEncodedPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes)
    {
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("public key found");
        }

        try
        {
            return getEncodedPrivateKeyInfo(PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey, attributes));
        }
        catch (Exception e)
        {
            return null;
        }
    }
}
