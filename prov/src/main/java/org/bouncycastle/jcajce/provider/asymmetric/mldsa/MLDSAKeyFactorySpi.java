package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.BaseKeyFactorySpi;
import org.bouncycastle.util.Arrays;

public class MLDSAKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> pureKeyOids = new HashSet<ASN1ObjectIdentifier>();
    private static final Set<ASN1ObjectIdentifier> hashKeyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        pureKeyOids.add(NISTObjectIdentifiers.id_ml_dsa_44);
        pureKeyOids.add(NISTObjectIdentifiers.id_ml_dsa_65);
        pureKeyOids.add(NISTObjectIdentifiers.id_ml_dsa_87);

        hashKeyOids.add(NISTObjectIdentifiers.id_ml_dsa_44);
        hashKeyOids.add(NISTObjectIdentifiers.id_ml_dsa_65);
        hashKeyOids.add(NISTObjectIdentifiers.id_ml_dsa_87);
        hashKeyOids.add(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
        hashKeyOids.add(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
        hashKeyOids.add(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);
    }

    private final boolean isHashOnly;

    public MLDSAKeyFactorySpi(Set<ASN1ObjectIdentifier> keyOids)
    {
        super(keyOids);

        this.isHashOnly = false;
    }

    public MLDSAKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);

        this.isHashOnly = (keyOid.equals(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512)
            || keyOid.equals(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512)
            || keyOid.equals(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512));
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCMLDSAPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
            if (MLDSAPrivateKeySpec.class.isAssignableFrom(keySpec))
            {
                BCMLDSAPrivateKey mldsaKey = (BCMLDSAPrivateKey)key;
                byte[] seed = mldsaKey.getSeed();
                if (seed != null)
                {
                    return new MLDSAPrivateKeySpec(mldsaKey.getParameterSpec(), seed);
                }
                return new MLDSAPrivateKeySpec(mldsaKey.getParameterSpec(), mldsaKey.getPrivateData(), mldsaKey.getPublicKey().getPublicData());
            }
            if (MLDSAPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                BCMLDSAPrivateKey mldsaKey = (BCMLDSAPrivateKey)key;
                return new MLDSAPublicKeySpec(mldsaKey.getParameterSpec(), mldsaKey.getPublicKey().getPublicData());
            }
        }
        else if (key instanceof BCMLDSAPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
            if (MLDSAPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                BCMLDSAPublicKey mldsaKey = (BCMLDSAPublicKey)key;
                return new MLDSAPublicKeySpec(mldsaKey.getParameterSpec(), mldsaKey.getPublicData());
            }
        }
        else
        {
            throw new InvalidKeySpecException("unsupported key type: "
                + key.getClass() + ".");
        }

        throw new InvalidKeySpecException("unknown key specification: "
            + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCMLDSAPrivateKey || key instanceof BCMLDSAPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("unsupported key type");
    }

    public PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof MLDSAPrivateKeySpec)
        {
            MLDSAPrivateKeySpec spec = (MLDSAPrivateKeySpec)keySpec;
            MLDSAPrivateKeyParameters params;
            MLDSAParameters mldsaParameters = Utils.getParameters(spec.getParameterSpec().getName());
            if (spec.isSeed())
            {
                params = new MLDSAPrivateKeyParameters(
                    mldsaParameters, spec.getSeed());
            }
            else
            {
                params = new MLDSAPrivateKeyParameters(
                    mldsaParameters, spec.getPrivateData(), null);
                byte[] publicData = spec.getPublicData();
                if (publicData != null)
                {
                    if (!Arrays.constantTimeAreEqual(publicData, params.getPublicKey()))
                    {
                        throw new InvalidKeySpecException("public key data does not match private key data");
                    }
                }
            }

            return new BCMLDSAPrivateKey(params);
        }

        return super.engineGeneratePrivate(keySpec);
    }

    public PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof MLDSAPublicKeySpec)
        {
            MLDSAPublicKeySpec spec = (MLDSAPublicKeySpec)keySpec;

            return new BCMLDSAPublicKey(new MLDSAPublicKeyParameters(
                Utils.getParameters(spec.getParameterSpec().getName()),
                spec.getPublicData()));
        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        BCMLDSAPrivateKey key = new BCMLDSAPrivateKey(keyInfo);

        if (!isHashOnly || (key.getAlgorithm().indexOf("WITH") > 0))
        {
            return key;
        }

        // keyfactory for hash-only, convert key to hash-only.
        MLDSAPrivateKeyParameters kParams = key.getKeyParams();
        MLDSAParameters mldsaParameters = null;
        if (kParams.getParameters().equals(MLDSAParameters.ml_dsa_44))
        {
            mldsaParameters = MLDSAParameters.ml_dsa_44_with_sha512;
        }
        else if (kParams.getParameters().equals(MLDSAParameters.ml_dsa_65))
        {
            mldsaParameters = MLDSAParameters.ml_dsa_65_with_sha512;
        }
        else if (kParams.getParameters().equals(MLDSAParameters.ml_dsa_87))
        {
            mldsaParameters = MLDSAParameters.ml_dsa_87_with_sha512;
        }
        else
        {
            throw new IllegalStateException("unknown ML-DSA parameters");
        }
        
        MLDSAPrivateKeyParameters hkParams = new MLDSAPrivateKeyParameters(
            mldsaParameters, kParams.getRho(), kParams.getK(), kParams.getTr(), kParams.getS1(), kParams.getS2(), kParams.getT0(), kParams.getT1(), kParams.getSeed());

        return new BCMLDSAPrivateKey(hkParams);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCMLDSAPublicKey(keyInfo);
    }

    public static class Pure
        extends MLDSAKeyFactorySpi
    {
        public Pure()
        {
            super(pureKeyOids);
        }
    }

    public static class MLDSA44
        extends MLDSAKeyFactorySpi
    {
        public MLDSA44()
        {
            super(NISTObjectIdentifiers.id_ml_dsa_44);
        }
    }

    public static class MLDSA65
        extends MLDSAKeyFactorySpi
    {
        public MLDSA65()
        {
            super(NISTObjectIdentifiers.id_ml_dsa_65);
        }
    }

    public static class MLDSA87
        extends MLDSAKeyFactorySpi
    {
        public MLDSA87()
        {
            super(NISTObjectIdentifiers.id_ml_dsa_87);
        }
    }

    public static class Hash
        extends MLDSAKeyFactorySpi
    {
        public Hash()
        {
            super(hashKeyOids);
        }
    }

    public static class HashMLDSA44
        extends MLDSAKeyFactorySpi
    {
        public HashMLDSA44()
        {
            super(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
        }
    }

    public static class HashMLDSA65
        extends MLDSAKeyFactorySpi
    {
        public HashMLDSA65()
        {
            super(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
        }
    }

    public static class HashMLDSA87
        extends MLDSAKeyFactorySpi
    {
        public HashMLDSA87()
        {
            super(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);
        }
    }
}
