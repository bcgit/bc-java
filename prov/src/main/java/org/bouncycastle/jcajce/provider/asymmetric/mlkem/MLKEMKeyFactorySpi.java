package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

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
import org.bouncycastle.jcajce.spec.MLKEMPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLKEMPublicKeySpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.BaseKeyFactorySpi;
import org.bouncycastle.util.Arrays;

public class MLKEMKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(NISTObjectIdentifiers.id_alg_ml_kem_512);
        keyOids.add(NISTObjectIdentifiers.id_alg_ml_kem_768);
        keyOids.add(NISTObjectIdentifiers.id_alg_ml_kem_1024);
    }

    public MLKEMKeyFactorySpi()
    {
        super(keyOids);
    }

    public MLKEMKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }


    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCMLKEMPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
            if (MLKEMPrivateKeySpec.class.isAssignableFrom(keySpec))
            {
                BCMLKEMPrivateKey mlkemKey = (BCMLKEMPrivateKey)key;
                byte[] seed = mlkemKey.getSeed();
                if (seed != null)
                {
                    return new MLKEMPrivateKeySpec(mlkemKey.getParameterSpec(), seed);
                }
                return new MLKEMPrivateKeySpec(mlkemKey.getParameterSpec(), mlkemKey.getPrivateData(), mlkemKey.getPublicKey().getPublicData());
            }
            if (MLKEMPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                BCMLKEMPrivateKey mlkemKey = (BCMLKEMPrivateKey)key;
                return new MLKEMPublicKeySpec(mlkemKey.getParameterSpec(), mlkemKey.getPublicKey().getPublicData());
            }
        }
        else if (key instanceof BCMLKEMPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
            if (MLKEMPublicKeySpec.class.isAssignableFrom(keySpec))
            {
                BCMLKEMPublicKey mlkemKey = (BCMLKEMPublicKey)key;
                return new MLKEMPublicKeySpec(mlkemKey.getParameterSpec(), mlkemKey.getPublicData());
            }
        }
        else
        {
            throw new InvalidKeySpecException("Unsupported key type: "
                + key.getClass() + ".");
        }

        throw new InvalidKeySpecException("unknown key specification: "
            + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCMLKEMPrivateKey || key instanceof BCMLKEMPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("unsupported key type");
    }

    public PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof MLKEMPrivateKeySpec)
        {
            MLKEMPrivateKeySpec spec = (MLKEMPrivateKeySpec)keySpec;
            MLKEMPrivateKeyParameters params;
            MLKEMParameters mlkemParameters = Utils.getParameters(spec.getParameterSpec().getName());
            if (spec.isSeed())
            {
                params = new MLKEMPrivateKeyParameters(
                    mlkemParameters, spec.getSeed());
            }
            else
            {
                params = new MLKEMPrivateKeyParameters(mlkemParameters, spec.getPrivateData());
                byte[] publicKeyData = spec.getPublicData();
                if (publicKeyData != null)
                {
                    if (!Arrays.constantTimeAreEqual(publicKeyData, params.getPublicKey()))
                    {
                        throw new InvalidKeySpecException("public key data does not match private key data");
                    }
                }
            }

            return new BCMLKEMPrivateKey(params);
        }

        return super.engineGeneratePrivate(keySpec);
    }

    public PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof MLKEMPublicKeySpec)
        {
            MLKEMPublicKeySpec spec = (MLKEMPublicKeySpec)keySpec;

            return new BCMLKEMPublicKey(new MLKEMPublicKeyParameters(
                Utils.getParameters(spec.getParameterSpec().getName()),
                spec.getPublicData()));
        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCMLKEMPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCMLKEMPublicKey(keyInfo);
    }

    public static class MLKEM512
        extends MLKEMKeyFactorySpi
    {
        public MLKEM512()
        {
            super(NISTObjectIdentifiers.id_alg_ml_kem_512);
        }
    }

    public static class MLKEM768
        extends MLKEMKeyFactorySpi
    {
        public MLKEM768()
        {
            super(NISTObjectIdentifiers.id_alg_ml_kem_768);
        }
    }

    public static class MLKEM1024
        extends MLKEMKeyFactorySpi
    {
        public MLKEM1024()
        {
            super(NISTObjectIdentifiers.id_alg_ml_kem_1024);
        }
    }

}
