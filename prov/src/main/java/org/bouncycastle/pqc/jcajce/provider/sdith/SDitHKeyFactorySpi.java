package org.bouncycastle.pqc.jcajce.provider.sdith;

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
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.jcajce.provider.util.BaseKeyFactorySpi;

public class SDitHKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.sdith_hypercube_cat1_gf256);
        keyOids.add(BCObjectIdentifiers.sdith_hypercube_cat3_gf256);
        keyOids.add(BCObjectIdentifiers.sdith_hypercube_cat5_gf256);
        keyOids.add(BCObjectIdentifiers.sdith_hypercube_cat1_p251);
        keyOids.add(BCObjectIdentifiers.sdith_hypercube_cat3_p251);
        keyOids.add(BCObjectIdentifiers.sdith_hypercube_cat5_p251);
        keyOids.add(BCObjectIdentifiers.sdith_threshold_cat1_gf256);
        keyOids.add(BCObjectIdentifiers.sdith_threshold_cat3_gf256);
        keyOids.add(BCObjectIdentifiers.sdith_threshold_cat5_gf256);
        keyOids.add(BCObjectIdentifiers.sdith_threshold_cat1_p251);
        keyOids.add(BCObjectIdentifiers.sdith_threshold_cat3_p251);
        keyOids.add(BCObjectIdentifiers.sdith_threshold_cat5_p251);
    }

    public SDitHKeyFactorySpi()
    {
        super(keyOids);
    }

    public SDitHKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCSDitHPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCSDitHPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
        }
        else
        {
            throw new InvalidKeySpecException("unsupported key type: " + key.getClass() + ".");
        }

        throw new InvalidKeySpecException("unknown key specification: " + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCSDitHPrivateKey || key instanceof BCSDitHPublicKey)
        {
            return key;
        }
        throw new InvalidKeyException("unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCSDitHPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCSDitHPublicKey(keyInfo);
    }

    public static class HypercubeCat1Gf256
        extends SDitHKeyFactorySpi
    {
        public HypercubeCat1Gf256()
        {
            super(BCObjectIdentifiers.sdith_hypercube_cat1_gf256);
        }
    }

    public static class HypercubeCat3Gf256
        extends SDitHKeyFactorySpi
    {
        public HypercubeCat3Gf256()
        {
            super(BCObjectIdentifiers.sdith_hypercube_cat3_gf256);
        }
    }

    public static class HypercubeCat5Gf256
        extends SDitHKeyFactorySpi
    {
        public HypercubeCat5Gf256()
        {
            super(BCObjectIdentifiers.sdith_hypercube_cat5_gf256);
        }
    }

    public static class HypercubeCat1P251
        extends SDitHKeyFactorySpi
    {
        public HypercubeCat1P251()
        {
            super(BCObjectIdentifiers.sdith_hypercube_cat1_p251);
        }
    }

    public static class HypercubeCat3P251
        extends SDitHKeyFactorySpi
    {
        public HypercubeCat3P251()
        {
            super(BCObjectIdentifiers.sdith_hypercube_cat3_p251);
        }
    }

    public static class HypercubeCat5P251
        extends SDitHKeyFactorySpi
    {
        public HypercubeCat5P251()
        {
            super(BCObjectIdentifiers.sdith_hypercube_cat5_p251);
        }
    }

    public static class ThresholdCat1Gf256
        extends SDitHKeyFactorySpi
    {
        public ThresholdCat1Gf256()
        {
            super(BCObjectIdentifiers.sdith_threshold_cat1_gf256);
        }
    }

    public static class ThresholdCat3Gf256
        extends SDitHKeyFactorySpi
    {
        public ThresholdCat3Gf256()
        {
            super(BCObjectIdentifiers.sdith_threshold_cat3_gf256);
        }
    }

    public static class ThresholdCat5Gf256
        extends SDitHKeyFactorySpi
    {
        public ThresholdCat5Gf256()
        {
            super(BCObjectIdentifiers.sdith_threshold_cat5_gf256);
        }
    }

    public static class ThresholdCat1P251
        extends SDitHKeyFactorySpi
    {
        public ThresholdCat1P251()
        {
            super(BCObjectIdentifiers.sdith_threshold_cat1_p251);
        }
    }

    public static class ThresholdCat3P251
        extends SDitHKeyFactorySpi
    {
        public ThresholdCat3P251()
        {
            super(BCObjectIdentifiers.sdith_threshold_cat3_p251);
        }
    }

    public static class ThresholdCat5P251
        extends SDitHKeyFactorySpi
    {
        public ThresholdCat5P251()
        {
            super(BCObjectIdentifiers.sdith_threshold_cat5_p251);
        }
    }
}
