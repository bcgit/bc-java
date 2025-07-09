package org.bouncycastle.pqc.jcajce.provider.cross;

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

public class CrossKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.cross_rsdp_1_small);
        keyOids.add(BCObjectIdentifiers.cross_rsdp_1_balanced);
        keyOids.add(BCObjectIdentifiers.cross_rsdp_1_fast);

        keyOids.add(BCObjectIdentifiers.cross_rsdp_3_small);
        keyOids.add(BCObjectIdentifiers.cross_rsdp_3_balanced);
        keyOids.add(BCObjectIdentifiers.cross_rsdp_3_fast);

        keyOids.add(BCObjectIdentifiers.cross_rsdp_5_small);
        keyOids.add(BCObjectIdentifiers.cross_rsdp_5_balanced);
        keyOids.add(BCObjectIdentifiers.cross_rsdp_5_fast);

        keyOids.add(BCObjectIdentifiers.cross_rsdpg_1_small);
        keyOids.add(BCObjectIdentifiers.cross_rsdpg_1_balanced);
        keyOids.add(BCObjectIdentifiers.cross_rsdpg_1_fast);

        keyOids.add(BCObjectIdentifiers.cross_rsdpg_3_small);
        keyOids.add(BCObjectIdentifiers.cross_rsdpg_3_balanced);
        keyOids.add(BCObjectIdentifiers.cross_rsdpg_3_fast);

        keyOids.add(BCObjectIdentifiers.cross_rsdpg_5_small);
        keyOids.add(BCObjectIdentifiers.cross_rsdpg_5_balanced);
        keyOids.add(BCObjectIdentifiers.cross_rsdpg_5_fast);
    }

    public CrossKeyFactorySpi()
    {
        super(keyOids);
    }

    public CrossKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCCrossPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCCrossPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
        }
        else
        {
            throw new InvalidKeySpecException("Unsupported key type: "
                + key.getClass() + ".");
        }

        throw new InvalidKeySpecException("Unknown key specification: "
            + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCCrossPrivateKey || key instanceof BCCrossPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCCrossPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCCrossPublicKey(keyInfo);
    }

    public static class CrossRsdp1Small extends CrossKeyFactorySpi
    {
        public CrossRsdp1Small()
        {
            super(BCObjectIdentifiers.cross_rsdp_1_small);
        }
    }

    public static class CrossRsdp1Balanced extends CrossKeyFactorySpi
    {
        public CrossRsdp1Balanced()
        {
            super(BCObjectIdentifiers.cross_rsdp_1_balanced);
        }
    }

    public static class CrossRsdp1Fast extends CrossKeyFactorySpi
    {
        public CrossRsdp1Fast()
        {
            super(BCObjectIdentifiers.cross_rsdp_1_fast);
        }
    }

    public static class CrossRsdp3Small extends CrossKeyFactorySpi
    {
        public CrossRsdp3Small()
        {
            super(BCObjectIdentifiers.cross_rsdp_3_small);
        }
    }

    public static class CrossRsdp3Balanced extends CrossKeyFactorySpi
    {
        public CrossRsdp3Balanced()
        {
            super(BCObjectIdentifiers.cross_rsdp_3_balanced);
        }
    }

    public static class CrossRsdp3Fast extends CrossKeyFactorySpi
    {
        public CrossRsdp3Fast()
        {
            super(BCObjectIdentifiers.cross_rsdp_3_fast);
        }
    }

    public static class CrossRsdp5Small extends CrossKeyFactorySpi
    {
        public CrossRsdp5Small()
        {
            super(BCObjectIdentifiers.cross_rsdp_5_small);
        }
    }

    public static class CrossRsdp5Balanced extends CrossKeyFactorySpi
    {
        public CrossRsdp5Balanced()
        {
            super(BCObjectIdentifiers.cross_rsdp_5_balanced);
        }
    }

    public static class CrossRsdp5Fast extends CrossKeyFactorySpi
    {
        public CrossRsdp5Fast()
        {
            super(BCObjectIdentifiers.cross_rsdp_5_fast);
        }
    }

    public static class CrossRsdpg1Small extends CrossKeyFactorySpi
    {
        public CrossRsdpg1Small()
        {
            super(BCObjectIdentifiers.cross_rsdpg_1_small);
        }
    }

    public static class CrossRsdpg1Balanced extends CrossKeyFactorySpi
    {
        public CrossRsdpg1Balanced()
        {
            super(BCObjectIdentifiers.cross_rsdpg_1_balanced);
        }
    }

    public static class CrossRsdpg1Fast extends CrossKeyFactorySpi
    {
        public CrossRsdpg1Fast()
        {
            super(BCObjectIdentifiers.cross_rsdpg_1_fast);
        }
    }

    public static class CrossRsdpg3Small extends CrossKeyFactorySpi
    {
        public CrossRsdpg3Small()
        {
            super(BCObjectIdentifiers.cross_rsdpg_3_small);
        }
    }

    public static class CrossRsdpg3Balanced extends CrossKeyFactorySpi
    {
        public CrossRsdpg3Balanced()
        {
            super(BCObjectIdentifiers.cross_rsdpg_3_balanced);
        }
    }

    public static class CrossRsdpg3Fast extends CrossKeyFactorySpi
    {
        public CrossRsdpg3Fast()
        {
            super(BCObjectIdentifiers.cross_rsdpg_3_fast);
        }
    }

    public static class CrossRsdpg5Small extends CrossKeyFactorySpi
    {
        public CrossRsdpg5Small()
        {
            super(BCObjectIdentifiers.cross_rsdpg_5_small);
        }
    }

    public static class CrossRsdpg5Balanced extends CrossKeyFactorySpi
    {
        public CrossRsdpg5Balanced()
        {
            super(BCObjectIdentifiers.cross_rsdpg_5_balanced);
        }
    }

    public static class CrossRsdpg5Fast extends CrossKeyFactorySpi
    {
        public CrossRsdpg5Fast()
        {
            super(BCObjectIdentifiers.cross_rsdpg_5_fast);
        }
    }

}

