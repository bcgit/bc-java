package org.bouncycastle.pqc.jcajce.provider.mqom;

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

public class MQOMKeyFactorySpi
        extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf2_fast_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf2_fast_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf2_short_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf2_short_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf16_fast_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf16_fast_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf16_short_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf16_short_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf256_fast_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf256_fast_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf256_short_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat1_gf256_short_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf2_fast_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf2_fast_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf2_short_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf2_short_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf16_fast_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf16_fast_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf16_short_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf16_short_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf256_fast_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf256_fast_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf256_short_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat3_gf256_short_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf2_fast_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf2_fast_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf2_short_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf2_short_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf16_fast_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf16_fast_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf16_short_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf16_short_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf256_fast_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf256_fast_r5);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf256_short_r3);
        keyOids.add(BCObjectIdentifiers.mqom2_cat5_gf256_short_r5);
    }

    public MQOMKeyFactorySpi()
    {
        super(keyOids);
    }

    public MQOMKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
            throws InvalidKeySpecException
    {
        if (key instanceof BCMQOMPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCMQOMPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
        }
        else
        {
            throw new InvalidKeySpecException("Unsupported key type: " + key.getClass() + ".");
        }
        throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
            throws InvalidKeyException
    {
        if (key instanceof BCMQOMPrivateKey || key instanceof BCMQOMPublicKey)
        {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
    {
        return new BCMQOMPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
    {
        return new BCMQOMPublicKey(keyInfo);
    }

    public static class Base extends MQOMKeyFactorySpi
    {
        public Base()
        {
            super();
        }
    }

    public static class C1Gf2Fr3 extends MQOMKeyFactorySpi
    {
        public C1Gf2Fr3()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf2_fast_r3);
        }
    }

    public static class C1Gf2Fr5 extends MQOMKeyFactorySpi
    {
        public C1Gf2Fr5()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf2_fast_r5);
        }
    }

    public static class C1Gf2Sr3 extends MQOMKeyFactorySpi
    {
        public C1Gf2Sr3()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf2_short_r3);
        }
    }

    public static class C1Gf2Sr5 extends MQOMKeyFactorySpi
    {
        public C1Gf2Sr5()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf2_short_r5);
        }
    }

    public static class C1Gf16Fr3 extends MQOMKeyFactorySpi
    {
        public C1Gf16Fr3()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf16_fast_r3);
        }
    }

    public static class C1Gf16Fr5 extends MQOMKeyFactorySpi
    {
        public C1Gf16Fr5()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf16_fast_r5);
        }
    }

    public static class C1Gf16Sr3 extends MQOMKeyFactorySpi
    {
        public C1Gf16Sr3()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf16_short_r3);
        }
    }

    public static class C1Gf16Sr5 extends MQOMKeyFactorySpi
    {
        public C1Gf16Sr5()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf16_short_r5);
        }
    }

    public static class C1Gf256Fr3 extends MQOMKeyFactorySpi
    {
        public C1Gf256Fr3()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf256_fast_r3);
        }
    }

    public static class C1Gf256Fr5 extends MQOMKeyFactorySpi
    {
        public C1Gf256Fr5()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf256_fast_r5);
        }
    }

    public static class C1Gf256Sr3 extends MQOMKeyFactorySpi
    {
        public C1Gf256Sr3()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf256_short_r3);
        }
    }

    public static class C1Gf256Sr5 extends MQOMKeyFactorySpi
    {
        public C1Gf256Sr5()
        {
            super(BCObjectIdentifiers.mqom2_cat1_gf256_short_r5);
        }
    }

    public static class C3Gf2Fr3 extends MQOMKeyFactorySpi
    {
        public C3Gf2Fr3()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf2_fast_r3);
        }
    }

    public static class C3Gf2Fr5 extends MQOMKeyFactorySpi
    {
        public C3Gf2Fr5()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf2_fast_r5);
        }
    }

    public static class C3Gf2Sr3 extends MQOMKeyFactorySpi
    {
        public C3Gf2Sr3()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf2_short_r3);
        }
    }

    public static class C3Gf2Sr5 extends MQOMKeyFactorySpi
    {
        public C3Gf2Sr5()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf2_short_r5);
        }
    }

    public static class C3Gf16Fr3 extends MQOMKeyFactorySpi
    {
        public C3Gf16Fr3()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf16_fast_r3);
        }
    }

    public static class C3Gf16Fr5 extends MQOMKeyFactorySpi
    {
        public C3Gf16Fr5()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf16_fast_r5);
        }
    }

    public static class C3Gf16Sr3 extends MQOMKeyFactorySpi
    {
        public C3Gf16Sr3()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf16_short_r3);
        }
    }

    public static class C3Gf16Sr5 extends MQOMKeyFactorySpi
    {
        public C3Gf16Sr5()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf16_short_r5);
        }
    }

    public static class C3Gf256Fr3 extends MQOMKeyFactorySpi
    {
        public C3Gf256Fr3()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf256_fast_r3);
        }
    }

    public static class C3Gf256Fr5 extends MQOMKeyFactorySpi
    {
        public C3Gf256Fr5()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf256_fast_r5);
        }
    }

    public static class C3Gf256Sr3 extends MQOMKeyFactorySpi
    {
        public C3Gf256Sr3()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf256_short_r3);
        }
    }

    public static class C3Gf256Sr5 extends MQOMKeyFactorySpi
    {
        public C3Gf256Sr5()
        {
            super(BCObjectIdentifiers.mqom2_cat3_gf256_short_r5);
        }
    }

    public static class C5Gf2Fr3 extends MQOMKeyFactorySpi
    {
        public C5Gf2Fr3()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf2_fast_r3);
        }
    }

    public static class C5Gf2Fr5 extends MQOMKeyFactorySpi
    {
        public C5Gf2Fr5()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf2_fast_r5);
        }
    }

    public static class C5Gf2Sr3 extends MQOMKeyFactorySpi
    {
        public C5Gf2Sr3()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf2_short_r3);
        }
    }

    public static class C5Gf2Sr5 extends MQOMKeyFactorySpi
    {
        public C5Gf2Sr5()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf2_short_r5);
        }
    }

    public static class C5Gf16Fr3 extends MQOMKeyFactorySpi
    {
        public C5Gf16Fr3()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf16_fast_r3);
        }
    }

    public static class C5Gf16Fr5 extends MQOMKeyFactorySpi
    {
        public C5Gf16Fr5()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf16_fast_r5);
        }
    }

    public static class C5Gf16Sr3 extends MQOMKeyFactorySpi
    {
        public C5Gf16Sr3()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf16_short_r3);
        }
    }

    public static class C5Gf16Sr5 extends MQOMKeyFactorySpi
    {
        public C5Gf16Sr5()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf16_short_r5);
        }
    }

    public static class C5Gf256Fr3 extends MQOMKeyFactorySpi
    {
        public C5Gf256Fr3()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf256_fast_r3);
        }
    }

    public static class C5Gf256Fr5 extends MQOMKeyFactorySpi
    {
        public C5Gf256Fr5()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf256_fast_r5);
        }
    }

    public static class C5Gf256Sr3 extends MQOMKeyFactorySpi
    {
        public C5Gf256Sr3()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf256_short_r3);
        }
    }

    public static class C5Gf256Sr5 extends MQOMKeyFactorySpi
    {
        public C5Gf256Sr5()
        {
            super(BCObjectIdentifiers.mqom2_cat5_gf256_short_r5);
        }
    }
}
