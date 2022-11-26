package org.bouncycastle.pqc.jcajce.provider.kyber;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.jcajce.provider.util.BaseKeyFactorySpi;

public class KyberKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.kyber512);
        keyOids.add(BCObjectIdentifiers.kyber768);
        keyOids.add(BCObjectIdentifiers.kyber1024);
        keyOids.add(BCObjectIdentifiers.kyber512_aes);
        keyOids.add(BCObjectIdentifiers.kyber768_aes);
        keyOids.add(BCObjectIdentifiers.kyber1024_aes);
    }

    public KyberKeyFactorySpi()
    {
        super(keyOids);
    }

    public KyberKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
            throws InvalidKeySpecException
    {
        if (key instanceof BCKyberPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCKyberPublicKey)
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
        if (key instanceof BCKyberPrivateKey || key instanceof BCKyberPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
    {
        return new BCKyberPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
    {
        return new BCKyberPublicKey(keyInfo);
    }

    public static class Kyber512
        extends KyberKeyFactorySpi
    {
        public Kyber512()
        {
            super(BCObjectIdentifiers.kyber512);
        }
    }

    public static class Kyber768
        extends KyberKeyFactorySpi
    {
        public Kyber768()
        {
            super(BCObjectIdentifiers.kyber768);
        }
    }

    public static class Kyber1024
        extends KyberKeyFactorySpi
    {
        public Kyber1024()
        {
            super(BCObjectIdentifiers.kyber1024);
        }
    }

    public static class Kyber512_AES
        extends KyberKeyFactorySpi
    {
        public Kyber512_AES()
        {
            super(BCObjectIdentifiers.kyber512_aes);
        }
    }

    public static class Kyber768_AES
        extends KyberKeyFactorySpi
    {
        public Kyber768_AES()
        {
            super(BCObjectIdentifiers.kyber768_aes);
        }
    }

    public static class Kyber1024_AES
        extends KyberKeyFactorySpi
    {
        public Kyber1024_AES()
        {
            super(BCObjectIdentifiers.kyber1024_aes);
        }
    }
}
