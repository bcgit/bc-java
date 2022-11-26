package org.bouncycastle.pqc.jcajce.provider.dilithium;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.NoSuchAlgorithmException;
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
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.jcajce.provider.util.BaseKeyFactorySpi;

public class DilithiumKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.dilithium2);
        keyOids.add(BCObjectIdentifiers.dilithium3);
        keyOids.add(BCObjectIdentifiers.dilithium5);
        keyOids.add(BCObjectIdentifiers.dilithium2_aes);
        keyOids.add(BCObjectIdentifiers.dilithium3_aes);
        keyOids.add(BCObjectIdentifiers.dilithium5_aes);
    }

    public DilithiumKeyFactorySpi()
    {
        super(keyOids);
    }

    public DilithiumKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
            throws InvalidKeySpecException
    {
        if (key instanceof BCDilithiumPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCDilithiumPublicKey)
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
        if (key instanceof BCDilithiumPrivateKey || key instanceof BCDilithiumPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
    {
        return new BCDilithiumPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
    {
        return new BCDilithiumPublicKey(keyInfo);
    }

    public static class Base2
        extends DilithiumKeyFactorySpi
    {
        public Base2()
        {
            super(BCObjectIdentifiers.dilithium2);
        }
    }

    public static class Base3
        extends DilithiumKeyFactorySpi
    {
        public Base3()
        {
            super(BCObjectIdentifiers.dilithium3);
        }
    }

    public static class Base5
        extends DilithiumKeyFactorySpi
    {
        public Base5()
        {
            super(BCObjectIdentifiers.dilithium5);
        }
    }

    public static class Base2_AES
        extends DilithiumKeyFactorySpi
    {
        public Base2_AES()
        {
            super(BCObjectIdentifiers.dilithium2_aes);
        }
    }

    public static class Base3_AES
        extends DilithiumKeyFactorySpi
    {
        public Base3_AES()
        {
            super(BCObjectIdentifiers.dilithium3_aes);
        }
    }

    public static class Base5_AES
        extends DilithiumKeyFactorySpi
    {
        public Base5_AES()
        {
            super(BCObjectIdentifiers.dilithium5_aes);
        }
    }
}
