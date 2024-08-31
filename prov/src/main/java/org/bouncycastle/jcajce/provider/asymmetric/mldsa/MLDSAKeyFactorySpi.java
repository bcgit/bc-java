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
import org.bouncycastle.pqc.jcajce.provider.util.BaseKeyFactorySpi;

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

    public MLDSAKeyFactorySpi(Set<ASN1ObjectIdentifier> keyOids)
    {
        super(keyOids);
    }

    public MLDSAKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
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
        }
        else if (key instanceof BCMLDSAPublicKey)
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
        if (key instanceof BCMLDSAPrivateKey || key instanceof BCMLDSAPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
    {
        return new BCMLDSAPrivateKey(keyInfo);
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
