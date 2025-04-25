package org.bouncycastle.pqc.jcajce.provider.mayo;

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

public class MayoKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.mayo1);
        keyOids.add(BCObjectIdentifiers.mayo2);
        keyOids.add(BCObjectIdentifiers.mayo3);
        keyOids.add(BCObjectIdentifiers.mayo5);
    }

    public MayoKeyFactorySpi()
    {
        super(keyOids);
    }

    public MayoKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCMayoPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCMayoPublicKey)
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
        if (key instanceof BCMayoPrivateKey || key instanceof BCMayoPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCMayoPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCMayoPublicKey(keyInfo);
    }

    public static class Mayo1
        extends MayoKeyFactorySpi
    {
        public Mayo1()
        {
            super(BCObjectIdentifiers.mayo1);
        }
    }

    public static class Mayo2
        extends MayoKeyFactorySpi
    {
        public Mayo2()
        {
            super(BCObjectIdentifiers.mayo2);
        }
    }

    public static class Mayo3
        extends MayoKeyFactorySpi
    {
        public Mayo3()
        {
            super(BCObjectIdentifiers.mayo3);
        }
    }

    public static class Mayo5
        extends MayoKeyFactorySpi
    {
        public Mayo5()
        {
            super(BCObjectIdentifiers.mayo5);
        }
    }
}

