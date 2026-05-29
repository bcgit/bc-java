package org.bouncycastle.pqc.jcajce.provider.sqisign;

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

public class SQIsignKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.sqisign_lvl1);
        keyOids.add(BCObjectIdentifiers.sqisign_lvl3);
        keyOids.add(BCObjectIdentifiers.sqisign_lvl5);
    }

    public SQIsignKeyFactorySpi()
    {
        super(keyOids);
    }

    public SQIsignKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCSQIsignPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCSQIsignPublicKey)
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
        if (key instanceof BCSQIsignPrivateKey || key instanceof BCSQIsignPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCSQIsignPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCSQIsignPublicKey(keyInfo);
    }

    public static class SQIsign_lvl1
        extends SQIsignKeyFactorySpi
    {
        public SQIsign_lvl1()
        {
            super(BCObjectIdentifiers.sqisign_lvl1);
        }
    }

    public static class SQIsign_lvl3
        extends SQIsignKeyFactorySpi
    {
        public SQIsign_lvl3()
        {
            super(BCObjectIdentifiers.sqisign_lvl3);
        }
    }

    public static class SQIsign_lvl5
        extends SQIsignKeyFactorySpi
    {
        public SQIsign_lvl5()
        {
            super(BCObjectIdentifiers.sqisign_lvl5);
        }
    }
}
