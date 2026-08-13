package org.bouncycastle.pqc.jcajce.provider.smaugt;

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

public class SmaugTKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.smaugt_mode1);
        keyOids.add(BCObjectIdentifiers.smaugt_mode3);
        keyOids.add(BCObjectIdentifiers.smaugt_mode5);
        keyOids.add(BCObjectIdentifiers.smaugt_modet);
    }

    public SmaugTKeyFactorySpi()
    {
        super(keyOids);
    }

    public SmaugTKeyFactorySpi(ASN1ObjectIdentifier keyOids)
    {
        super(keyOids);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCSmaugTPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCSmaugTPublicKey)
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
        if (key instanceof BCSmaugTPrivateKey || key instanceof BCSmaugTPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCSmaugTPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCSmaugTPublicKey(keyInfo);
    }

    public static class Mode1
        extends SmaugTKeyFactorySpi
    {
        public Mode1()
        {
            super(BCObjectIdentifiers.smaugt_mode1);
        }
    }

    public static class Mode3
        extends SmaugTKeyFactorySpi
    {
        public Mode3()
        {
            super(BCObjectIdentifiers.smaugt_mode3);
        }
    }

    public static class Mode5
        extends SmaugTKeyFactorySpi
    {
        public Mode5()
        {
            super(BCObjectIdentifiers.smaugt_mode5);
        }
    }

    public static class ModeT
        extends SmaugTKeyFactorySpi
    {
        public ModeT()
        {
            super(BCObjectIdentifiers.smaugt_modet);
        }
    }
}
