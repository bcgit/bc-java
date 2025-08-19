package org.bouncycastle.pqc.jcajce.provider.mirath;

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

public class MirathKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.mirath_1a_fast);
        keyOids.add(BCObjectIdentifiers.mirath_1a_short);
        keyOids.add(BCObjectIdentifiers.mirath_1b_fast);
        keyOids.add(BCObjectIdentifiers.mirath_1b_short);
        keyOids.add(BCObjectIdentifiers.mirath_3a_fast);
        keyOids.add(BCObjectIdentifiers.mirath_3a_short);
        keyOids.add(BCObjectIdentifiers.mirath_3b_fast);
        keyOids.add(BCObjectIdentifiers.mirath_3b_short);
        keyOids.add(BCObjectIdentifiers.mirath_5a_fast);
        keyOids.add(BCObjectIdentifiers.mirath_5a_short);
        keyOids.add(BCObjectIdentifiers.mirath_5b_fast);
        keyOids.add(BCObjectIdentifiers.mirath_5b_short);
    }

    public MirathKeyFactorySpi()
    {
        super(keyOids);
    }

    public MirathKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCMirathPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCMirathPublicKey)
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
        if (key instanceof BCMirathPrivateKey || key instanceof BCMirathPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCMirathPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCMirathPublicKey(keyInfo);
    }

    public static class Mirath1aFast
        extends MirathKeyFactorySpi
    {
        public Mirath1aFast()
        {
            super(BCObjectIdentifiers.mirath_1a_fast);
        }
    }

    public static class Mirath1aShort
        extends MirathKeyFactorySpi
    {
        public Mirath1aShort()
        {
            super(BCObjectIdentifiers.mirath_1a_short);
        }
    }

    public static class Mirath1bFast
        extends MirathKeyFactorySpi
    {
        public Mirath1bFast()
        {
            super(BCObjectIdentifiers.mirath_1b_fast);
        }
    }

    public static class Mirath1bShort
        extends MirathKeyFactorySpi
    {
        public Mirath1bShort()
        {
            super(BCObjectIdentifiers.mirath_1b_short);
        }
    }

    public static class Mirath3aFast
        extends MirathKeyFactorySpi
    {
        public Mirath3aFast()
        {
            super(BCObjectIdentifiers.mirath_3a_fast);
        }
    }

    public static class Mirath3aShort
        extends MirathKeyFactorySpi
    {
        public Mirath3aShort()
        {
            super(BCObjectIdentifiers.mirath_3a_short);
        }
    }

    public static class Mirath3bFast
        extends MirathKeyFactorySpi
    {
        public Mirath3bFast()
        {
            super(BCObjectIdentifiers.mirath_3b_fast);
        }
    }

    public static class Mirath3bShort
        extends MirathKeyFactorySpi
    {
        public Mirath3bShort()
        {
            super(BCObjectIdentifiers.mirath_3b_short);
        }
    }

    public static class Mirath5aFast
        extends MirathKeyFactorySpi
    {
        public Mirath5aFast()
        {
            super(BCObjectIdentifiers.mirath_5a_fast);
        }
    }

    public static class Mirath5aShort
        extends MirathKeyFactorySpi
    {
        public Mirath5aShort()
        {
            super(BCObjectIdentifiers.mirath_5a_short);
        }
    }

    public static class Mirath5bFast
        extends MirathKeyFactorySpi
    {
        public Mirath5bFast()
        {
            super(BCObjectIdentifiers.mirath_5b_fast);
        }
    }

    public static class Mirath5bShort
        extends MirathKeyFactorySpi
    {
        public Mirath5bShort()
        {
            super(BCObjectIdentifiers.mirath_5b_short);
        }
    }
}

