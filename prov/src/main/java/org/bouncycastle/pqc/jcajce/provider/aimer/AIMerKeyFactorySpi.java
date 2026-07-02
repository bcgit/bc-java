package org.bouncycastle.pqc.jcajce.provider.aimer;

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

public class AIMerKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.aimer_128f);
        keyOids.add(BCObjectIdentifiers.aimer_128s);
        keyOids.add(BCObjectIdentifiers.aimer_192f);
        keyOids.add(BCObjectIdentifiers.aimer_192s);
        keyOids.add(BCObjectIdentifiers.aimer_256f);
        keyOids.add(BCObjectIdentifiers.aimer_256s);
    }

    public AIMerKeyFactorySpi()
    {
        super(keyOids);
    }

    public AIMerKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCAIMerPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCAIMerPublicKey)
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
        if (key instanceof BCAIMerPrivateKey || key instanceof BCAIMerPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCAIMerPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCAIMerPublicKey(keyInfo);
    }

    public static class AIMer_128f
        extends AIMerKeyFactorySpi
    {
        public AIMer_128f()
        {
            super(BCObjectIdentifiers.aimer_128f);
        }
    }

    public static class AIMer_128s
        extends AIMerKeyFactorySpi
    {
        public AIMer_128s()
        {
            super(BCObjectIdentifiers.aimer_128s);
        }
    }

    public static class AIMer_192f
        extends AIMerKeyFactorySpi
    {
        public AIMer_192f()
        {
            super(BCObjectIdentifiers.aimer_192f);
        }
    }

    public static class AIMer_192s
        extends AIMerKeyFactorySpi
    {
        public AIMer_192s()
        {
            super(BCObjectIdentifiers.aimer_192s);
        }
    }

    public static class AIMer_256f
        extends AIMerKeyFactorySpi
    {
        public AIMer_256f()
        {
            super(BCObjectIdentifiers.aimer_256f);
        }
    }

    public static class AIMer_256s
        extends AIMerKeyFactorySpi
    {
        public AIMer_256s()
        {
            super(BCObjectIdentifiers.aimer_256s);
        }
    }
}

