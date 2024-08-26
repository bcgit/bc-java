package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

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

public class SLHDSAKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_sha2_256s);

        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_shake_256f);
        keyOids.add(NISTObjectIdentifiers.id_slh_dsa_shake_256s);
    }

    public SLHDSAKeyFactorySpi()
    {
        super(keyOids);
    }

    public SLHDSAKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCSLHDSAPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCSLHDSAPublicKey)
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
        if (key instanceof BCSLHDSAPrivateKey || key instanceof BCSLHDSAPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCSLHDSAPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCSLHDSAPublicKey(keyInfo);
    }

    public static class Sha2_128f
            extends SLHDSAKeyFactorySpi
    {
        public Sha2_128f()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        }
    }

    public static class Sha2_128s
            extends SLHDSAKeyFactorySpi
    {
        public Sha2_128s()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        }
    }
    
    public static class Sha2_192f
            extends SLHDSAKeyFactorySpi
    {
        public Sha2_192f()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        }
    }

    public static class Sha2_192s
            extends SLHDSAKeyFactorySpi
    {
        public Sha2_192s()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        }
    }
    
    public static class Sha2_256f
            extends SLHDSAKeyFactorySpi
    {
        public Sha2_256f()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        }
    }

    public static class Sha2_256s
            extends SLHDSAKeyFactorySpi
    {
        public Sha2_256s()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
        }
    }
    
    public static class Shake_128f
            extends SLHDSAKeyFactorySpi
    {
        public Shake_128f()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        }
    }

    public static class Shake_128s
            extends SLHDSAKeyFactorySpi
    {
        public Shake_128s()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        }
    }
    
    public static class Shake_192f
            extends SLHDSAKeyFactorySpi
    {
        public Shake_192f()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        }
    }

    public static class Shake_192s
            extends SLHDSAKeyFactorySpi
    {
        public Shake_192s()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        }
    }
    
    public static class Shake_256f
            extends SLHDSAKeyFactorySpi
    {
        public Shake_256f()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_256f);
        }
    }

    public static class Shake_256s
            extends SLHDSAKeyFactorySpi
    {
        public Shake_256s()
        {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_256s);
        }
    }
}
