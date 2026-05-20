package org.bouncycastle.pqc.jcajce.provider.faest;

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

public class FaestKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.faest_128s);
        keyOids.add(BCObjectIdentifiers.faest_128f);
        keyOids.add(BCObjectIdentifiers.faest_192s);
        keyOids.add(BCObjectIdentifiers.faest_192f);
        keyOids.add(BCObjectIdentifiers.faest_256s);
        keyOids.add(BCObjectIdentifiers.faest_256f);
        keyOids.add(BCObjectIdentifiers.faest_em_128s);
        keyOids.add(BCObjectIdentifiers.faest_em_128f);
        keyOids.add(BCObjectIdentifiers.faest_em_192s);
        keyOids.add(BCObjectIdentifiers.faest_em_192f);
        keyOids.add(BCObjectIdentifiers.faest_em_256s);
        keyOids.add(BCObjectIdentifiers.faest_em_256f);
    }

    public FaestKeyFactorySpi()
    {
        super(keyOids);
    }

    public FaestKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCFaestPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCFaestPublicKey)
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
        if (key instanceof BCFaestPrivateKey || key instanceof BCFaestPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCFaestPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCFaestPublicKey(keyInfo);
    }

    public static class FAEST_128S
        extends FaestKeyFactorySpi
    {
        public FAEST_128S()
        {
            super(BCObjectIdentifiers.faest_128s);
        }
    }

    public static class FAEST_128F
        extends FaestKeyFactorySpi
    {
        public FAEST_128F()
        {
            super(BCObjectIdentifiers.faest_128f);
        }
    }

    public static class FAEST_192S
        extends FaestKeyFactorySpi
    {
        public FAEST_192S()
        {
            super(BCObjectIdentifiers.faest_192s);
        }
    }

    public static class FAEST_192F
        extends FaestKeyFactorySpi
    {
        public FAEST_192F()
        {
            super(BCObjectIdentifiers.faest_192f);
        }
    }

    public static class FAEST_256S
        extends FaestKeyFactorySpi
    {
        public FAEST_256S()
        {
            super(BCObjectIdentifiers.faest_256s);
        }
    }

    public static class FAEST_256F
        extends FaestKeyFactorySpi
    {
        public FAEST_256F()
        {
            super(BCObjectIdentifiers.faest_256f);
        }
    }

    public static class FAEST_EM_128S
        extends FaestKeyFactorySpi
    {
        public FAEST_EM_128S()
        {
            super(BCObjectIdentifiers.faest_em_128s);
        }
    }

    public static class FAEST_EM_128F
        extends FaestKeyFactorySpi
    {
        public FAEST_EM_128F()
        {
            super(BCObjectIdentifiers.faest_em_128f);
        }
    }

    public static class FAEST_EM_192S
        extends FaestKeyFactorySpi
    {
        public FAEST_EM_192S()
        {
            super(BCObjectIdentifiers.faest_em_192s);
        }
    }

    public static class FAEST_EM_192F
        extends FaestKeyFactorySpi
    {
        public FAEST_EM_192F()
        {
            super(BCObjectIdentifiers.faest_em_192f);
        }
    }

    public static class FAEST_EM_256S
        extends FaestKeyFactorySpi
    {
        public FAEST_EM_256S()
        {
            super(BCObjectIdentifiers.faest_em_256s);
        }
    }

    public static class FAEST_EM_256F
        extends FaestKeyFactorySpi
    {
        public FAEST_EM_256F()
        {
            super(BCObjectIdentifiers.faest_em_256f);
        }
    }
}
