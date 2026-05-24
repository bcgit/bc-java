package org.bouncycastle.pqc.jcajce.provider.hawk;

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

/**
 * {@link java.security.KeyFactorySpi} for Hawk. The unparameterised form
 * accepts encoded keys for any Hawk parameter set; the nested {@link HAWK_256}
 * / {@link HAWK_512} / {@link HAWK_1024} subclasses restrict decoding to a
 * single OID for use as the per-parameter-set {@code KeyFactory.<spec.getName()>}
 * registrations.
 */
public class HawkKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.hawk256);
        keyOids.add(BCObjectIdentifiers.hawk512);
        keyOids.add(BCObjectIdentifiers.hawk1024);
    }

    public HawkKeyFactorySpi()
    {
        super(keyOids);
    }

    public HawkKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCHawkPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCHawkPublicKey)
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
        if (key instanceof BCHawkPrivateKey || key instanceof BCHawkPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCHawkPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCHawkPublicKey(keyInfo);
    }

    public static class HAWK_256
        extends HawkKeyFactorySpi
    {
        public HAWK_256()
        {
            super(BCObjectIdentifiers.hawk256);
        }
    }

    public static class HAWK_512
        extends HawkKeyFactorySpi
    {
        public HAWK_512()
        {
            super(BCObjectIdentifiers.hawk512);
        }
    }

    public static class HAWK_1024
        extends HawkKeyFactorySpi
    {
        public HAWK_1024()
        {
            super(BCObjectIdentifiers.hawk1024);
        }
    }
}
