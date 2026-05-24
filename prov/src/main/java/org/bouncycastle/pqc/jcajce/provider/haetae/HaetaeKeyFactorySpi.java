package org.bouncycastle.pqc.jcajce.provider.haetae;

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
 * {@link java.security.KeyFactorySpi} for HAETAE. The unparameterised form
 * accepts encoded keys for any HAETAE parameter set; the nested
 * {@link HAETAE2} / {@link HAETAE3} / {@link HAETAE5} subclasses restrict
 * decoding to a single OID for use as the per-parameter-set
 * {@code KeyFactory.<spec.getName()>} registrations.
 */
public class HaetaeKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.haetae2);
        keyOids.add(BCObjectIdentifiers.haetae3);
        keyOids.add(BCObjectIdentifiers.haetae5);
    }

    public HaetaeKeyFactorySpi()
    {
        super(keyOids);
    }

    public HaetaeKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCHaetaePrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCHaetaePublicKey)
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
        if (key instanceof BCHaetaePrivateKey || key instanceof BCHaetaePublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCHaetaePrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCHaetaePublicKey(keyInfo);
    }

    public static class HAETAE2
        extends HaetaeKeyFactorySpi
    {
        public HAETAE2()
        {
            super(BCObjectIdentifiers.haetae2);
        }
    }

    public static class HAETAE3
        extends HaetaeKeyFactorySpi
    {
        public HAETAE3()
        {
            super(BCObjectIdentifiers.haetae3);
        }
    }

    public static class HAETAE5
        extends HaetaeKeyFactorySpi
    {
        public HAETAE5()
        {
            super(BCObjectIdentifiers.haetae5);
        }
    }
}
