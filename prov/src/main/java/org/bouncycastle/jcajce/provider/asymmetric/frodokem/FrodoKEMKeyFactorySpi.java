package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

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
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.BasePQCKeyFactorySpi;

public class FrodoKEMKeyFactorySpi
    extends BasePQCKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(ISOIECObjectIdentifiers.frodokem976_shake);
        keyOids.add(ISOIECObjectIdentifiers.frodokem1344_shake);
        keyOids.add(ISOIECObjectIdentifiers.efrodokem976_shake);
        keyOids.add(ISOIECObjectIdentifiers.efrodokem1344_shake);
        keyOids.add(ISOIECObjectIdentifiers.frodokem976_aes);
        keyOids.add(ISOIECObjectIdentifiers.frodokem1344_aes);
        keyOids.add(ISOIECObjectIdentifiers.efrodokem976_aes);
        keyOids.add(ISOIECObjectIdentifiers.efrodokem1344_aes);
    }

    public FrodoKEMKeyFactorySpi()
    {
        super(keyOids);
    }

    public FrodoKEMKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCFrodoKEMPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCFrodoKEMPublicKey)
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

        throw new InvalidKeySpecException("unknown key specification: "
            + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCFrodoKEMPrivateKey || key instanceof BCFrodoKEMPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCFrodoKEMPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCFrodoKEMPublicKey(keyInfo);
    }

    public static class Frodokem976Shake
        extends FrodoKEMKeyFactorySpi
    {
        public Frodokem976Shake()
        {
            super(ISOIECObjectIdentifiers.frodokem976_shake);
        }
    }

    public static class Frodokem1344Shake
        extends FrodoKEMKeyFactorySpi
    {
        public Frodokem1344Shake()
        {
            super(ISOIECObjectIdentifiers.frodokem1344_shake);
        }
    }

    public static class EFrodokem976Shake
        extends FrodoKEMKeyFactorySpi
    {
        public EFrodokem976Shake()
        {
            super(ISOIECObjectIdentifiers.efrodokem976_shake);
        }
    }

    public static class EFrodokem1344Shake
        extends FrodoKEMKeyFactorySpi
    {
        public EFrodokem1344Shake()
        {
            super(ISOIECObjectIdentifiers.efrodokem1344_shake);
        }
    }

    public static class Frodokem976Aes
        extends FrodoKEMKeyFactorySpi
    {
        public Frodokem976Aes()
        {
            super(ISOIECObjectIdentifiers.frodokem976_aes);
        }
    }

    public static class Frodokem1344Aes
        extends FrodoKEMKeyFactorySpi
    {
        public Frodokem1344Aes()
        {
            super(ISOIECObjectIdentifiers.frodokem1344_aes);
        }
    }

    public static class EFrodokem976Aes
        extends FrodoKEMKeyFactorySpi
    {
        public EFrodokem976Aes()
        {
            super(ISOIECObjectIdentifiers.efrodokem976_aes);
        }
    }

    public static class EFrodokem1344Aes
        extends FrodoKEMKeyFactorySpi
    {
        public EFrodokem1344Aes()
        {
            super(ISOIECObjectIdentifiers.efrodokem1344_aes);
        }
    }
}
