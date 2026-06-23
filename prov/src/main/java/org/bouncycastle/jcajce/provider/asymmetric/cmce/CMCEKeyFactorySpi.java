package org.bouncycastle.jcajce.provider.asymmetric.cmce;

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

public class CMCEKeyFactorySpi
    extends BasePQCKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(ISOIECObjectIdentifiers.mceliece460896);
        keyOids.add(ISOIECObjectIdentifiers.mceliece460896f);
        keyOids.add(ISOIECObjectIdentifiers.mceliece460896pc);
        keyOids.add(ISOIECObjectIdentifiers.mceliece460896pcf);
        keyOids.add(ISOIECObjectIdentifiers.mceliece6688128);
        keyOids.add(ISOIECObjectIdentifiers.mceliece6688128f);
        keyOids.add(ISOIECObjectIdentifiers.mceliece6688128pc);
        keyOids.add(ISOIECObjectIdentifiers.mceliece6688128pcf);
        keyOids.add(ISOIECObjectIdentifiers.mceliece6960119);
        keyOids.add(ISOIECObjectIdentifiers.mceliece6960119f);
        keyOids.add(ISOIECObjectIdentifiers.mceliece6960119pc);
        keyOids.add(ISOIECObjectIdentifiers.mceliece6960119pcf);
        keyOids.add(ISOIECObjectIdentifiers.mceliece8192128);
        keyOids.add(ISOIECObjectIdentifiers.mceliece8192128f);
        keyOids.add(ISOIECObjectIdentifiers.mceliece8192128pc);
        keyOids.add(ISOIECObjectIdentifiers.mceliece8192128pcf);
    }

    public CMCEKeyFactorySpi()
    {
        super(keyOids);
    }

    public CMCEKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCCMCEPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCCMCEPublicKey)
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
        if (key instanceof BCCMCEPrivateKey || key instanceof BCCMCEPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCCMCEPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCCMCEPublicKey(keyInfo);
    }

    public static class Mceliece460896
        extends CMCEKeyFactorySpi
    {
        public Mceliece460896()
        {
            super(ISOIECObjectIdentifiers.mceliece460896);
        }
    }

    public static class Mceliece460896F
        extends CMCEKeyFactorySpi
    {
        public Mceliece460896F()
        {
            super(ISOIECObjectIdentifiers.mceliece460896f);
        }
    }

    public static class Mceliece460896Pc
        extends CMCEKeyFactorySpi
    {
        public Mceliece460896Pc()
        {
            super(ISOIECObjectIdentifiers.mceliece460896pc);
        }
    }

    public static class Mceliece460896Pcf
        extends CMCEKeyFactorySpi
    {
        public Mceliece460896Pcf()
        {
            super(ISOIECObjectIdentifiers.mceliece460896pcf);
        }
    }

    public static class Mceliece6688128
        extends CMCEKeyFactorySpi
    {
        public Mceliece6688128()
        {
            super(ISOIECObjectIdentifiers.mceliece6688128);
        }
    }

    public static class Mceliece6688128F
        extends CMCEKeyFactorySpi
    {
        public Mceliece6688128F()
        {
            super(ISOIECObjectIdentifiers.mceliece6688128f);
        }
    }

    public static class Mceliece6688128Pc
        extends CMCEKeyFactorySpi
    {
        public Mceliece6688128Pc()
        {
            super(ISOIECObjectIdentifiers.mceliece6688128pc);
        }
    }

    public static class Mceliece6688128Pcf
        extends CMCEKeyFactorySpi
    {
        public Mceliece6688128Pcf()
        {
            super(ISOIECObjectIdentifiers.mceliece6688128pcf);
        }
    }

    public static class Mceliece6960119
        extends CMCEKeyFactorySpi
    {
        public Mceliece6960119()
        {
            super(ISOIECObjectIdentifiers.mceliece6960119);
        }
    }

    public static class Mceliece6960119F
        extends CMCEKeyFactorySpi
    {
        public Mceliece6960119F()
        {
            super(ISOIECObjectIdentifiers.mceliece6960119f);
        }
    }

    public static class Mceliece6960119Pc
        extends CMCEKeyFactorySpi
    {
        public Mceliece6960119Pc()
        {
            super(ISOIECObjectIdentifiers.mceliece6960119pc);
        }
    }

    public static class Mceliece6960119Pcf
        extends CMCEKeyFactorySpi
    {
        public Mceliece6960119Pcf()
        {
            super(ISOIECObjectIdentifiers.mceliece6960119pcf);
        }
    }

    public static class Mceliece8192128
        extends CMCEKeyFactorySpi
    {
        public Mceliece8192128()
        {
            super(ISOIECObjectIdentifiers.mceliece8192128);
        }
    }

    public static class Mceliece8192128F
        extends CMCEKeyFactorySpi
    {
        public Mceliece8192128F()
        {
            super(ISOIECObjectIdentifiers.mceliece8192128f);
        }
    }

    public static class Mceliece8192128Pc
        extends CMCEKeyFactorySpi
    {
        public Mceliece8192128Pc()
        {
            super(ISOIECObjectIdentifiers.mceliece8192128pc);
        }
    }

    public static class Mceliece8192128Pcf
        extends CMCEKeyFactorySpi
    {
        public Mceliece8192128Pcf()
        {
            super(ISOIECObjectIdentifiers.mceliece8192128pcf);
        }
    }
}
