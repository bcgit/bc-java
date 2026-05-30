package org.bouncycastle.pqc.jcajce.provider.qruov;

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

public class QRUOVKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.qruov1q127L3v156m54);
        keyOids.add(BCObjectIdentifiers.qruov1q31L3v165m60);
        keyOids.add(BCObjectIdentifiers.qruov1q31L10v600m70);
        keyOids.add(BCObjectIdentifiers.qruov1q7L10v740m100);
        keyOids.add(BCObjectIdentifiers.qruov3q127L3v228m78);
        keyOids.add(BCObjectIdentifiers.qruov3q31L3v246m87);
        keyOids.add(BCObjectIdentifiers.qruov3q31L10v890m100);
        keyOids.add(BCObjectIdentifiers.qruov3q7L10v1100m140);
        keyOids.add(BCObjectIdentifiers.qruov5q127L3v306m105);
        keyOids.add(BCObjectIdentifiers.qruov5q31L3v324m114);
        keyOids.add(BCObjectIdentifiers.qruov5q31L10v1120m120);
        keyOids.add(BCObjectIdentifiers.qruov5q7L10v1490m190);
    }

    public QRUOVKeyFactorySpi()
    {
        super(keyOids);
    }

    public QRUOVKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (key instanceof BCQRUOVPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCQRUOVPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
        }
        else
        {
            throw new InvalidKeySpecException("Unsupported key type: " + key.getClass() + ".");
        }
        throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCQRUOVPrivateKey || key instanceof BCQRUOVPublicKey)
        {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        return new BCQRUOVPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return new BCQRUOVPublicKey(keyInfo);
    }

    public static class QRUOV1Q127L3V156M54
        extends QRUOVKeyFactorySpi
    {
        public QRUOV1Q127L3V156M54()
        {
            super(BCObjectIdentifiers.qruov1q127L3v156m54);
        }
    }

    public static class QRUOV1Q31L3V165M60
        extends QRUOVKeyFactorySpi
    {
        public QRUOV1Q31L3V165M60()
        {
            super(BCObjectIdentifiers.qruov1q31L3v165m60);
        }
    }

    public static class QRUOV1Q31L10V600M70
        extends QRUOVKeyFactorySpi
    {
        public QRUOV1Q31L10V600M70()
        {
            super(BCObjectIdentifiers.qruov1q31L10v600m70);
        }
    }

    public static class QRUOV1Q7L10V740M100
        extends QRUOVKeyFactorySpi
    {
        public QRUOV1Q7L10V740M100()
        {
            super(BCObjectIdentifiers.qruov1q7L10v740m100);
        }
    }

    public static class QRUOV3Q127L3V228M78
        extends QRUOVKeyFactorySpi
    {
        public QRUOV3Q127L3V228M78()
        {
            super(BCObjectIdentifiers.qruov3q127L3v228m78);
        }
    }

    public static class QRUOV3Q31L3V246M87
        extends QRUOVKeyFactorySpi
    {
        public QRUOV3Q31L3V246M87()
        {
            super(BCObjectIdentifiers.qruov3q31L3v246m87);
        }
    }

    public static class QRUOV3Q31L10V890M100
        extends QRUOVKeyFactorySpi
    {
        public QRUOV3Q31L10V890M100()
        {
            super(BCObjectIdentifiers.qruov3q31L10v890m100);
        }
    }

    public static class QRUOV3Q7L10V1100M140
        extends QRUOVKeyFactorySpi
    {
        public QRUOV3Q7L10V1100M140()
        {
            super(BCObjectIdentifiers.qruov3q7L10v1100m140);
        }
    }

    public static class QRUOV5Q127L3V306M105
        extends QRUOVKeyFactorySpi
    {
        public QRUOV5Q127L3V306M105()
        {
            super(BCObjectIdentifiers.qruov5q127L3v306m105);
        }
    }

    public static class QRUOV5Q31L3V324M114
        extends QRUOVKeyFactorySpi
    {
        public QRUOV5Q31L3V324M114()
        {
            super(BCObjectIdentifiers.qruov5q31L3v324m114);
        }
    }

    public static class QRUOV5Q31L10V1120M120
        extends QRUOVKeyFactorySpi
    {
        public QRUOV5Q31L10V1120M120()
        {
            super(BCObjectIdentifiers.qruov5q31L10v1120m120);
        }
    }

    public static class QRUOV5Q7L10V1490M190
        extends QRUOVKeyFactorySpi
    {
        public QRUOV5Q7L10V1490M190()
        {
            super(BCObjectIdentifiers.qruov5q7L10v1490m190);
        }
    }
}
