package org.bouncycastle.pqc.jcajce.provider.uov;

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

public class UOVKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.uov_Is_classic);
        keyOids.add(BCObjectIdentifiers.uov_Is_pkc);
        keyOids.add(BCObjectIdentifiers.uov_Is_pkc_skc);
        keyOids.add(BCObjectIdentifiers.uov_Ip_classic);
        keyOids.add(BCObjectIdentifiers.uov_Ip_pkc);
        keyOids.add(BCObjectIdentifiers.uov_Ip_pkc_skc);
        keyOids.add(BCObjectIdentifiers.uov_III_classic);
        keyOids.add(BCObjectIdentifiers.uov_III_pkc);
        keyOids.add(BCObjectIdentifiers.uov_III_pkc_skc);
        keyOids.add(BCObjectIdentifiers.uov_V_classic);
        keyOids.add(BCObjectIdentifiers.uov_V_pkc);
        keyOids.add(BCObjectIdentifiers.uov_V_pkc_skc);
    }

    public UOVKeyFactorySpi()
    {
        super(keyOids);
    }

    public UOVKeyFactorySpi(ASN1ObjectIdentifier keyOid)
    {
        super(keyOid);
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
            throws InvalidKeySpecException
    {
        if (key instanceof BCUOVPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCUOVPublicKey)
        {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new X509EncodedKeySpec(key.getEncoded());
            }
        }
        else
        {
            throw new InvalidKeySpecException("unsupported key type: " + key.getClass() + ".");
        }
        throw new InvalidKeySpecException("unknown key specification: " + keySpec + ".");
    }

    public final Key engineTranslateKey(Key key)
            throws InvalidKeyException
    {
        if (key instanceof BCUOVPrivateKey || key instanceof BCUOVPublicKey)
        {
            return key;
        }
        throw new InvalidKeyException("unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
    {
        return new BCUOVPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
    {
        return new BCUOVPublicKey(keyInfo);
    }

    public static class Generic
            extends UOVKeyFactorySpi
    {
        public Generic()
        {
            super();
        }
    }

    public static class Is extends UOVKeyFactorySpi
    {
        public Is()
        {
            super(BCObjectIdentifiers.uov_Is_classic);
        }
    }

    public static class IsPkc extends UOVKeyFactorySpi
    {
        public IsPkc()
        {
            super(BCObjectIdentifiers.uov_Is_pkc);
        }
    }

    public static class IsPkcSkc extends UOVKeyFactorySpi
    {
        public IsPkcSkc()
        {
            super(BCObjectIdentifiers.uov_Is_pkc_skc);
        }
    }

    public static class Ip extends UOVKeyFactorySpi
    {
        public Ip()
        {
            super(BCObjectIdentifiers.uov_Ip_classic);
        }
    }

    public static class IpPkc extends UOVKeyFactorySpi
    {
        public IpPkc()
        {
            super(BCObjectIdentifiers.uov_Ip_pkc);
        }
    }

    public static class IpPkcSkc extends UOVKeyFactorySpi
    {
        public IpPkcSkc()
        {
            super(BCObjectIdentifiers.uov_Ip_pkc_skc);
        }
    }

    public static class III extends UOVKeyFactorySpi
    {
        public III()
        {
            super(BCObjectIdentifiers.uov_III_classic);
        }
    }

    public static class IIIPkc extends UOVKeyFactorySpi
    {
        public IIIPkc()
        {
            super(BCObjectIdentifiers.uov_III_pkc);
        }
    }

    public static class IIIPkcSkc extends UOVKeyFactorySpi
    {
        public IIIPkcSkc()
        {
            super(BCObjectIdentifiers.uov_III_pkc_skc);
        }
    }

    public static class V extends UOVKeyFactorySpi
    {
        public V()
        {
            super(BCObjectIdentifiers.uov_V_classic);
        }
    }

    public static class VPkc extends UOVKeyFactorySpi
    {
        public VPkc()
        {
            super(BCObjectIdentifiers.uov_V_pkc);
        }
    }

    public static class VPkcSkc extends UOVKeyFactorySpi
    {
        public VPkcSkc()
        {
            super(BCObjectIdentifiers.uov_V_pkc_skc);
        }
    }
}
