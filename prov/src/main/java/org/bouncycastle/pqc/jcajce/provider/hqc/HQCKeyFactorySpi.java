package org.bouncycastle.pqc.jcajce.provider.hqc;

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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.jcajce.provider.util.BaseKeyFactorySpi;

public class HQCKeyFactorySpi
    extends BaseKeyFactorySpi
{
    private static final Set<ASN1ObjectIdentifier> keyOids = new HashSet<ASN1ObjectIdentifier>();

    static
    {
        keyOids.add(BCObjectIdentifiers.hqc128);
        keyOids.add(BCObjectIdentifiers.hqc192);
        keyOids.add(BCObjectIdentifiers.hqc256);
    }

    public HQCKeyFactorySpi()
    {
        super(keyOids);
    }

    public HQCKeyFactorySpi(ASN1ObjectIdentifier keyOids)
    {
        super(keyOids);
    }
    
    public PrivateKey engineGeneratePrivate(KeySpec keySpec)
            throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            // get the DER-encoded Key according to PKCS#8 from the spec
            byte[] encKey = ((PKCS8EncodedKeySpec)keySpec).getEncoded();

            try
            {
                return generatePrivate(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey)));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.toString());
            }
        }

        throw new InvalidKeySpecException("Unsupported key specification: "
                + keySpec.getClass() + ".");
    }

    public PublicKey engineGeneratePublic(KeySpec keySpec)
            throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            // get the DER-encoded Key according to X.509 from the spec
            byte[] encKey = ((X509EncodedKeySpec)keySpec).getEncoded();

            // decode the SubjectPublicKeyInfo data structure to the pki object
            try
            {
                return generatePublic(SubjectPublicKeyInfo.getInstance(encKey));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.toString());
            }
        }

        throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
    }

    public final KeySpec engineGetKeySpec(Key key, Class keySpec)
            throws InvalidKeySpecException
    {
        if (key instanceof BCHQCPrivateKey)
        {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec))
            {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        }
        else if (key instanceof BCHQCPublicKey)
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
        if (key instanceof BCHQCPrivateKey || key instanceof BCHQCPublicKey)
        {
            return key;
        }

        throw new InvalidKeyException("Unsupported key type");
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
    {
        return new BCHQCPrivateKey(keyInfo);
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
    {
        return new BCHQCPublicKey(keyInfo);
    }

    public static class HQC128
        extends HQCKeyFactorySpi
    {
        public HQC128()
        {
            super(BCObjectIdentifiers.hqc128);
        }
    }

    public static class HQC192
        extends HQCKeyFactorySpi
    {
        public HQC192()
        {
            super(BCObjectIdentifiers.hqc192);
        }
    }

    public static class HQC256
        extends HQCKeyFactorySpi
    {
        public HQC256()
        {
            super(BCObjectIdentifiers.hqc256);
        }
    }
}
