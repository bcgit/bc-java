package org.bouncycastle.jcajce.provider.asymmetric.ecgost12;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

public class KeyFactorySpi
    extends BaseKeyFactorySpi
{
    public KeyFactorySpi()
    {
    }

    protected KeySpec engineGetKeySpec(
        Key key,
        Class spec)
        throws InvalidKeySpecException
    {
       if (spec.isAssignableFrom(java.security.spec.ECPublicKeySpec.class) && key instanceof ECPublicKey)
       {
           ECPublicKey k = (ECPublicKey)key;
           if (k.getParams() != null)
           {
               return new java.security.spec.ECPublicKeySpec(k.getW(), k.getParams());
           }
           else
           {
               ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

               return new java.security.spec.ECPublicKeySpec(k.getW(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
           }
       }
       else if (spec.isAssignableFrom(java.security.spec.ECPrivateKeySpec.class) && key instanceof ECPrivateKey)
       {
           ECPrivateKey k = (ECPrivateKey)key;

           if (k.getParams() != null)
           {
               return new java.security.spec.ECPrivateKeySpec(k.getS(), k.getParams());
           }
           else
           {
               ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

               return new java.security.spec.ECPrivateKeySpec(k.getS(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
           }
       }
       else if (spec.isAssignableFrom(ECPublicKeySpec.class) && key instanceof ECPublicKey)
       {
           ECPublicKey k = (ECPublicKey)key;
           if (k.getParams() != null)
           {
               return new ECPublicKeySpec(EC5Util.convertPoint(k.getParams(), k.getW()), EC5Util.convertSpec(k.getParams()));
           }
           else
           {
               ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

               return new ECPublicKeySpec(EC5Util.convertPoint(k.getParams(), k.getW()), implicitSpec);
           }
       }
       else if (spec.isAssignableFrom(ECPrivateKeySpec.class) && key instanceof ECPrivateKey)
       {
           ECPrivateKey k = (ECPrivateKey)key;

           if (k.getParams() != null)
           {
               return new ECPrivateKeySpec(k.getS(), EC5Util.convertSpec(k.getParams()));
           }
           else
           {
               ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

               return new ECPrivateKeySpec(k.getS(), implicitSpec);
           }
       }

       return super.engineGetKeySpec(key, spec);
    }

    protected Key engineTranslateKey(
        Key key)
        throws InvalidKeyException
    {
        throw new InvalidKeyException("key type unknown");
    }

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof ECPrivateKeySpec)
        {
            return new BCECGOST3410_2012PrivateKey((ECPrivateKeySpec)keySpec);
        }
        else if (keySpec instanceof java.security.spec.ECPrivateKeySpec)
        {
            return new BCECGOST3410_2012PrivateKey((java.security.spec.ECPrivateKeySpec)keySpec);
        }

        return super.engineGeneratePrivate(keySpec);
    }

    public PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof ECPublicKeySpec)
        {
            return new BCECGOST3410_2012PublicKey((ECPublicKeySpec)keySpec, BouncyCastleProvider.CONFIGURATION);
        }
        else if (keySpec instanceof java.security.spec.ECPublicKeySpec)
        {
            return new BCECGOST3410_2012PublicKey((java.security.spec.ECPublicKeySpec)keySpec);
        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (isValid(algOid))
        {
            return new BCECGOST3410_2012PrivateKey(keyInfo);
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

        if (isValid(algOid))
        {
            return new BCECGOST3410_2012PublicKey(keyInfo);
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    private boolean isValid(ASN1ObjectIdentifier algOid)
    {
        return algOid.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256)
            || algOid.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512)
            || algOid.equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256)
            || algOid.equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512);
    }
}
