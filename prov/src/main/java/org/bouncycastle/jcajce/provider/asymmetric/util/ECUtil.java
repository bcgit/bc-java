package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.anssi.ANSSINamedCurves;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * utility class for converting jce/jca ECDSA, ECDH, and ECDHC
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class ECUtil
{
    /**
     * Returns a sorted array of middle terms of the reduction polynomial.
     * @param k The unsorted array of middle terms of the reduction polynomial
     * of length 1 or 3.
     * @return the sorted array of middle terms of the reduction polynomial.
     * This array always has length 3.
     */
    static int[] convertMidTerms(
        int[] k)
    {
        int[] res = new int[3];
        
        if (k.length == 1)
        {
            res[0] = k[0];
        }
        else
        {
            if (k.length != 3)
            {
                throw new IllegalArgumentException("Only Trinomials and pentanomials supported");
            }

            if (k[0] < k[1] && k[0] < k[2])
            {
                res[0] = k[0];
                if (k[1] < k[2])
                {
                    res[1] = k[1];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[1];
                }
            }
            else if (k[1] < k[2])
            {
                res[0] = k[1];
                if (k[0] < k[2])
                {
                    res[1] = k[0];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[0];
                }
            }
            else
            {
                res[0] = k[2];
                if (k[0] < k[1])
                {
                    res[1] = k[0];
                    res[2] = k[1];
                }
                else
                {
                    res[1] = k[1];
                    res[2] = k[0];
                }
            }
        }

        return res;
    }

    public static ECDomainParameters getDomainParameters(
        ProviderConfiguration configuration,
        org.bouncycastle.jce.spec.ECParameterSpec params)
    {
        ECDomainParameters domainParameters;

        if (params instanceof ECNamedCurveParameterSpec)
        {
            ECNamedCurveParameterSpec nParams = (ECNamedCurveParameterSpec)params;
            ASN1ObjectIdentifier nameOid = ECUtil.getNamedCurveOid(nParams.getName());

            domainParameters = new ECNamedDomainParameters(nameOid, nParams.getCurve(), nParams.getG(), nParams.getN(), nParams.getH(), nParams.getSeed());
        }
        else if (params == null)
        {
            org.bouncycastle.jce.spec.ECParameterSpec iSpec = configuration.getEcImplicitlyCa();

            domainParameters = new ECDomainParameters(iSpec.getCurve(), iSpec.getG(), iSpec.getN(), iSpec.getH(), iSpec.getSeed());
        }
        else
        {
            domainParameters = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());
        }

        return domainParameters;
    }

    public static ECDomainParameters getDomainParameters(
        ProviderConfiguration configuration,
        X962Parameters params)
    {
        ECDomainParameters domainParameters;

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
            X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);
            if (ecP == null)
            {
                Map extraCurves = configuration.getAdditionalECParameters();

                ecP = (X9ECParameters)extraCurves.get(oid);
            }
            domainParameters = new ECNamedDomainParameters(oid, ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
        }
        else if (params.isImplicitlyCA())
        {
            org.bouncycastle.jce.spec.ECParameterSpec iSpec = configuration.getEcImplicitlyCa();

            domainParameters = new ECDomainParameters(iSpec.getCurve(), iSpec.getG(), iSpec.getN(), iSpec.getH(), iSpec.getSeed());
        }
        else
        {
            X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());

            domainParameters = new ECDomainParameters(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
        }

        return domainParameters;
    }

    public static AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof ECPublicKey)
        {
            ECPublicKey    k = (ECPublicKey)key;
            ECParameterSpec s = k.getParameters();

            return new ECPublicKeyParameters(
                            k.getQ(),
                            new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
        }
        else if (key instanceof java.security.interfaces.ECPublicKey)
        {
            java.security.interfaces.ECPublicKey pubKey = (java.security.interfaces.ECPublicKey)key;
            ECParameterSpec s = EC5Util.convertSpec(pubKey.getParams(), false);
            return new ECPublicKeyParameters(
                EC5Util.convertPoint(pubKey.getParams(), pubKey.getW(), false),
                            new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
        }
        else
        {
            // see if we can build a key from key.getEncoded()
            try
            {
                byte[] bytes = key.getEncoded();

                if (bytes == null)
                {
                    throw new InvalidKeyException("no encoding for EC public key");
                }

                PublicKey publicKey = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(bytes));

                if (publicKey instanceof java.security.interfaces.ECPublicKey)
                {
                    return ECUtil.generatePublicKeyParameter(publicKey);
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("cannot identify EC public key: " + e.toString());
            }
        }

        throw new InvalidKeyException("cannot identify EC public key.");
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        if (key instanceof ECPrivateKey)
        {
            ECPrivateKey  k = (ECPrivateKey)key;
            ECParameterSpec s = k.getParameters();

            if (s == null)
            {
                s = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
            }

            return new ECPrivateKeyParameters(
                            k.getD(),
                            new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
        }
        else if (key instanceof java.security.interfaces.ECPrivateKey)
        {
            java.security.interfaces.ECPrivateKey privKey = (java.security.interfaces.ECPrivateKey)key;
            ECParameterSpec s = EC5Util.convertSpec(privKey.getParams(), false);
            return new ECPrivateKeyParameters(
                            privKey.getS(),
                            new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
        }
        else
        {
            // see if we can build a key from key.getEncoded()
            try
            {
                byte[] bytes = key.getEncoded();

                if (bytes == null)
                {
                    throw new InvalidKeyException("no encoding for EC private key");
                }

                PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(bytes));

                if (privateKey instanceof java.security.interfaces.ECPrivateKey)
                {
                    return ECUtil.generatePrivateKeyParameter(privateKey);
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("cannot identify EC private key: " + e.toString());
            }
        }

        throw new InvalidKeyException("can't identify EC private key.");
    }

    public static int getOrderBitLength(ProviderConfiguration configuration, BigInteger order, BigInteger privateValue)
    {
        if (order == null)     // implicitly CA
        {
            ECParameterSpec implicitCA = configuration.getEcImplicitlyCa();

            if (implicitCA == null)
            {
                return privateValue.bitLength();   // a guess but better than an exception!
            }

            return implicitCA.getN().bitLength();
        }
        else
        {
            return order.bitLength();
        }
    }

    public static ASN1ObjectIdentifier getNamedCurveOid(
        String curveName)
    {
        String name;

        if (curveName.indexOf(' ') > 0)
        {
            name = curveName.substring(curveName.indexOf(' ') + 1);
        }
        else
        {
            name = curveName;
        }

        try
        {
            if (name.charAt(0) >= '0' && name.charAt(0) <= '2')
            {
                return new ASN1ObjectIdentifier(name);
            }
            else
            {
                return lookupOidByName(name);
            }
        }
        catch (IllegalArgumentException ex)
        {
            return lookupOidByName(name);
        }
    }

    private static ASN1ObjectIdentifier lookupOidByName(String name)
    {
        ASN1ObjectIdentifier oid = X962NamedCurves.getOID(name);

        if (oid == null)
        {
            oid = SECNamedCurves.getOID(name);
            if (oid == null)
            {
                oid = NISTNamedCurves.getOID(name);
            }
            if (oid == null)
            {
                oid = TeleTrusTNamedCurves.getOID(name);
            }
            if (oid == null)
            {
                oid = ECGOST3410NamedCurves.getOID(name);
            }
            if (oid == null)
            {
                oid = ANSSINamedCurves.getOID(name);
            }
            if (oid == null)
            {
                oid = GMNamedCurves.getOID(name);
            }
        }

        return oid;
    }

    public static ASN1ObjectIdentifier getNamedCurveOid(
        ECParameterSpec ecParameterSpec)
    {
        for (Enumeration names = ECNamedCurveTable.getNames(); names.hasMoreElements();)
        {
            String name = (String)names.nextElement();

            X9ECParameters params = ECNamedCurveTable.getByName(name);

            if (params.getN().equals(ecParameterSpec.getN())
                && params.getH().equals(ecParameterSpec.getH())
                && params.getCurve().equals(ecParameterSpec.getCurve())
                && params.getG().equals(ecParameterSpec.getG()))
            {
                return org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID(name);
            }
        }

        return null;
    }

    public static X9ECParameters getNamedCurveByOid(
        ASN1ObjectIdentifier oid)
    {
        X9ECParameters params = CustomNamedCurves.getByOID(oid);

        if (params == null)
        {
            params = X962NamedCurves.getByOID(oid);
            if (params == null)
            {
                params = SECNamedCurves.getByOID(oid);
            }
            if (params == null)
            {
                params = NISTNamedCurves.getByOID(oid);
            }
            if (params == null)
            {
                params = TeleTrusTNamedCurves.getByOID(oid);
            }
            if (params == null)
            {
                params = GMNamedCurves.getByOID(oid);
            }
        }

        return params;
    }

    public static X9ECParameters getNamedCurveByName(
        String curveName)
    {
        X9ECParameters params = CustomNamedCurves.getByName(curveName);

        if (params == null)
        {
            params = X962NamedCurves.getByName(curveName);
            if (params == null)
            {
                params = SECNamedCurves.getByName(curveName);
            }
            if (params == null)
            {
                params = NISTNamedCurves.getByName(curveName);
            }
            if (params == null)
            {
                params = TeleTrusTNamedCurves.getByName(curveName);
            }
            if (params == null)
            {
                params = GMNamedCurves.getByName(curveName);
            }
        }

        return params;
    }

    public static String getCurveName(
        ASN1ObjectIdentifier oid)
    {
        String name = X962NamedCurves.getName(oid);
        
        if (name == null)
        {
            name = SECNamedCurves.getName(oid);
            if (name == null)
            {
                name = NISTNamedCurves.getName(oid);
            }
            if (name == null)
            {
                name = TeleTrusTNamedCurves.getName(oid);
            }
            if (name == null)
            {
                name = ECGOST3410NamedCurves.getName(oid);
            }
        }

        return name;
    }
}
