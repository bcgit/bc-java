package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

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
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;

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
            ASN1ObjectIdentifier nameOid = getNamedCurveOid(nParams.getName());

            domainParameters = toNamedDomainParameters(nameOid, nParams);
        }
        else if (params == null)
        {
            org.bouncycastle.jce.spec.ECParameterSpec iSpec = configuration.getEcImplicitlyCa();

            domainParameters = toDomainParameters(iSpec);
        }
        else
        {
            domainParameters = toDomainParameters(params);
        }

        return domainParameters;
    }

    private static ECDomainParameters toDomainParameters(
        org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        return new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }

    private static ECNamedDomainParameters toNamedDomainParameters(
        ASN1ObjectIdentifier                      name,
        org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        return new ECNamedDomainParameters(name, spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }

    public static ECDomainParameters getDomainParameters(
        ProviderConfiguration configuration,
        X962Parameters params)
    {
        ECDomainParameters domainParameters;

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
            X9ECParameters ecP = getNamedCurveByOid(oid);

            domainParameters = new ECNamedDomainParameters(oid, ecP);
        }
        else if (params.isImplicitlyCA())
        {
            org.bouncycastle.jce.spec.ECParameterSpec iSpec = configuration.getEcImplicitlyCa();

            domainParameters = toDomainParameters(iSpec);
        }
        else
        {
            X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());

            domainParameters = new ECDomainParameters(ecP);
        }

        return domainParameters;
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

    public static AsymmetricKeyParameter generatePublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        if (key instanceof ECPublicKey)
        {
            return bcPublicKeyParameter((ECPublicKey)key);
        }
        else
        {
            return encodedPublicKeyParameter(key);
        }
    }

    private static AsymmetricKeyParameter bcPublicKeyParameter(
        ECPublicKey    key)
        throws InvalidKeyException
    {
        try
        {
            ECParameterSpec s = getKeyParameters(key.getParameters(), "public");

            return new ECPublicKeyParameters(key.getQ(), toDomainParameters(s));
        }
        catch (RuntimeException e)
        {
            throw SecurityExceptions.invalidKeyException("invalid EC public key: " + e.getMessage(), e);
        }
    }

    // A key that is not a BC EC key: rebuild it from its encoding with the BC provider, and convert the
    // result directly rather than through generatePublicKeyParameter, so it cannot recurse.
    private static AsymmetricKeyParameter encodedPublicKeyParameter(
        PublicKey    key)
        throws InvalidKeyException
    {
        PublicKey publicKey;
        try
        {
            byte[] bytes = key.getEncoded();

            if (bytes == null)
            {
                throw new InvalidKeyException("no encoding for EC public key");
            }

            publicKey = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(bytes));
        }
        catch (Exception e)
        {
            throw SecurityExceptions.invalidKeyException("cannot identify EC public key: " + e.toString(), e);
        }

        if (publicKey instanceof ECPublicKey)
        {
            return bcPublicKeyParameter((ECPublicKey)publicKey);
        }

        throw new InvalidKeyException("cannot identify EC public key.");
    }

    public static AsymmetricKeyParameter generatePrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        if (key instanceof ECPrivateKey)
        {
            return bcPrivateKeyParameter((ECPrivateKey)key);
        }
        else
        {
            return encodedPrivateKeyParameter(key);
        }
    }

    private static AsymmetricKeyParameter bcPrivateKeyParameter(
        ECPrivateKey    key)
        throws InvalidKeyException
    {
        try
        {
            ECParameterSpec s = getKeyParameters(key.getParameters(), "private");

            return new ECPrivateKeyParameters(key.getD(), toDomainParameters(s));
        }
        catch (RuntimeException e)
        {
            throw SecurityExceptions.invalidKeyException("invalid EC private key: " + e.getMessage(), e);
        }
    }

    // A key's own domain parameters, or the configured implicitlyCA ones when it has none.
    private static ECParameterSpec getKeyParameters(
        ECParameterSpec s,
        String          keyType)
        throws InvalidKeyException
    {
        if (s != null)
        {
            return s;
        }

        // TODO A key built with its own ProviderConfiguration should resolve implicitlyCA through that, not the global one
        ECParameterSpec implicitlyCa = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
        if (implicitlyCa == null)
        {
            throw new InvalidKeyException("EC " + keyType + " key uses implicitlyCA parameters but none are configured");
        }

        return implicitlyCa;
    }

    // A key that is not a BC EC key: rebuild it from its encoding with the BC provider, and convert the
    // result directly rather than through generatePrivateKeyParameter, so it cannot recurse.
    private static AsymmetricKeyParameter encodedPrivateKeyParameter(
        PrivateKey    key)
        throws InvalidKeyException
    {
        PrivateKey privateKey;
        try
        {
            byte[] bytes = key.getEncoded();

            if (bytes == null)
            {
                throw new InvalidKeyException("no encoding for EC private key");
            }

            privateKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(bytes));
        }
        catch (Exception e)
        {
            throw SecurityExceptions.invalidKeyException("cannot identify EC private key: " + e.toString(), e);
        }

        if (privateKey instanceof ECPrivateKey)
        {
            return bcPrivateKeyParameter((ECPrivateKey)privateKey);
        }

        throw new InvalidKeyException("can't identify EC private key.");
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
        ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(name);

        return oid;
    }
    
    public static X9ECParameters getNamedCurveByOid(
        ASN1ObjectIdentifier oid)
    {
        X9ECParameters params = CustomNamedCurves.getByOID(oid);

        if (params == null)
        {
            params = ECNamedCurveTable.getByOID(oid);
        }

        return params;
    }

    public static X9ECParameters getNamedCurveByName(
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

        X9ECParameters params = CustomNamedCurves.getByName(name);

        if (params == null)
        {
            params = ECNamedCurveTable.getByName(name);
        }

        return params;
    }

    public static String getCurveName(
        ASN1ObjectIdentifier oid)
    {
        String name = ECNamedCurveTable.getName(oid);

        return name;
    }

    /**
     * Describe a named curve for toString() in the "name (oid)" form SunEC's own named curves use, so
     * messages read the same whichever provider made the key. A name that is itself an OID is shown
     * once, after the table name when there is one, and a name with no known OID is shown as given.
     *
     * @param name the curve name, or an OID in dotted form.
     * @return the description, or null if name is null.
     */
    public static String namedCurveToString(String name)
    {
        if (name == null || name.length() == 0)
        {
            return name;
        }

        ASN1ObjectIdentifier oid = getNamedCurveOid(name);
        if (oid == null)
        {
            return name;
        }

        String id = oid.getId();
        if (!id.equals(name))
        {
            return name + " (" + id + ")";
        }

        String tableName = getCurveName(oid);

        return (tableName == null) ? id : tableName + " (" + id + ")";
    }

    /**
     * Describe EC domain parameters that carry no name for toString(), by field type and size, for
     * example "EC parameters (Fp, 256-bit field)".
     *
     * @param curve the curve, may be null.
     * @return the description.
     */
    public static String curveToString(ECCurve curve)
    {
        if (curve == null)
        {
            return "EC parameters";
        }

        return curveToString(ECAlgorithms.isFpCurve(curve), curve.getFieldSize());
    }

    static String curveToString(boolean isFp, int fieldSize)
    {
        return "EC parameters (" + (isFp ? "Fp" : "F2m") + ", " + fieldSize + "-bit field)";
    }

    public static String privateKeyToString(String algorithm, BigInteger d, org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();

        org.bouncycastle.math.ec.ECPoint q = new FixedPointCombMultiplier().multiply(spec.getG(), d).normalize();

        buf.append(algorithm);
        buf.append(" Private Key [").append(ECUtil.generateKeyFingerprint(q, spec)).append("]").append(nl);
        buf.append("            X: ").append(q.getAffineXCoord().toBigInteger().toString(16)).append(nl);
        buf.append("            Y: ").append(q.getAffineYCoord().toBigInteger().toString(16)).append(nl);

        return buf.toString();
    }

    public static String publicKeyToString(String algorithm, org.bouncycastle.math.ec.ECPoint q, org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(ECUtil.generateKeyFingerprint(q, spec)).append("]").append(nl);
        buf.append("            X: ").append(q.getAffineXCoord().toBigInteger().toString(16)).append(nl);
        buf.append("            Y: ").append(q.getAffineYCoord().toBigInteger().toString(16)).append(nl);

        return buf.toString();
    }

    public static String generateKeyFingerprint(ECPoint publicPoint, org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        ECCurve curve = spec.getCurve();
        ECPoint g = spec.getG();

        if (curve != null)
        {
            return new Fingerprint(Arrays.concatenate(publicPoint.getEncoded(false), curve.getA().getEncoded(), curve.getB().getEncoded(), g.getEncoded(false))).toString();
        }

        return new Fingerprint(publicPoint.getEncoded(false)).toString();
    }

    /**
     * Hash code for an EC private scalar derived from the public point and domain parameters.
     */
    public static int privateKeyHashCode(BigInteger d, org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        if (spec == null)
        {
            return 0;
        }

        return spec.getG().multiply(d).normalize().hashCode() ^ spec.hashCode();
    }
}
