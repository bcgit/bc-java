package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
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
            domainParameters = new ECNamedDomainParameters(oid, ecP);
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
            ECParameterSpec s = EC5Util.convertSpec(pubKey.getParams());
            return new ECPublicKeyParameters(
                EC5Util.convertPoint(pubKey.getParams(), pubKey.getW()),
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

            if (k.getParameters() instanceof ECNamedCurveParameterSpec)
            {
                String name = ((ECNamedCurveParameterSpec)k.getParameters()).getName();
                return new ECPrivateKeyParameters(
                    k.getD(),
                    new ECNamedDomainParameters(ECNamedCurveTable.getOID(name),
                        s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
            }
            else
            {
                return new ECPrivateKeyParameters(
                    k.getD(),
                    new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
            }
        }
        else if (key instanceof java.security.interfaces.ECPrivateKey)
        {
            java.security.interfaces.ECPrivateKey privKey = (java.security.interfaces.ECPrivateKey)key;
            try
            {
                ECParameterSpec s = EC5Util.convertSpec(privKey.getParams());
                return new ECPrivateKeyParameters(
                                privKey.getS(),
                                new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
            }
            catch (RuntimeException e)
            {
                throw SecurityExceptions.invalidKeyException(
                    "cannot recognise EC private key - its parameters are not accessible (a hardware-backed key?): " + e.getMessage(), e);
            }
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
            if (configuration == null)
            {
                return privateValue.bitLength();   // a guess but better than an exception!
            }

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
        if (null == curveName)
        {
            return null;
        }

        curveName = curveName.trim();

        if (curveName.length() == 0)
        {
            return null;
        }

        int spacePos = curveName.indexOf(' ');
        if (spacePos > 0)
        {
            curveName = curveName.substring(spacePos + 1);
        }

        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.tryFromID(curveName);
        if (null != oid)
        {
            return oid;
        }

        return ECNamedCurveTable.getOID(curveName);
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

    /**
     * Return the {@code subjectPublicKey} bytes of a SubjectPublicKeyInfo with an EC point
     * normalised to its uncompressed encoding, and the bytes of any other key type unchanged.
     * <p>
     * The composite drafts (draft-ietf-lamps-pq-composite-sigs / -kem sec. 4) require an EC
     * component to be carried as an uncompressed point, so a component key that would encode itself
     * compressed - a BC EC key whose point format has been set through
     * {@link org.bouncycastle.jce.interfaces.ECPointEncoder}, or a key from a provider that
     * preserves a compressed encoding - has to be normalised on the way out rather than passed
     * through as it came. This is a write-side normalisation only: a compressed component is still
     * accepted on decode, as the component key factories decode either form.
     *
     * @param spki the key to take the component bytes from.
     * @param configuration provider configuration, consulted only for implicitlyCA and additional
     *                      curve parameters.
     * @return the component key bytes, uncompressed if they are an EC point.
     */
    public static byte[] getUncompressedSubjectPublicKeyBytes(SubjectPublicKeyInfo spki, ProviderConfiguration configuration)
    {
        byte[] keyBytes = spki.getPublicKeyData().getOctets();

        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(spki.getAlgorithm().getAlgorithm()))
        {
            return keyBytes;
        }

        X962Parameters params = X962Parameters.getInstance(spki.getAlgorithm().getParameters());
        ECDomainParameters domainParameters = getDomainParameters(configuration, params);

        return domainParameters.getCurve().decodePoint(keyBytes).normalize().getEncoded(false);
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
        X9ECParameters params = CustomNamedCurves.getByName(curveName);

        if (params == null)
        {
            params = ECNamedCurveTable.getByName(curveName);
        }

        return params;
    }

    public static String getCurveName(
        ASN1ObjectIdentifier oid)
    {
        return ECNamedCurveTable.getName(oid);
    }

    public static String privateKeyToString(String algorithm, BigInteger d, org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        StringBuilder buf = new StringBuilder();
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
        StringBuilder buf = new StringBuilder();
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

    public static String getNameFrom(final AlgorithmParameterSpec paramSpec)
    {
        return SpecUtil.getNameFrom(paramSpec);
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

        // d is the private scalar, so use the cache-safe fixed-point comb, not the
        // curve's default wNAF multiplier
        return new FixedPointCombMultiplier().multiply(spec.getG(), d).normalize().hashCode() ^ spec.hashCode();
    }
}
