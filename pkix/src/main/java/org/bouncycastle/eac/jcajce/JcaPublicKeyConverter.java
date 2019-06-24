package org.bouncycastle.eac.jcajce;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.asn1.eac.RSAPublicKey;
import org.bouncycastle.eac.EACException;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.Polynomial;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.bouncycastle.util.Arrays;

public class JcaPublicKeyConverter
{
    private EACHelper helper = new DefaultEACHelper();

    public JcaPublicKeyConverter setProvider(String providerName)
    {
        this.helper = new NamedEACHelper(providerName);

        return this;
    }

    public JcaPublicKeyConverter setProvider(Provider provider)
    {
        this.helper = new ProviderEACHelper(provider);

        return this;
    }

    public PublicKey getKey(PublicKeyDataObject publicKeyDataObject)
        throws EACException, InvalidKeySpecException
    {
        if (publicKeyDataObject.getUsage().on(EACObjectIdentifiers.id_TA_ECDSA))
        {
            return getECPublicKeyPublicKey((ECDSAPublicKey)publicKeyDataObject);
        }
        else
        {
            RSAPublicKey pubKey = (RSAPublicKey)publicKeyDataObject;
            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(pubKey.getModulus(), pubKey.getPublicExponent());

            try
            {
                KeyFactory factk = helper.createKeyFactory("RSA");

                return factk.generatePublic(pubKeySpec);
            }
            catch (NoSuchProviderException e)
            {
                throw new EACException("cannot find provider: " + e.getMessage(), e);
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new EACException("cannot find algorithm ECDSA: " + e.getMessage(), e);
            }
        }
    }

    private PublicKey getECPublicKeyPublicKey(ECDSAPublicKey key)
        throws EACException, InvalidKeySpecException
    {
        ECParameterSpec spec = getParams(key);
        java.security.spec.ECPoint publicPoint = getPublicPoint(key);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(publicPoint, spec);

        KeyFactory factk;
        try
        {
            factk = helper.createKeyFactory("ECDSA");
        }
        catch (NoSuchProviderException e)
        {
            throw new EACException("cannot find provider: " + e.getMessage(), e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new EACException("cannot find algorithm ECDSA: " + e.getMessage(), e);
        }

        return factk.generatePublic(pubKeySpec);
    }

    private java.security.spec.ECPoint getPublicPoint(ECDSAPublicKey key)
    {
        if (!key.hasParameters())
        {
            throw new IllegalArgumentException("Public key does not contains EC Params");
        }

        BigInteger p = key.getPrimeModulusP();
        ECCurve.Fp curve = new ECCurve.Fp(p, key.getFirstCoefA(), key.getSecondCoefB(), key.getOrderOfBasePointR(), key.getCofactorF());

        ECPoint.Fp pubY = (ECPoint.Fp)curve.decodePoint(key.getPublicPointY());

        return new java.security.spec.ECPoint(pubY.getAffineXCoord().toBigInteger(), pubY.getAffineYCoord().toBigInteger());
    }

    private ECParameterSpec getParams(ECDSAPublicKey key)
    {
        if (!key.hasParameters())
        {
            throw new IllegalArgumentException("Public key does not contains EC Params");
        }

        BigInteger p = key.getPrimeModulusP();
        ECCurve.Fp curve = new ECCurve.Fp(p, key.getFirstCoefA(), key.getSecondCoefB(), key.getOrderOfBasePointR(), key.getCofactorF());

        ECPoint G = curve.decodePoint(key.getBasePointG());

        BigInteger order = key.getOrderOfBasePointR();
        BigInteger coFactor = key.getCofactorF();

        EllipticCurve jcaCurve = convertCurve(curve);

        return new ECParameterSpec(jcaCurve, new java.security.spec.ECPoint(G.getAffineXCoord().toBigInteger(), G.getAffineYCoord().toBigInteger()), order, coFactor.intValue());
    }

    public PublicKeyDataObject getPublicKeyDataObject(ASN1ObjectIdentifier usage, PublicKey publicKey)
    {
        if (publicKey instanceof java.security.interfaces.RSAPublicKey)
        {
            java.security.interfaces.RSAPublicKey pubKey = (java.security.interfaces.RSAPublicKey)publicKey;

            return new RSAPublicKey(usage, pubKey.getModulus(), pubKey.getPublicExponent());
        }
        else
        {
            ECPublicKey pubKey = (ECPublicKey)publicKey;
            java.security.spec.ECParameterSpec params = pubKey.getParams();

            EllipticCurve c1 = params.getCurve();
            ECCurve c2 = convertCurve(c1, params.getOrder(), params.getCofactor());

            ECPoint basePoint = convertPoint(c2, params.getGenerator());
            ECPoint publicPoint = convertPoint(c2, pubKey.getW());

            return new ECDSAPublicKey(usage, ((ECFieldFp)c1.getField()).getP(), c1.getA(), c1.getB(),
                basePoint.getEncoded(false), params.getOrder(), publicPoint.getEncoded(false), params.getCofactor());
        }
    }

    private static org.bouncycastle.math.ec.ECPoint convertPoint(
        ECCurve curve,
        java.security.spec.ECPoint point)
    {
        return curve.createPoint(point.getAffineX(), point.getAffineY());
    }

    private static ECCurve convertCurve(
        EllipticCurve ec, BigInteger order, int coFactor)
    {
        ECField field = ec.getField();
        BigInteger a = ec.getA();
        BigInteger b = ec.getB();

        if (field instanceof ECFieldFp)
        {
            return new ECCurve.Fp(((ECFieldFp)field).getP(), a, b, order, BigInteger.valueOf(coFactor));
        }
        else
        {
            throw new IllegalStateException("not implemented yet!!!");
        }
    }

    private static EllipticCurve convertCurve(
        ECCurve curve)
    {
        ECField field = convertField(curve.getField());
        BigInteger a = curve.getA().toBigInteger(), b = curve.getB().toBigInteger();

        // TODO: the Sun EC implementation doesn't currently handle the seed properly
        // so at the moment it's set to null. Should probably look at making this configurable
        return new EllipticCurve(field, a, b, null);
    }

    private static ECField convertField(FiniteField field)
    {
        if (ECAlgorithms.isFpField(field))
        {
            return new ECFieldFp(field.getCharacteristic());
        }
        else //if (ECAlgorithms.isF2mField(curveField))
        {
            Polynomial poly = ((PolynomialExtensionField)field).getMinimalPolynomial();
            int[] exponents = poly.getExponentsPresent();
            int[] ks = Arrays.reverse(Arrays.copyOfRange(exponents, 1, exponents.length - 1));
            return new ECFieldF2m(poly.getDegree(), ks);
        }
    }
}
