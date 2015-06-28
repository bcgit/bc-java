package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.Polynomial;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.bouncycastle.util.Arrays;

public class EC5Util
{
    private static Map customCurves = new HashMap();

    static
    {
        Enumeration e = CustomNamedCurves.getNames();
        while (e.hasMoreElements())
        {
            String name = (String)e.nextElement();

            X9ECParameters curveParams = ECNamedCurveTable.getByName(name);
            if (curveParams != null)  // there may not be a regular curve, may just be a custom curve.
            {
                customCurves.put(curveParams.getCurve(), CustomNamedCurves.getByName(name).getCurve());
            }
        }
    }

    public static ECCurve getCurve(
        ProviderConfiguration configuration,
        X962Parameters params)
    {
        ECCurve curve;

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
            X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);

            curve = ecP.getCurve();
        }
        else if (params.isImplicitlyCA())
        {
            curve = configuration.getEcImplicitlyCa().getCurve();
        }
        else
        {
            X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());

            curve = ecP.getCurve();
        }

        return curve;
    }

    public static ECParameterSpec convertToSpec(
        X962Parameters params, ECCurve curve)
    {
        ECParameterSpec ecSpec;
        EllipticCurve ellipticCurve;

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();
            X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);

            ellipticCurve = EC5Util.convertCurve(curve, ecP.getSeed());

            ecSpec = new ECNamedCurveSpec(
                ECUtil.getCurveName(oid),
                ellipticCurve,
                new ECPoint(
                    ecP.getG().getAffineXCoord().toBigInteger(),
                    ecP.getG().getAffineYCoord().toBigInteger()),
                ecP.getN(),
                ecP.getH());
        }
        else if (params.isImplicitlyCA())
        {
            ecSpec = null;
        }
        else
        {
            X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());

            ellipticCurve = EC5Util.convertCurve(curve, ecP.getSeed());

            if (ecP.getH() != null)
            {
                ecSpec = new ECParameterSpec(
                    ellipticCurve,
                    new ECPoint(
                        ecP.getG().getAffineXCoord().toBigInteger(),
                        ecP.getG().getAffineYCoord().toBigInteger()),
                    ecP.getN(),
                    ecP.getH().intValue());
            }
            else
            {
                ecSpec = new ECParameterSpec(
                    ellipticCurve,
                    new ECPoint(
                        ecP.getG().getAffineXCoord().toBigInteger(),
                        ecP.getG().getAffineYCoord().toBigInteger()),
                    ecP.getN(), 1);      // TODO: not strictly correct... need to fix the test data...
            }
        }

        return ecSpec;
    }

    public static ECParameterSpec convertToSpec(
        X9ECParameters domainParameters)
    {
        return new ECParameterSpec(
            convertCurve(domainParameters.getCurve(), null),  // JDK 1.5 has trouble with this if it's not null...
            new ECPoint(
                domainParameters.getG().getAffineXCoord().toBigInteger(),
                domainParameters.getG().getAffineYCoord().toBigInteger()),
            domainParameters.getN(),
            domainParameters.getH().intValue());
    }

    public static EllipticCurve convertCurve(
        ECCurve curve, 
        byte[]  seed)
    {
        ECField field = convertField(curve.getField());
        BigInteger a = curve.getA().toBigInteger(), b = curve.getB().toBigInteger();

        // TODO: the Sun EC implementation doesn't currently handle the seed properly
        // so at the moment it's set to null. Should probably look at making this configurable
        return new EllipticCurve(field, a, b, null);
    }

    public static ECCurve convertCurve(
        EllipticCurve ec)
    {
        ECField field = ec.getField();
        BigInteger a = ec.getA();
        BigInteger b = ec.getB();

        if (field instanceof ECFieldFp)
        {
            ECCurve.Fp curve = new ECCurve.Fp(((ECFieldFp)field).getP(), a, b);

            if (customCurves.containsKey(curve))
            {
                return (ECCurve)customCurves.get(curve);
            }

            return curve;
        }
        else
        {
            ECFieldF2m fieldF2m = (ECFieldF2m)field;
            int m = fieldF2m.getM();
            int ks[] = ECUtil.convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
            return new ECCurve.F2m(m, ks[0], ks[1], ks[2], a, b); 
        }
    }

    public static ECField convertField(FiniteField field)
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

    public static ECParameterSpec convertSpec(
        EllipticCurve ellipticCurve,
        org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        if (spec instanceof ECNamedCurveParameterSpec)
        {
            return new ECNamedCurveSpec(
                ((ECNamedCurveParameterSpec)spec).getName(),
                ellipticCurve,
                new ECPoint(
                    spec.getG().getAffineXCoord().toBigInteger(),
                    spec.getG().getAffineYCoord().toBigInteger()),
                spec.getN(),
                spec.getH());
        }
        else
        {
            return new ECParameterSpec(
                ellipticCurve,
                new ECPoint(
                    spec.getG().getAffineXCoord().toBigInteger(),
                    spec.getG().getAffineYCoord().toBigInteger()),
                spec.getN(),
                spec.getH().intValue());
        }
    }

    public static org.bouncycastle.jce.spec.ECParameterSpec convertSpec(
        ECParameterSpec ecSpec,
        boolean withCompression)
    {
        ECCurve curve = convertCurve(ecSpec.getCurve());

        return new org.bouncycastle.jce.spec.ECParameterSpec(
            curve,
            convertPoint(curve, ecSpec.getGenerator(), withCompression),
            ecSpec.getOrder(),
            BigInteger.valueOf(ecSpec.getCofactor()),
            ecSpec.getCurve().getSeed());
    }

    public static org.bouncycastle.math.ec.ECPoint convertPoint(
        ECParameterSpec ecSpec,
        ECPoint point,
        boolean withCompression)
    {
        return convertPoint(convertCurve(ecSpec.getCurve()), point, withCompression);
    }

    public static org.bouncycastle.math.ec.ECPoint convertPoint(
        ECCurve curve,
        ECPoint point,
        boolean withCompression)
    {
        return curve.createPoint(point.getAffineX(), point.getAffineY());
    }
}
