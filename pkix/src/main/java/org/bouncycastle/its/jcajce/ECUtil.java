package org.bouncycastle.its.jcajce;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.Polynomial;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.bouncycastle.util.Arrays;

class ECUtil
{
    static ECPoint convertPoint(org.bouncycastle.math.ec.ECPoint point)
    {
        point = point.normalize();

        return new ECPoint(
            point.getAffineXCoord().toBigInteger(),
            point.getAffineYCoord().toBigInteger());
    }

    public static EllipticCurve convertCurve(
        ECCurve curve,
        byte[] seed)
    {
        ECField field = convertField(curve.getField());
        BigInteger a = curve.getA().toBigInteger(), b = curve.getB().toBigInteger();

        // TODO: the Sun EC implementation doesn't currently handle the seed properly
        // so at the moment it's set to null. Should probably look at making this configurable
        return new EllipticCurve(field, a, b, null);
    }

    public static ECParameterSpec convertToSpec(
        X9ECParameters domainParameters)
    {
        return new ECParameterSpec(
            convertCurve(domainParameters.getCurve(), null),  // JDK 1.5 has trouble with this if it's not null...
            convertPoint(domainParameters.getG()),
            domainParameters.getN(),
            domainParameters.getH().intValue());
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
            int[] ks = Arrays.reverseInPlace(Arrays.copyOfRange(exponents, 1, exponents.length - 1));
            return new ECFieldF2m(poly.getDegree(), ks);
        }
    }
}
