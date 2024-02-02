package org.bouncycastle.its.jcajce;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECField;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccCurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;

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
        return EC5Util.convertField(field);
    }

    static PublicKey getPublicKey(X9ECParameters params, ECCurve curve, EccCurvePoint itsPoint, JcaJceHelper helper)
    {
        byte[] key;

        if (itsPoint instanceof EccP256CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else if (itsPoint instanceof EccP384CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else
        {
            throw new IllegalStateException("unknown key type");
        }

        org.bouncycastle.math.ec.ECPoint point = curve.decodePoint(key).normalize();
        try
        {
            KeyFactory keyFactory = helper.createKeyFactory("EC");
            ECParameterSpec spec = convertToSpec(params);
            ECPoint jPoint = convertPoint(point);
            return keyFactory.generatePublic(new ECPublicKeySpec(jPoint, spec));
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }
}
