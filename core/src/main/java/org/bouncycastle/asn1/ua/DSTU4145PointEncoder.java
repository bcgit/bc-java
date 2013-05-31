package org.bouncycastle.asn1.ua;

import java.math.BigInteger;
import java.util.Random;

import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/**
 * DSTU4145 encodes points somewhat differently than X9.62
 * It compresses the point to the size of the field element
 */

public abstract class DSTU4145PointEncoder
{

    private static X9IntegerConverter converter = new X9IntegerConverter();

    private static BigInteger trace(ECFieldElement fe)
    {
        ECFieldElement t = fe;
        for (int i = 0; i < fe.getFieldSize() - 1; i++)
        {
            t = t.square().add(fe);
        }
        return t.toBigInteger();
    }

    /**
     * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
     * D.1.6) The other solution is <code>z + 1</code>.
     *
     * @param beta The value to solve the qradratic equation for.
     * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
     *         <code>null</code> if no solution exists.
     */
    private static ECFieldElement solveQuadradicEquation(ECFieldElement beta)
    {
        ECFieldElement.F2m b = (ECFieldElement.F2m)beta;
        ECFieldElement zeroElement = new ECFieldElement.F2m(
            b.getM(), b.getK1(), b.getK2(), b.getK3(), ECConstants.ZERO);

        if (beta.toBigInteger().equals(ECConstants.ZERO))
        {
            return zeroElement;
        }

        ECFieldElement z = null;
        ECFieldElement gamma = zeroElement;

        Random rand = new Random();
        int m = b.getM();
        do
        {
            ECFieldElement t = new ECFieldElement.F2m(b.getM(), b.getK1(),
                b.getK2(), b.getK3(), new BigInteger(m, rand));
            z = zeroElement;
            ECFieldElement w = beta;
            for (int i = 1; i <= m - 1; i++)
            {
                ECFieldElement w2 = w.square();
                z = z.square().add(w2.multiply(t));
                w = w2.add(beta);
            }
            if (!w.toBigInteger().equals(ECConstants.ZERO))
            {
                return null;
            }
            gamma = z.square().add(z);
        }
        while (gamma.toBigInteger().equals(ECConstants.ZERO));

        return z;
    }

    public static byte[] encodePoint(ECPoint Q)
    {
        /*if (!Q.isCompressed())
              Q=new ECPoint.F2m(Q.getCurve(),Q.getX(),Q.getY(),true);

          byte[] bytes=Q.getEncoded();

          if (bytes[0]==0x02)
              bytes[bytes.length-1]&=0xFE;
          else if (bytes[0]==0x02)
              bytes[bytes.length-1]|=0x01;

          return Arrays.copyOfRange(bytes, 1, bytes.length);*/

        int byteCount = converter.getByteLength(Q.getX());
        byte[] bytes = converter.integerToBytes(Q.getX().toBigInteger(), byteCount);

        if (!(Q.getX().toBigInteger().equals(ECConstants.ZERO)))
        {
            ECFieldElement y = Q.getY().multiply(Q.getX().invert());
            if (trace(y).equals(ECConstants.ONE))
            {
                bytes[bytes.length - 1] |= 0x01;
            }
            else
            {
                bytes[bytes.length - 1] &= 0xFE;
            }
        }

        return bytes;
    }

    public static ECPoint decodePoint(ECCurve curve, byte[] bytes)
    {
        /*byte[] bp_enc=new byte[bytes.length+1];
          if (0==(bytes[bytes.length-1]&0x1))
              bp_enc[0]=0x02;
          else
              bp_enc[0]=0x03;
          System.arraycopy(bytes, 0, bp_enc, 1, bytes.length);
          if (!trace(curve.fromBigInteger(new BigInteger(1, bytes))).equals(curve.getA().toBigInteger()))
              bp_enc[bp_enc.length-1]^=0x01;

          return curve.decodePoint(bp_enc);*/

        BigInteger k = BigInteger.valueOf(bytes[bytes.length - 1] & 0x1);
        if (!trace(curve.fromBigInteger(new BigInteger(1, bytes))).equals(curve.getA().toBigInteger()))
        {
            bytes = Arrays.clone(bytes);
            bytes[bytes.length - 1] ^= 0x01;
        }
        ECCurve.F2m c = (ECCurve.F2m)curve;
        ECFieldElement xp = curve.fromBigInteger(new BigInteger(1, bytes));
        ECFieldElement yp = null;
        if (xp.toBigInteger().equals(ECConstants.ZERO))
        {
            yp = (ECFieldElement.F2m)curve.getB();
            for (int i = 0; i < c.getM() - 1; i++)
            {
                yp = yp.square();
            }
        }
        else
        {
            ECFieldElement beta = xp.add(curve.getA()).add(
                curve.getB().multiply(xp.square().invert()));
            ECFieldElement z = solveQuadradicEquation(beta);
            if (z == null)
            {
                throw new RuntimeException("Invalid point compression");
            }
            if (!trace(z).equals(k))
            {
                z = z.add(curve.fromBigInteger(ECConstants.ONE));
            }
            yp = xp.multiply(z);
        }

        return new ECPoint.F2m(curve, xp, yp);
    }

}
