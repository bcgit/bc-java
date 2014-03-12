package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.GLVMultiplier;
import org.bouncycastle.math.ec.endo.GLVTypeBEndomorphism;
import org.bouncycastle.math.ec.endo.GLVTypeBParameters;
import org.bouncycastle.math.field.FiniteFields;
import org.bouncycastle.util.encoders.Hex;

public class SecP256K1Curve extends ECCurve
{
    public static final BigInteger q = new BigInteger(1,
        Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));

    private static final int SECP256K1_DEFAULT_COORDS = COORD_JACOBIAN;

    protected SecP256K1Point infinity;

    public SecP256K1Curve()
    {
        super(FiniteFields.getPrimeField(q));

        this.infinity = new SecP256K1Point(this, null, null);

        this.a = fromBigInteger(ECConstants.ZERO);
        this.b = fromBigInteger(BigInteger.valueOf(7));
        this.order = new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));
        this.cofactor = BigInteger.valueOf(1);
        this.coord = SECP256K1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP256K1Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_JACOBIAN:
            return true;
        default:
            return false;
        }
    }

    protected ECMultiplier createDefaultMultiplier()
    {
        GLVTypeBParameters p = new GLVTypeBParameters(
            fromBigInteger(new BigInteger("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee", 16)),
            new BigInteger("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72", 16),
            new BigInteger[]{
                new BigInteger("3086d221a7d46bcde86c90e49284eb15", 16),
                new BigInteger("-e4437ed6010e88286f547fa90abfe4c3", 16) },
            new BigInteger[]{
                new BigInteger("114ca50f7a8e2f3f657c1108d9d44cfd8", 16),
                new BigInteger("3086d221a7d46bcde86c90e49284eb15", 16) },
            new BigInteger("c21b48869f51af37a1b243924a13ac55", 16),
            new BigInteger("3910dfb58043a20a1bd51fea42aff9311", 16),
            258);
        return new GLVMultiplier(this, new GLVTypeBEndomorphism(p));
    }

    public BigInteger getQ()
    {
        return q;
    }

    public int getFieldSize()
    {
        return q.bitLength();
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecP256K1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecP256K1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecP256K1Point(this, x, y, zs, withCompression);
    }

    protected ECPoint decompressPoint(int yTilde, BigInteger X1)
    {
        ECFieldElement x = fromBigInteger(X1);
        ECFieldElement alpha = x.square().multiply(x).add(getB());
        ECFieldElement beta = alpha.sqrt();

        //
        // if we can't find a sqrt we haven't got a point on the
        // curve - run!
        //
        if (beta == null)
        {
            throw new RuntimeException("Invalid point compression");
        }

        if (beta.testBitZero() != (yTilde == 1))
        {
            // Use the other root
            beta = beta.negate();
        }

        return new SecP256K1Point(this, x, beta, true);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }
}
