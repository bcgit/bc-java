package org.bouncycastle.crypto.kems;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.SAKKEPrivateKeyParameters;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import static org.bouncycastle.crypto.kems.SAKKEKEMSGenerator.pairing;

public class SAKKEKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final ECCurve curve;
    private final BigInteger p;
    private final BigInteger q;
    private final ECPoint P;
    private final ECPoint Z_S;
    private final ECPoint K_bS; // Receiver's RSK
    private final int n; // Security parameter
    private final SAKKEPrivateKeyParameters privateKey;

    public SAKKEKEMExtractor(SAKKEPrivateKeyParameters privateKey)
    {
        this.privateKey = privateKey;
        SAKKEPublicKeyParameters publicKey = privateKey.getPublicParams();
        this.curve = publicKey.getCurve();
        this.q = publicKey.getQ();
        this.P = publicKey.getP();
        this.p = publicKey.getp();
        this.Z_S = publicKey.getZ();
        this.K_bS = privateKey.getPrivatePoint();
        this.n = publicKey.getN();
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        try
        {
            // Step 1: Parse Encapsulated Data (R_bS, H)
            ECPoint R_bS = curve.decodePoint(Arrays.copyOfRange(encapsulation, 0, 257));
            BigInteger H = new BigInteger(Arrays.copyOfRange(encapsulation, 257, 274));

            // Step 2: Compute w = <R_bS, K_bS> using pairing
//            BigInteger w = computeTLPairing(new BigInteger[] {R_bS.getXCoord().toBigInteger(), R_bS.getYCoord().toBigInteger()},
//                new BigInteger[] {K_bS.getXCoord().toBigInteger(), K_bS.getYCoord().toBigInteger()}, this.p, this.q);
            BigInteger w = computePairing(R_bS, K_bS, p, q);

            // Step 3: Compute SSV = H XOR HashToIntegerRange(w, 2^n)
            BigInteger ssv = computeSSV(H, w);

            // Step 4: Compute r = HashToIntegerRange(SSV || b)
//            BigInteger r = computeR(ssv, privateKey.getPrivatePoint());
//
//            // Step 5: Validate R_bS
//            if (!validateR_bS(r, privateKey.getPrivatePoint(), R_bS)) {
//                throw new IllegalStateException("Validation of R_bS failed");
//            }

            return BigIntegers.asUnsignedByteArray(n / 8, ssv);
        }
        catch (Exception e)
        {
            throw new IllegalStateException("SAKKE extraction failed: " + e.getMessage());
        }
    }

    @Override
    public int getEncapsulationLength()
    {
        return 0;
    }

    private BigInteger computePairing(ECPoint R, ECPoint K)
    {
        // Use your existing pairing implementation
        return pairing(R, K, p, q);
    }

    private BigInteger computeSSV(BigInteger H, BigInteger w)
    {
        BigInteger twoToN = BigInteger.ONE.shiftLeft(n);
        BigInteger mask = SAKKEUtils.hashToIntegerRange(w.toByteArray(), twoToN);
        return H.xor(mask);
    }

    public static BigInteger computeTLPairing(
        BigInteger[] R,  // C = (Rx, Ry)
        BigInteger[] Q,  // Q = (Qx, Qy)
        BigInteger p,
        BigInteger q
    )
    {
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        int N = qMinus1.bitLength() - 1;

        // Initialize V = (1, 0)
        BigInteger[] V = {BigInteger.ONE, BigInteger.ZERO};
        // Initialize C = R
        BigInteger[] C = {R[0], R[1]};

        for (; N > 0; N--)
        {
            // V = V^2
            pointSquare(V, p);

            // Compute line function T
            BigInteger[] T = computeLineFunctionT(C, Q, p);

            // V = V * T
            pointMultiply(V, T, p);

            // C = 2*C (point doubling)
            pointDouble(C, p);

            if (qMinus1.testBit(N - 1))
            {
                // Compute addition line function
                BigInteger[] TAdd = computeLineFunctionAdd(C, R, Q, p);

                // V = V * TAdd
                pointMultiply(V, TAdd, p);

                // C = C + R (point addition)
                pointAdd(C, R, p);
            }
        }

        // Final squaring
        pointSquare(V, p);
        pointSquare(V, p);

        // Compute w = (Vy * Vx^{-1}) mod p
        BigInteger VxInv = V[0].modInverse(p);
        return V[1].multiply(VxInv).mod(p);
    }

    private static void pointSquare(BigInteger[] point, BigInteger p)
    {
        BigInteger x = point[0];
        BigInteger y = point[1];

        // x = (x + y)(x - y) mod p
        BigInteger xPlusY = x.add(y).mod(p);
        BigInteger xMinusY = x.subtract(y).mod(p);
        BigInteger newX = xPlusY.multiply(xMinusY).mod(p);

        // y = 2xy mod p
        BigInteger newY = x.multiply(y).multiply(BigInteger.valueOf(2)).mod(p);

        point[0] = newX;
        point[1] = newY;
    }

    private static void pointMultiply(BigInteger[] a, BigInteger[] b, BigInteger p)
    {
        // Complex multiplication (a + bi)*(c + di) = (ac - bd) + (ad + bc)i
        BigInteger real = a[0].multiply(b[0]).subtract(a[1].multiply(b[1])).mod(p);
        BigInteger imag = a[0].multiply(b[1]).add(a[1].multiply(b[0])).mod(p);

        a[0] = real;
        a[1] = imag;
    }

    private static void pointDouble(BigInteger[] point, BigInteger p)
    {
        // Elliptic curve point doubling formulas
        BigInteger x = point[0];
        BigInteger y = point[1];

        BigInteger slope = x.pow(2).multiply(BigInteger.valueOf(3))
            .mod(p)
            .multiply(y.multiply(BigInteger.valueOf(2)).modInverse(p))
            .mod(p);

        BigInteger newX = slope.pow(2).subtract(x.multiply(BigInteger.valueOf(2))).mod(p);
        BigInteger newY = slope.multiply(x.subtract(newX)).subtract(y).mod(p);

        point[0] = newX;
        point[1] = newY;
    }

    private static void pointAdd(BigInteger[] a, BigInteger[] b, BigInteger p)
    {
        // Elliptic curve point addition
        BigInteger x1 = a[0], y1 = a[1];
        BigInteger x2 = b[0], y2 = b[1];

        BigInteger slope = y2.subtract(y1)
            .multiply(x2.subtract(x1).modInverse(p))
            .mod(p);

        BigInteger newX = slope.pow(2).subtract(x1).subtract(x2).mod(p);
        BigInteger newY = slope.multiply(x1.subtract(newX)).subtract(y1).mod(p);

        a[0] = newX;
        a[1] = newY;
    }

    private static BigInteger[] computeLineFunctionT(
        BigInteger[] C,
        BigInteger[] Q,
        BigInteger p
    )
    {
        // Line function evaluation for doubling
        BigInteger Cx = C[0], Cy = C[1];
        BigInteger Qx = Q[0], Qy = Q[1];

        // l = (3Cx² + a)/(2Cy) but a=0 for many curves
        BigInteger numerator = Cx.pow(2).multiply(BigInteger.valueOf(3)).mod(p);
        BigInteger denominator = Cy.multiply(BigInteger.valueOf(2)).mod(p);
        BigInteger l = numerator.multiply(denominator.modInverse(p)).mod(p);

        // T = l*(Qx + Cx) - 2Qy
        BigInteger tReal = l.multiply(Qx.add(Cx).mod(p)).mod(p);
        BigInteger tImag = l.multiply(Qy).negate().mod(p);

        return new BigInteger[]{tReal, tImag};
    }

    private static BigInteger[] computeLineFunctionAdd(
        BigInteger[] C,
        BigInteger[] R,
        BigInteger[] Q,
        BigInteger p
    )
    {
        // Line function evaluation for addition
        BigInteger Cx = C[0], Cy = C[1];
        BigInteger Rx = R[0], Ry = R[1];
        BigInteger Qx = Q[0], Qy = Q[1];

        // l = (Cy - Ry)/(Cx - Rx)
        BigInteger numerator = Cy.subtract(Ry).mod(p);
        BigInteger denominator = Cx.subtract(Rx).mod(p);
        BigInteger l = numerator.multiply(denominator.modInverse(p)).mod(p);

        // T = l*(Qx + Cx) - Qy
        BigInteger tReal = l.multiply(Qx.add(Cx).mod(p)).mod(p);
        BigInteger tImag = l.multiply(Qy).negate().mod(p);

        return new BigInteger[]{tReal, tImag};
    }

    private boolean pointsEqual(ECPoint p1, ECPoint p2)
    {
        return p1.normalize().getXCoord().equals(p2.normalize().getXCoord())
            && p1.normalize().getYCoord().equals(p2.normalize().getYCoord());
    }

    public static BigInteger computePairing(ECPoint R, ECPoint Q, BigInteger p, BigInteger q)
    {
        BigInteger c = p.add(BigInteger.ONE).divide(q);  // Compute c = (p+1)/q
        BigInteger[] v = new BigInteger[]{BigInteger.ONE, BigInteger.ZERO};  // v = (1,0) in F_p^2
        ECPoint C = R;

        BigInteger qMinusOne = q.subtract(BigInteger.ONE);
        int numBits = qMinusOne.bitLength();

        // Miller loop
        for (int i = numBits - 2; i >= 0; i--)
        {
            v = fp2SquareAndAccumulate(v, C, Q, p);
            C = C.twice().normalize();  // C = [2]C

            if (qMinusOne.testBit(i))
            {
                v = fp2MultiplyAndAccumulate(v, C, R, Q, p);
                C = C.add(R).normalize();
            }
        }

        // Final exponentiation: t = v^c
        return fp2FinalExponentiation(v, p, c);
    }

    private static BigInteger[] fp2SquareAndAccumulate(BigInteger[] v, ECPoint C, ECPoint Q, BigInteger p)
    {
        BigInteger Cx = C.getAffineXCoord().toBigInteger();
        BigInteger Cy = C.getAffineYCoord().toBigInteger();
        BigInteger Qx = Q.getAffineXCoord().toBigInteger();
        BigInteger Qy = Q.getAffineYCoord().toBigInteger();

        // Compute l = (3 * (Cx^2 - 1)) / (2 * Cy) mod p
        BigInteger l = Cx.multiply(Cx).mod(p).subtract(BigInteger.ONE).multiply(BigInteger.valueOf(3)).mod(p)
            .multiply(Cy.multiply(BigInteger.valueOf(2)).modInverse(p))
            .mod(p);

        // Compute v = v^2 * ( l*( Q_x + C_x ) + ( i*Q_y - C_y ) )
        v = fp2Multiply(v[0], v[1], v[0], v[1], p);
        return fp2Multiply(v[0], v[1], l.multiply(Qx.add(Cx)), (Qy.subtract(Cy)), p);
    }

    private static BigInteger[] fp2MultiplyAndAccumulate(BigInteger[] v, ECPoint C, ECPoint R, ECPoint Q, BigInteger p)
    {
        BigInteger Cx = C.getAffineXCoord().toBigInteger();
        BigInteger Cy = C.getAffineYCoord().toBigInteger();
        BigInteger Rx = R.getAffineXCoord().toBigInteger();
        BigInteger Ry = R.getAffineYCoord().toBigInteger();
        BigInteger Qx = Q.getAffineXCoord().toBigInteger();
        BigInteger Qy = Q.getAffineYCoord().toBigInteger();

        // Compute l = (Cy - Ry) / (Cx - Rx) mod p
        BigInteger l = Cy.subtract(Ry)
            .multiply(Cx.subtract(Rx).modInverse(p))
            .mod(p);

        // Compute v = v * ( l*( Q_x + C_x ) + ( i*Q_y - C_y ) )
        return fp2Multiply(v[0], v[1], l.multiply(Qx.add(Cx)), Qy.subtract(Cy), p);
    }


    private static BigInteger[] fp2Multiply(BigInteger x_real, BigInteger x_imag, BigInteger y_real, BigInteger y_imag, BigInteger p)
    {
        // Multiply v = (a + i*b) * scalar
        return new BigInteger[]{
            x_real.multiply(y_real).subtract(x_imag.multiply(y_imag)).mod(p),
            x_real.multiply(y_imag).add(x_imag.multiply(y_real)).mod(p)
        };
    }

    private static BigInteger fp2FinalExponentiation(BigInteger[] v, BigInteger p, BigInteger c)
    {
        // Compute representative in F_p: return b/a (mod p)
//        BigInteger v0 = v[0].modPow(c, p);
//        BigInteger v1 = v[1].modPow(c, p);
//        return v1.multiply(v0.modInverse(p)).mod(p);
        v = fp2Multiply(v[0], v[1], v[0], v[1], p);
        v = fp2Multiply(v[0], v[1], v[0], v[1], p);
        return v[1].multiply(v[0].modInverse(p)).mod(p);
    }
}
