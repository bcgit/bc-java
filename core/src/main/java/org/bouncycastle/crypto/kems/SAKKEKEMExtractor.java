package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.SAKKEPrivateKeyParameters;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

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

            //ECCurveWithTatePairing pairing = new ECCurveWithTatePairing(q, BigInteger.ONE, BigInteger.ZERO, p);
            //BigInteger w = pairing.TatePairing(R_bS, K_bS).toBigInteger();
            // Step 2: Compute w = <R_bS, K_bS> using pairing
//            BigInteger w = computeTLPairing(new BigInteger[] {R_bS.getXCoord().toBigInteger(), R_bS.getYCoord().toBigInteger()},
//                new BigInteger[] {K_bS.getXCoord().toBigInteger(), K_bS.getYCoord().toBigInteger()}, this.p, this.q);
            BigInteger w = computePairing(R_bS, K_bS, p, q);
            System.out.println(new String(Hex.encode(w.toByteArray())));
            //BigInteger w = tatePairing(R_bS.getXCoord().toBigInteger(), R_bS.getYCoord().toBigInteger(), K_bS.getXCoord().toBigInteger(), K_bS.getYCoord().toBigInteger(), q, p);
            // Step 3: Compute SSV = H XOR HashToIntegerRange(w, 2^n)
            BigInteger ssv = computeSSV(H, w);

            // Step 4: Compute r = HashToIntegerRange(SSV || b)
            BigInteger b = privateKey.getB();
            BigInteger r = SAKKEUtils.hashToIntegerRange(Arrays.concatenate(ssv.toByteArray(), b.toByteArray()), q);
//
//            // Step 5: Validate R_bS
            ECPoint bP = P.multiply(b).normalize();
            ECPoint Test = bP.add(Z_S).multiply(r).normalize();
            if(!R_bS.equals(Test))
            {
                throw new IllegalStateException("Validation of R_bS failed");
            }
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


    private BigInteger computeSSV(BigInteger H, BigInteger w)
    {
        BigInteger twoToN = BigInteger.ONE.shiftLeft(n);
        BigInteger mask = SAKKEUtils.hashToIntegerRange(w.toByteArray(), twoToN);
        return H.xor(mask);
    }

    public static BigInteger computePairing(ECPoint R, ECPoint Q, BigInteger p, BigInteger q)
    {
        BigInteger c = p.add(BigInteger.ONE).divide(q);  // Compute c = (p+1)/q
        BigInteger[] v = new BigInteger[]{BigInteger.ONE, BigInteger.ZERO};  // v = (1,0) in F_p^2
        //BigInteger v = BigInteger.ONE;
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
        BigInteger l = BigInteger.valueOf(3).multiply(Cx.multiply(Cx).subtract(BigInteger.ONE))
            .multiply(Cy.multiply(BigInteger.valueOf(2)).modInverse(p)).mod(p);

        // Compute v = v^2 * ( l*( Q_x + C_x ) + ( i*Q_y - C_y ) )
        v = fp2Multiply(v[0], v[1], v[0], v[1], p);
//        v[0] = v[0].multiply(v[0]);
//        v[1] = v[1].multiply(v[1]);
        return accumulateLine(v[0], v[1], Cx, Cy, Qx, Qy, l, p);
//        BigInteger t_x1_bn = Cx.multiply(Cx).subtract(BigInteger.ONE).multiply(BigInteger.valueOf(3)).multiply(Qx.add(Cx)).mod(p)
//            .subtract(Cy.multiply(Cy).multiply(BigInteger.valueOf(2))).mod(p);
//        BigInteger t_x2_bn =  Cy.multiply(Qy).multiply(BigInteger.valueOf(2)).mod(p);
//        v = fp2Multiply(v[0], v[1], v[0], v[1], p);
//        return fp2Multiply(v[0], v[1], t_x1_bn, t_x2_bn, p);
    }

    private static BigInteger[] accumulateLine(BigInteger v0, BigInteger v1, BigInteger Cx, BigInteger Cy, BigInteger Qx, BigInteger Qy, BigInteger l, BigInteger p)
    {
        return fp2Multiply(v0, v1, l.multiply(Qx.add(Cx)).subtract(Cy), Qy, p);
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
        return accumulateLine(v[0], v[1], Cx, Cy, Qx, Qy, l, p);
//        BigInteger t_x1_bn = Qx.add(Rx).multiply(Cy).subtract(Qx.add(Cx).multiply(Ry)).mod(p);
//        BigInteger t_x2_bn =  Cx.subtract(Rx).multiply(Qy).mod(p);
//        return fp2Multiply(v[0], v[1], t_x1_bn, t_x2_bn, p);

    }


    static BigInteger[] fp2Multiply(BigInteger x_real, BigInteger x_imag, BigInteger y_real, BigInteger y_imag, BigInteger p)
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
