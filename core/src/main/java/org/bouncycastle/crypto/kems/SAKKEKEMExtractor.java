package org.bouncycastle.crypto.kems;

import java.math.BigInteger;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.params.SAKKEPrivateKeyParameters;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;


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
            BigInteger w = computePairing(R_bS, K_bS, p, q);
            System.out.println(new String(Hex.encode(w.toByteArray())));
            //BigInteger w = tatePairing(R_bS.getXCoord().toBigInteger(), R_bS.getYCoord().toBigInteger(), K_bS.getXCoord().toBigInteger(), K_bS.getYCoord().toBigInteger(), q, p);
            // Step 3: Compute SSV = H XOR HashToIntegerRange(w, 2^n)
            BigInteger twoToN = BigInteger.ONE.shiftLeft(n);
            BigInteger mask = SAKKEUtils.hashToIntegerRange(w.toByteArray(), twoToN);
            BigInteger ssv = H.xor(mask);

            // Step 4: Compute r = HashToIntegerRange(SSV || b)
            BigInteger b = privateKey.getB();
            BigInteger r = SAKKEUtils.hashToIntegerRange(Arrays.concatenate(ssv.toByteArray(), b.toByteArray()), q);

            // Step 5: Validate R_bS
            ECPoint bP = P.multiply(b).normalize();
            ECPoint Test = bP.add(Z_S).multiply(r).normalize();
            if (!R_bS.equals(Test))
            {
                throw new IllegalStateException("Validation of R_bS failed");
            }

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


    public static BigInteger computePairing(ECPoint R, ECPoint Q, BigInteger p, BigInteger q)
    {
        // v = (1,0) in F_p^2
        BigInteger[] v = new BigInteger[]{BigInteger.ONE, BigInteger.ZERO};
        ECPoint C = R;

        BigInteger qMinusOne = q.subtract(BigInteger.ONE);
        int numBits = qMinusOne.bitLength();
        BigInteger Qx = Q.getAffineXCoord().toBigInteger();
        BigInteger Qy = Q.getAffineYCoord().toBigInteger();
        BigInteger Rx = R.getAffineXCoord().toBigInteger();
        BigInteger Ry = R.getAffineYCoord().toBigInteger();
        BigInteger l, Cx, Cy;
        final BigInteger three = BigInteger.valueOf(3);
        final BigInteger two = BigInteger.valueOf(2);

        // Miller loop
        for (int i = numBits - 2; i >= 0; i--)
        {
            Cx = C.getAffineXCoord().toBigInteger();
            Cy = C.getAffineYCoord().toBigInteger();

            // Compute l = (3 * (Cx^2 - 1)) / (2 * Cy) mod p
            l = three.multiply(Cx.multiply(Cx).subtract(BigInteger.ONE))
                .multiply(Cy.multiply(two).modInverse(p)).mod(p);

            // Compute v = v^2 * ( l*( Q_x + C_x ) + ( i*Q_y - C_y ) )
            v = fp2PointSquare(v[0], v[1], p);
            v = fp2Multiply(v[0], v[1], l.multiply(Qx.add(Cx)).subtract(Cy), Qy, p);

            C = C.twice().normalize();  // C = [2]C

            if (qMinusOne.testBit(i))
            {
                Cx = C.getAffineXCoord().toBigInteger();
                Cy = C.getAffineYCoord().toBigInteger();

                // Compute l = (Cy - Ry) / (Cx - Rx) mod p
                l = Cy.subtract(Ry).multiply(Cx.subtract(Rx).modInverse(p)).mod(p);

                // Compute v = v * ( l*( Q_x + C_x ) + ( i*Q_y - C_y ) )
                v = fp2Multiply(v[0], v[1], l.multiply(Qx.add(Cx)).subtract(Cy), Qy, p);

                C = C.add(R).normalize();
            }
        }

        // Final exponentiation: t = v^c
        v = fp2PointSquare(v[0], v[1], p);
        v = fp2PointSquare(v[0], v[1], p);
        return v[1].multiply(v[0].modInverse(p)).mod(p);
    }

    static BigInteger[] fp2Multiply(BigInteger x_real, BigInteger x_imag, BigInteger y_real, BigInteger y_imag, BigInteger p)
    {
        return new BigInteger[]{
            x_real.multiply(y_real).subtract(x_imag.multiply(y_imag)).mod(p),
            x_real.multiply(y_imag).add(x_imag.multiply(y_real)).mod(p)
        };
    }

    static BigInteger[] fp2PointSquare(BigInteger currentX, BigInteger currentY, BigInteger p)
    {
        BigInteger xPlusY = currentX.add(currentY).mod(p);
        BigInteger xMinusY = currentX.subtract(currentY).mod(p);
        BigInteger newX = xPlusY.multiply(xMinusY).mod(p);

        // Compute newY = 2xy mod p
        BigInteger newY = currentX.multiply(currentY).multiply(BigInteger.valueOf(2)).mod(p);
        return new BigInteger[]{newX, newY};
    }
}
