package org.bouncycastle.crypto.kems;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.params.SAKKEPrivateKeyParameters;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Implements the receiver side of the SAKKE (Sakai-Kasahara Key Encryption) protocol
 * as defined in RFC 6508. This class extracts the shared secret value (SSV) from
 * encapsulated data using the receiver's private key.
 * <p>
 * The extraction process follows these steps (RFC 6508, Section 6.2.2):
 * <ol>
 *   <li>Parse encapsulated data into R_(b,S) and H</li>
 *   <li>Compute pairing result w = &lt;R_(b,S), K_(b,S)&gt;</li>
 *   <li>Recover SSV via SSV = H XOR HashToIntegerRange(w, 2^n)</li>
 *   <li>Validate R_(b,S) by recomputing it with derived parameters</li>
 * </ol>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6508">Sakai-Kasahara Key Encryption (SAKKE)</a>
 */
public class SAKKEKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final ECCurve curve;
    private final BigInteger p;
    private final BigInteger q;
    private final ECPoint P;
    private final ECPoint Z_S;
    private final ECPoint K_bs;
    private final int n; // Security parameter
    private final BigInteger identifier;
    private final Digest digest;

    /**
     * Initializes the extractor with cryptographic parameters from the receiver's private key.
     *
     * @param privateKey The receiver's private key containing public parameters
     *                   (curve, prime, generator, etc.) and the Receiver Secret Key (RSK).
     *                   Must not be {@code null}.
     */
    public SAKKEKEMExtractor(SAKKEPrivateKeyParameters privateKey)
    {
        SAKKEPublicKeyParameters publicKey = privateKey.getPublicParams();
        this.curve = publicKey.getCurve();
        this.q = publicKey.getQ();
        this.P = publicKey.getPoint();
        this.p = publicKey.getPrime();
        this.Z_S = publicKey.getZ();
        this.identifier = publicKey.getIdentifier();
        this.K_bs = P.multiply(this.identifier.add(privateKey.getMasterSecret()).modInverse(q)).normalize();
        this.n = publicKey.getN();

        this.digest = publicKey.getDigest();
    }

    /**
     * Extracts the shared secret value (SSV) from encapsulated data as per RFC 6508.
     *
     * @param encapsulation The encapsulated data containing:
     *                      <ul>
     *                        <li>R_(b,S): Elliptic curve point (uncompressed format, 257 bytes)</li>
     *                        <li>H: Integer value (n/8 bytes)</li>
     *                      </ul>
     * @return The extracted SSV as a byte array.
     * @throws IllegalStateException If: Validation of R_(b,S) fails
     */
    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        // Step 1: Parse Encapsulated Data (R_bS, H)
        ECPoint R_bS = curve.decodePoint(Arrays.copyOfRange(encapsulation, 0, 257));
        BigInteger H = BigIntegers.fromUnsignedByteArray(encapsulation, 257, 16);

        // Step 2: Compute w = <R_bS, K_bS> using pairing
        BigInteger w = computePairing(R_bS, K_bs, p, q);

        // Step 3: Compute SSV = H XOR HashToIntegerRange(w, 2^n)
        BigInteger twoToN = BigInteger.ONE.shiftLeft(n);
        BigInteger mask = SAKKEKEMSGenerator.hashToIntegerRange(w.toByteArray(), twoToN, digest);
        BigInteger ssv = H.xor(mask).mod(p);

        // Step 4: Compute r = HashToIntegerRange(SSV || b)
        BigInteger b = identifier;
        BigInteger r = SAKKEKEMSGenerator.hashToIntegerRange(Arrays.concatenate(ssv.toByteArray(), b.toByteArray()), q, digest);

        // Step 5: Validate R_bS
        ECPoint bP = P.multiply(b).normalize();
        ECPoint Test = bP.add(Z_S).multiply(r).normalize();
        if (!R_bS.equals(Test))
        {
            throw new IllegalStateException("Validation of R_bS failed");
        }

        return BigIntegers.asUnsignedByteArray(n / 8, ssv);
    }

    @Override
    public int getEncapsulationLength()
    {
        return 273; //257 (length of ECPoint) + 16 (length of Hash)
    }

    /**
     * Computes the Tate-Lichtenbaum pairing &lt;R, Q&gt; for SAKKE validation.
     * Follows the pairing algorithm described in RFC 6508, Section 3.2.
     *
     * @param R First pairing input (elliptic curve point)
     * @param Q Second pairing input (elliptic curve point)
     * @param p Prime field characteristic
     * @param q Subgroup order
     * @return Pairing result in PF_p[q], represented as a field element
     */
    static BigInteger computePairing(ECPoint R, ECPoint Q, BigInteger p, BigInteger q)
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

    /**
     * Performs multiplication in F_p^2 field.
     *
     * @param x_real Real component of first operand
     * @param x_imag Imaginary component of first operand
     * @param y_real Real component of second operand
     * @param y_imag Imaginary component of second operand
     * @param p      Prime field characteristic
     * @return Result of multiplication in F_p^2 as [real, imaginary] array
     */
    static BigInteger[] fp2Multiply(BigInteger x_real, BigInteger x_imag, BigInteger y_real, BigInteger y_imag, BigInteger p)
    {
        return new BigInteger[]{
            x_real.multiply(y_real).subtract(x_imag.multiply(y_imag)).mod(p),
            x_real.multiply(y_imag).add(x_imag.multiply(y_real)).mod(p)
        };
    }

    /**
     * Computes squaring operation in F_p^2 field.
     *
     * @param currentX Real component of input
     * @param currentY Imaginary component of input
     * @param p        Prime field characteristic
     * @return Squared result in F_p^2 as [newX, newY] array
     */
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
