package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * This class implements the SAKKE (Sakai-Kasahara Key Encryption) Key Encapsulation Mechanism
 * as defined in RFC 6508. It generates an encapsulated shared secret value (SSV) using
 * Identity-Based Encryption (IBE) for secure transmission from a Sender to a Receiver.
 * <p>
 * The algorithm follows these steps (as per RFC 6508, Section 6.2.1):
 * <ol>
 *   <li>Generate a random SSV in the range [0, 2^n - 1].</li>
 *   <li>Compute r = HashToIntegerRange(SSV || b, q).</li>
 *   <li>Compute R_(b,S) = [r]([b]P + Z_S) on the elliptic curve.</li>
 *   <li>Compute H = SSV XOR HashToIntegerRange(g^r, 2^n).</li>
 *   <li>Encode the encapsulated data (R_(b,S), H).</li>
 * </ol>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6508">RFC 6508: Sakai-Kasahara Key Encryption (SAKKE)</a>
 */
public class SAKKEKEMSGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom random;

    /**
     * Constructs a SAKKEKEMSGenerator with the specified source of randomness.
     *
     * @param random a {@link SecureRandom} instance for generating cryptographically secure random values.
     *               Must not be {@code null}.
     */
    public SAKKEKEMSGenerator(SecureRandom random)
    {
        this.random = random;
    }

    /**
     * Generates an encapsulated shared secret value (SSV) using the recipient's public key parameters
     * as specified in RFC 6508, Section 6.2.1.
     * <p>
     * This method performs the following operations:
     * <ul>
     *   <li>Derives cryptographic parameters from the recipient's public key.</li>
     *   <li>Generates a random SSV and computes the encapsulation components (R_(b,S), H).</li>
     *   <li>Encodes the encapsulated data as specified in RFC 6508, Section 4.</li>
     * </ul>
     * </p>
     *
     * @param recipientKey the recipient's public key parameters. Must be an instance of
     *                     {@link SAKKEPublicKeyParameters}. Must not be {@code null}.
     * @return a {@link SecretWithEncapsulation} containing the SSV and the encapsulated data.
     */
    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        // Extract public parameters from the recipient's key
        SAKKEPublicKeyParameters keyParameters = (SAKKEPublicKeyParameters)recipientKey;
        ECPoint Z = keyParameters.getZ();
        BigInteger b = keyParameters.getIdentifier();
        BigInteger p = keyParameters.getPrime();
        BigInteger q = keyParameters.getQ();
        BigInteger g = keyParameters.getG();
        int n = keyParameters.getN();
        ECCurve curve = keyParameters.getCurve();
        ECPoint P = keyParameters.getPoint();
        Digest digest = keyParameters.getDigest();

        // 1. Generate random SSV in range [0, 2^n - 1]
        BigInteger ssv = BigIntegers.createRandomBigInteger(n, random);

        // 2. Compute r = HashToIntegerRange(SSV || b, q)
        BigInteger r = hashToIntegerRange(Arrays.concatenate(ssv.toByteArray(), b.toByteArray()), q, digest);


        // 3. Compute R_(b,S) = [r]([b]P + Z_S)
        ECPoint bP = P.multiply(b).normalize();
        ECPoint R_bS = bP.add(Z).multiply(r).normalize();

        // 4. Compute H = SSV XOR HashToIntegerRange( g^r, 2^n )
        BigInteger pointX = BigInteger.ONE;
        BigInteger pointY = g;
        BigInteger[] v = new BigInteger[2];

        // Initialize result with the original point
        BigInteger currentX = BigInteger.ONE;
        BigInteger currentY = g;
        ECPoint current = curve.createPoint(currentX, currentY);

        int numBits = r.bitLength();
        BigInteger[] rlt;
        // Process bits from MSB-1 down to 0
        for (int i = numBits - 2; i >= 0; i--)
        {
            // Square the current point
            rlt = SAKKEKEMExtractor.fp2PointSquare(currentX, currentY, p);
            current = current.timesPow2(2);
            currentX = rlt[0];
            currentY = rlt[1];
            // Multiply if bit is set
            if (r.testBit(i))
            {
                rlt = SAKKEKEMExtractor.fp2Multiply(currentX, currentY, pointX, pointY, p);

                currentX = rlt[0];
                currentY = rlt[1];
            }
        }

        v[0] = currentX;
        v[1] = currentY;
        BigInteger g_r = v[1].multiply(v[0].modInverse(p)).mod(p);

        BigInteger mask = hashToIntegerRange(g_r.toByteArray(), BigInteger.ONE.shiftLeft(n), digest); // 2^n

        BigInteger H = ssv.xor(mask);
        // 5. Encode encapsulated data (R_bS, H)
//        byte[] encapsulated = Arrays.concatenate(new byte[]{(byte)0x04},
//            BigIntegers.asUnsignedByteArray(n, R_bS.getXCoord().toBigInteger()),
//            BigIntegers.asUnsignedByteArray(n, R_bS.getYCoord().toBigInteger()),
//            BigIntegers.asUnsignedByteArray(16, H));
        byte[] encapsulated = Arrays.concatenate(R_bS.getEncoded(false), BigIntegers.asUnsignedByteArray(16, H));

        return new SecretWithEncapsulationImpl(
            BigIntegers.asUnsignedByteArray(n / 8, ssv), // Output SSV as key material
            encapsulated
        );
    }

    static BigInteger hashToIntegerRange(byte[] input, BigInteger q, Digest digest)
    {
        // RFC 6508 Section 5.1: Hashing to an Integer Range
        byte[] hash = new byte[digest.getDigestSize()];

        // Step 1: Compute A = hashfn(s)
        digest.update(input, 0, input.length);
        digest.doFinal(hash, 0);
        byte[] A = Arrays.clone(hash);

        // Step 2: Initialize h_0 to all-zero bytes of hashlen size
        byte[] h = new byte[digest.getDigestSize()];

        // Step 3: Compute l = Ceiling(lg(n)/hashlen)
        int l = q.bitLength() >> 8;

        BigInteger v = BigInteger.ZERO;

        // Step 4: Compute h_i and v_i
        for (int i = 0; i <= l; i++)
        {
            // h_i = hashfn(h_{i-1})
            digest.update(h, 0, h.length);
            digest.doFinal(h, 0);
            // v_i = hashfn(h_i || A)
            digest.update(h, 0, h.length);
            digest.update(A, 0, A.length);
            byte[] v_i = new byte[digest.getDigestSize()];
            digest.doFinal(v_i, 0);
            // Append v_i to v'
            v = v.shiftLeft(v_i.length * 8).add(new BigInteger(1, v_i));
        }
        // Step 6: v = v' mod n
        return v.mod(q);
    }
}
