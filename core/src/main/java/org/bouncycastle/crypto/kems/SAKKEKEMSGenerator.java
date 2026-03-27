package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
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
        ECPoint R_bS;

        BigInteger order = curve.getOrder();
        if (order == null)
        {
            R_bS = P.multiply(b).add(Z).multiply(r).normalize();
        }
        else
        {
            BigInteger a = b.multiply(r).mod(order);
            R_bS = ECAlgorithms.sumOfTwoMultiplies(P, a, Z, r).normalize();
        }

        // 4. Compute H = SSV XOR HashToIntegerRange( g^r, 2^n )
        BigInteger pointX = BigInteger.ONE;
        BigInteger pointY = g;

        // Initialize result with the original point
        BigInteger v0 = BigInteger.ONE;
        BigInteger v1 = g;
        ECPoint current = curve.createPoint(v0, v1);

        // Process bits from MSB-1 down to 0
        for (int i = r.bitLength() - 2; i >= 0; i--)
        {
            // Square the current point
            BigInteger[] rlt = SAKKEKEMExtractor.fp2PointSquare(v0, v1, p);
            current = current.timesPow2(2);
            v0 = rlt[0];
            v1 = rlt[1];
            // Multiply if bit is set
            if (r.testBit(i))
            {
                rlt = SAKKEKEMExtractor.fp2Multiply(v0, v1, pointX, pointY, p);

                v0 = rlt[0];
                v1 = rlt[1];
            }
        }

        BigInteger v0Inv = BigIntegers.modOddInverse(p, v0);
        BigInteger g_r = v1.multiply(v0Inv).mod(p);

        BigInteger mask = hashToIntegerRange(g_r.toByteArray(), BigInteger.ONE.shiftLeft(n), digest); // 2^n

        BigInteger H = ssv.xor(mask);
        // 5. Encode encapsulated data (R_bS, H)
        byte[] encapsulated = Arrays.concatenate(R_bS.getEncoded(false), BigIntegers.asUnsignedByteArray(16, H));

        return new SecretWithEncapsulationImpl(
            BigIntegers.asUnsignedByteArray(n / 8, ssv), // Output SSV as key material
            encapsulated
        );
    }

    static BigInteger hashToIntegerRange(byte[] input, BigInteger q, Digest digest)
    {
        // RFC 6508 Section 5.1: Hashing to an Integer Range
        byte[] A = new byte[digest.getDigestSize()];

        // Step 1: Compute A = hashfn(s)
        digest.update(input, 0, input.length);
        digest.doFinal(A, 0);

        // Step 2: Initialize h_0 to all-zero bytes of hashlen size
        byte[] h = new byte[digest.getDigestSize()];

        // Step 3: Compute l = Ceiling(lg(n)/hashlen)
        // FIXME Seems hardcoded to 256 bit digest?
        int l = q.bitLength() >> 8;

        BigInteger v = BigInteger.ZERO;
        byte[] v_i = new byte[digest.getDigestSize()];

        // Step 4: Compute h_i and v_i
        for (int i = 0; i <= l; i++)
        {
            // h_i = hashfn(h_{i-1})
            digest.update(h, 0, h.length);
            digest.doFinal(h, 0);
            // v_i = hashfn(h_i || A)
            digest.update(h, 0, h.length);
            digest.update(A, 0, A.length);
            digest.doFinal(v_i, 0);
            // Append v_i to v'
            v = v.shiftLeft(v_i.length * 8).add(new BigInteger(1, v_i));
        }
        // Step 6: v = v' mod n
        return v.mod(q);
    }
}
