package org.bouncycastle.crypto.kems;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.SAKKEPublicKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class SAKKEKEMSGenerator
    implements EncapsulatedSecretGenerator
{
    private final SAKKEPublicKey publicParams;
    private final SecureRandom random;

    public SAKKEKEMSGenerator(SAKKEPublicKey params, SecureRandom random)
    {
        this.publicParams = params;
        this.random = random;
    }

    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        // 1. Generate random SSV in range [0, 2^n - 1]
        BigInteger ssv = new BigInteger(publicParams.getN(), random);

        // 2. Compute r = HashToIntegerRange(SSV || b, q)
        BigInteger b = getRecipientId((SAKKEPublicKey)recipientKey);
        BigInteger r = SAKKEUtils.hashToIntegerRange(Arrays.concatenate(ssv.toByteArray(), b.toByteArray()), publicParams.getQ());

        // 3. Compute R_(b,S) = [r]([b]P + Z_S)
        ECPoint bP = publicParams.getP().multiply(b);   // [b]P
        ECPoint Z_S = publicParams.getZ();              // Z_S
        ECPoint R_bS = bP.add(Z_S).multiply(r);         // [r]([b]P + Z_S)

        // 4. Compute H = SSV XOR HashToIntegerRange( g^r, 2^n )
        BigInteger g_r = pairing(R_bS, publicParams.getP(), publicParams.getQ(), publicParams.getP().getCurve().getField().getCharacteristic());
        BigInteger mask = SAKKEUtils.hashToIntegerRange(g_r.toByteArray(), BigInteger.ONE.shiftLeft(publicParams.getN())); // 2^n

        BigInteger H = ssv.xor(mask);

        // 5. Encode encapsulated data (R_bS, H)
        byte[] encapsulated = encodeData(R_bS, H);

        return new SecretWithEncapsulationImpl(
            BigIntegers.asUnsignedByteArray(publicParams.getN() / 8, ssv), // Output SSV as key material
            encapsulated
        );
    }

    private BigInteger getRecipientId(SAKKEPublicKey pubKey)
    {
        byte[] hashedId = SAKKEUtils.hash(pubKey.getZ().getEncoded(false));  // Hash Z_S
        return new BigInteger(1, hashedId).mod(pubKey.getQ().subtract(BigInteger.ONE)).add(BigIntegers.TWO);
    }

    /**
     * Computes the Tate-Lichtenbaum pairing ⟨P, Q⟩ as per RFC 6508.
     * <p>
     * //* @param P First point (on E(F_p)).
     *
     * @param Q Second point (on E(F_p)).
     * @return Result of the pairing in the field F_p^2.
     */
    public static BigInteger pairing(ECPoint R, ECPoint Q, BigInteger p, BigInteger q)
    {
        ECCurve curve = R.getCurve();
        ECFieldElement i = curve.fromBigInteger(BigInteger.ONE.negate()); // i = -1 in F_p^2

        ECPoint C = R;
        BigInteger c = p.add(BigInteger.ONE).divide(q);
        ECFieldElement v = curve.fromBigInteger(BigInteger.ONE); // v = 1 in F_p

        String qBits = q.subtract(BigInteger.ONE).toString(2); // Binary representation of q-1

        for (int j = 1; j < qBits.length(); j++)
        { // Skip MSB
            // l = (3 * (C_x^2 - 1)) / (2 * C_y)
            ECFieldElement Cx = C.getAffineXCoord();
            ECFieldElement Cy = C.getAffineYCoord();
            ECFieldElement l = Cx.square().multiply(curve.fromBigInteger(ECFieldElement.THREE)).subtract(curve.fromBigInteger(BigInteger.ONE))
                .divide(Cy.multiply(curve.fromBigInteger(BigIntegers.TWO)));

            // v = v^2 * (l * (Q_x + C_x) + (i * Q_y - C_y))
            ECFieldElement Qx = Q.getAffineXCoord();
            ECFieldElement Qy = Q.getAffineYCoord();
            v = v.square().multiply(l.multiply(Qx.add(Cx)).add(i.multiply(Qy).subtract(Cy)));

            // Double the point
            C = C.twice();

            // If the bit is 1, perform additional step
            if (qBits.charAt(j) == '1')
            {
                // l = (C_y - R_y) / (C_x - R_x)
                ECFieldElement Rx = R.getAffineXCoord();
                ECFieldElement Ry = R.getAffineYCoord();
                l = Cy.subtract(Ry).divide(Cx.subtract(Rx));

                // v = v * (l * (Q_x + C_x) + (i * Q_y - C_y))
                v = v.multiply(l.multiply(Qx.add(Cx)).add(i.multiply(Qy).subtract(Cy)));

                // C = C + R
                C = C.add(R);
            }
        }

        // Compute v^c
        v = curve.fromBigInteger(v.toBigInteger().pow(c.intValue()));

        // Convert to F_p representative
        return computeFpRepresentative(v, curve);
    }

    private static BigInteger computeFpRepresentative(ECFieldElement t, ECCurve curve)
    {
        // Characteristic of F_p
        BigInteger p = ((ECCurve.Fp) curve).getQ();

        // Assume t = a + i * b in F_p² → extract a, b
        ECFieldElement a = t; // In F_p², a is the real part
        ECFieldElement b = t.multiply(curve.fromBigInteger(BigInteger.ONE.negate())); // Imaginary part

        // Compute b/a mod p
        return b.toBigInteger().multiply(a.toBigInteger().modInverse(p)).mod(p);
    }

    public static byte[] encodeData(ECPoint R_bS, BigInteger H) {
        // 1. Serialize EC Point (use compressed format for efficiency)
        byte[] R_bS_bytes = R_bS.getEncoded(true);

        // 2. Serialize H (convert to a fixed-length byte array)
        byte[] H_bytes = H.toByteArray();

        // 3. Combine both into a single byte array
        ByteBuffer buffer = ByteBuffer.allocate(R_bS_bytes.length + H_bytes.length);
        buffer.put(R_bS_bytes);
        buffer.put(H_bytes);

        return buffer.array();
    }
}
