package org.bouncycastle.crypto.agreement.ecjpake;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/**
 * Primitives needed for a EC J-PAKE exchange.
 * <p>
 * The recommended way to perform an EC J-PAKE exchange is by using
 * two {@link ECJPAKEParticipant}s.  Internally, those participants
 * call these primitive operations in {@link ECJPAKEUtil}.
 * <p>
 * The primitives, however, can be used without a {@link ECJPAKEParticipant}
 * if needed.
 */
public class ECJPAKEUtil
{
    static final BigInteger ZERO = BigInteger.valueOf(0);
    static final BigInteger ONE = BigInteger.valueOf(1);

    /**
     * Return a value that can be used as x1, x2, x3 or x4 during round 1.
     * <p>
     * The returned value is a random value in the range <tt>[1, n-1]</tt>.
     */
    public static BigInteger generateX1(
        BigInteger n,
        SecureRandom random)
    {
        BigInteger min = ONE;
        BigInteger max = n.subtract(ONE);
        return BigIntegers.createRandomInRange(min, max, random);
    }

    /**
     * Converts the given password to a {@link BigInteger} mod n.
     */
    public static BigInteger calculateS(
        BigInteger n,
        byte[] password)
        throws CryptoException
    {
        BigInteger s = new BigInteger(1, password).mod(n);
        if (s.signum() == 0)
        {
            throw new CryptoException("MUST ensure s is not equal to 0 modulo n");
        }
        return s;
    }

    /**
     * Converts the given password to a {@link BigInteger} mod n.
     */
    public static BigInteger calculateS(
        BigInteger n,
        char[] password)
        throws CryptoException
    {
        return calculateS(n, Strings.toUTF8ByteArray(password));
    }

    /**
     * Calculate g^x as done in round 1.
     */
    public static ECPoint calculateGx(
        ECPoint g,
        BigInteger x)
    {
        return g.multiply(x);
    }

    /**
     * Calculate ga as done in round 2.
     */
    public static ECPoint calculateGA(
        ECPoint gx1,
        ECPoint gx3,
        ECPoint gx4)
    {
        // ga = g^(x1+x3+x4) = g^x1 * g^x3 * g^x4 
        return gx1.add(gx3).add(gx4);
    }


    /**
     * Calculate x2 * s as done in round 2.
     */
    public static BigInteger calculateX2s(
        BigInteger n,
        BigInteger x2,
        BigInteger s)
    {
        return x2.multiply(s).mod(n);
    }


    /**
     * Calculate A as done in round 2.
     */
    public static ECPoint calculateA(
        ECPoint gA,
        BigInteger x2s)
    {
        // A = ga^(x*s)
        return gA.multiply(x2s);
    }

    /**
     * Calculate a zero knowledge proof of x using Schnorr's signature.
     * The returned object has two fields {g^v, r = v-x*h} for x.
     */
    public static ECSchnorrZKP calculateZeroKnowledgeProof(
        ECPoint generator,
        BigInteger n,
        BigInteger x,
        ECPoint X,
        Digest digest,
        String userID,
        SecureRandom random)
    {

        /* Generate a random v from [1, n-1], and compute V = G*v */
        BigInteger v = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
        ECPoint V = generator.multiply(v);
        BigInteger h = calculateHashForZeroKnowledgeProof(generator, V, X, userID, digest); // h
        // r = v-x*h mod n   

        return new ECSchnorrZKP(V, v.subtract(x.multiply(h)).mod(n));
    }

    private static BigInteger calculateHashForZeroKnowledgeProof(
        ECPoint g,
        ECPoint v,
        ECPoint x,
        String participantId,
        Digest digest)
    {
        digest.reset();

        updateDigestIncludingSize(digest, g);

        updateDigestIncludingSize(digest, v);

        updateDigestIncludingSize(digest, x);

        updateDigestIncludingSize(digest, participantId);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }

    private static void updateDigestIncludingSize(
        Digest digest,
        ECPoint ecPoint)
    {
        byte[] byteArray = ecPoint.getEncoded(true);
        digest.update(intToByteArray(byteArray.length), 0, 4);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigestIncludingSize(
        Digest digest,
        String string)
    {
        byte[] byteArray = Strings.toUTF8ByteArray(string);
        digest.update(intToByteArray(byteArray.length), 0, 4);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    /**
     * Validates the zero knowledge proof (generated by
     * {@link #calculateZeroKnowledgeProof(ECPoint, BigInteger, BigInteger, ECPoint, Digest, String, SecureRandom)})
     * is correct.
     *
     * @throws CryptoException if the zero knowledge proof is not correct
     */
    public static void validateZeroKnowledgeProof(
        ECPoint generator,
        ECPoint X,
        ECSchnorrZKP zkp,
        BigInteger q,
        BigInteger n,
        ECCurve curve,
        BigInteger coFactor,
        String userID,
        Digest digest)
        throws CryptoException
    {
        ECPoint V = zkp.getV();
        BigInteger r = zkp.getr();
        /* ZKP: {V=G*v, r} */
        BigInteger h = calculateHashForZeroKnowledgeProof(generator, V, X, userID, digest);

        /* Public key validation based on the following paper (Sec 3)
         * Antipa A., Brown D., Menezes A., Struik R. and Vanstone S.
         * "Validation of elliptic curve public keys", PKC, 2002
         * https://iacr.org/archive/pkc2003/25670211/25670211.pdf
         */
        // 1. X != infinity
        if (X.isInfinity())
        {
            throw new CryptoException("Zero-knowledge proof validation failed: X cannot equal infinity");
        }

        ECPoint x_normalized = X.normalize();
        // 2. Check x and y coordinates are in Fq, i.e., x, y in [0, q-1]
        if (x_normalized.getAffineXCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
            x_normalized.getAffineXCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1 ||
            x_normalized.getAffineYCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
            x_normalized.getAffineYCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1)
        {
            throw new CryptoException("Zero-knowledge proof validation failed: x and y are not in the field");
        }

        // 3. Check X lies on the curve
        try
        {
            curve.decodePoint(X.getEncoded(true));
        }
        catch (Exception e)
        {
            throw new CryptoException("Zero-knowledge proof validation failed: x does not lie on the curve", e);
        }

        // 4. Check that nX = infinity.
        // It is equivalent - but more more efficient - to check the coFactor*X is not infinity
        if (X.multiply(coFactor).isInfinity())
        {
            throw new CryptoException("Zero-knowledge proof validation failed: Nx cannot be infinity");
        }
        // Now check if V = G*r + X*h.
        // Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
        if (!V.equals(generator.multiply(r).add(X.multiply(h.mod(n)))))
        {
            throw new CryptoException("Zero-knowledge proof validation failed: V must be a point on the curve");
        }

    }

    /**
     * Validates that the given participant ids are not equal.
     * (For the J-PAKE exchange, each participant must use a unique id.)
     *
     * @throws CryptoException if the participantId strings are equal.
     */
    public static void validateParticipantIdsDiffer(
        String participantId1,
        String participantId2)
        throws CryptoException
    {
        if (participantId1.equals(participantId2))
        {
            throw new CryptoException(
                "Both participants are using the same participantId ("
                    + participantId1
                    + "). This is not allowed. "
                    + "Each participant must use a unique participantId.");
        }
    }

    /**
     * Validates that the given participant ids are equal.
     * This is used to ensure that the payloads received from
     * each round all come from the same participant.
     *
     * @throws CryptoException if the participantId strings are equal.
     */
    public static void validateParticipantIdsEqual(
        String expectedParticipantId,
        String actualParticipantId)
        throws CryptoException
    {
        if (!expectedParticipantId.equals(actualParticipantId))
        {
            throw new CryptoException(
                "Received payload from incorrect partner ("
                    + actualParticipantId
                    + "). Expected to receive payload from "
                    + expectedParticipantId
                    + ".");
        }
    }

    /**
     * Validates that the given object is not null.
     *
     * @param object      object in question
     * @param description name of the object (to be used in exception message)
     * @throws NullPointerException if the object is null.
     */
    public static void validateNotNull(
        Object object,
        String description)
    {
        if (object == null)
        {
            throw new NullPointerException(description + " must not be null");
        }
    }

    /**
     * Calculates the keying material, which can be done after round 2 has completed.
     * A session key must be derived from this key material using a secure key derivation function (KDF).
     * The KDF used to derive the key is handled externally (i.e. not by {@link ECJPAKEParticipant}).
     * <pre>
     * KeyingMaterial = (B/g^{x2*x4*s})^x2
     * </pre>
     */
    public static BigInteger calculateKeyingMaterial(
        BigInteger n,
        ECPoint gx4,
        BigInteger x2,
        BigInteger s,
        ECPoint B)
    {
        ECPoint k = ((B.subtract(gx4.multiply(x2.multiply(s).mod(n)))).multiply(x2));
        k = k.normalize();

        return k.getAffineXCoord().toBigInteger();
    }

    /**
     * Calculates the MacTag (to be used for key confirmation), as defined by
     * <a href= "https://csrc.nist.gov/pubs/sp/800/56/a/r3/final">NIST SP 800-56A Revision 3</a>,
     * Section 5.9.1 Unilateral Key Confirmation for Key Agreement Schemes.
     * <pre>
     * MacTag = HMAC(MacKey, MacLen, MacData)
     *
     * MacKey = H(K || "ECJPAKE_KC")
     *
     * MacData = "KC_1_U" || participantId || partnerParticipantId || gx1 || gx2 || gx3 || gx4
     *
     * Note that both participants use "KC_1_U" because the sender of the round 3 message
     * is always the initiator for key confirmation.
     *
     * HMAC = {@link HMac} used with the given {@link Digest}
     * H = The given {@link Digest}
     * MacOutputBits = MacTagBits, hence truncation function omitted.
     * MacLen = length of MacTag
     * </pre>
     */
    public static BigInteger calculateMacTag(
        String participantId,
        String partnerParticipantId,
        ECPoint gx1,
        ECPoint gx2,
        ECPoint gx3,
        ECPoint gx4,
        BigInteger keyingMaterial,
        Digest digest)
    {
        byte[] macKey = calculateMacKey(
            keyingMaterial,
            digest);

        HMac mac = new HMac(digest);
        byte[] macOutput = new byte[mac.getMacSize()];
        mac.init(new KeyParameter(macKey));

        /*
         * MacData = "KC_1_U" || participantId_Alice || participantId_Bob || gx1 || gx2 || gx3 || gx4.
         */
        updateMac(mac, "KC_1_U");
        updateMac(mac, participantId);
        updateMac(mac, partnerParticipantId);
        updateMac(mac, gx1);
        updateMac(mac, gx2);
        updateMac(mac, gx3);
        updateMac(mac, gx4);

        mac.doFinal(macOutput, 0);

        Arrays.fill(macKey, (byte)0);

        return new BigInteger(macOutput);

    }

    /**
     * Calculates the MacKey (i.e. the key to use when calculating the MagTag for key confirmation).
     * <pre>
     * MacKey = H(K || "ECJPAKE_KC")
     * </pre>
     */
    private static byte[] calculateMacKey(
        BigInteger keyingMaterial,
        Digest digest)
    {
        digest.reset();

        updateDigest(digest, keyingMaterial);
        /*
         * This constant is used to ensure that the macKey is NOT the same as the derived key.
         */
        updateDigest(digest, "ECJPAKE_KC");

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return output;
    }

    /**
     * Validates the MacTag received from the partner participant.
     *
     * @param partnerMacTag the MacTag received from the partner.
     * @throws CryptoException if the participantId strings are equal.
     */
    public static void validateMacTag(
        String participantId,
        String partnerParticipantId,
        ECPoint gx1,
        ECPoint gx2,
        ECPoint gx3,
        ECPoint gx4,
        BigInteger keyingMaterial,
        Digest digest,
        BigInteger partnerMacTag)
        throws CryptoException
    {
        /*
         * Calculate the expected MacTag using the parameters as the partner
         * would have used when the partner called calculateMacTag.
         *
         * i.e. basically all the parameters are reversed.
         * participantId <-> partnerParticipantId
         *            x1 <-> x3
         *            x2 <-> x4
         */
        BigInteger expectedMacTag = calculateMacTag(
            partnerParticipantId,
            participantId,
            gx3,
            gx4,
            gx1,
            gx2,
            keyingMaterial,
            digest);

        if (!expectedMacTag.equals(partnerMacTag))
        {
            throw new CryptoException(
                "Partner MacTag validation failed. "
                    + "Therefore, the password, MAC, or digest algorithm of each participant does not match.");
        }
    }

    private static void updateMac(Mac mac, ECPoint ecPoint)
    {
        byte[] byteArray = ecPoint.getEncoded(true);
        mac.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateMac(Mac mac, String string)
    {
        byte[] byteArray = Strings.toUTF8ByteArray(string);
        mac.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigest(Digest digest, ECPoint ecPoint)
    {
        byte[] byteArray = ecPoint.getEncoded(true);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigest(Digest digest, String string)
    {
        byte[] byteArray = Strings.toUTF8ByteArray(string);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static void updateDigest(Digest digest, BigInteger bigInteger)
    {
        byte[] byteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    private static byte[] intToByteArray(int value)
    {
        return new byte[]{
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value
        };
    }

}
