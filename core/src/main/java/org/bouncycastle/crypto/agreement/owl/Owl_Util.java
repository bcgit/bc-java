package org.example;

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
 * Primitives needed for an Owl exchange.
 * <p>
 * The recommended way to perform an Owl exchange is by using
 * an {@link Owl_Server} and {@link Owl_Client} 
 * (and for user registration {@link Owl_ClientRegistration} and {@link Owl_ServerRegistration}).  
 * Internally, those two classes call these primitive 
 * operations in {@link Owl_Util}.
 * <p>
 * The primitives, however, can be used without a {@link Owl_Server}
 * or {@link Owl_Client} if needed.
 */
public class Owl_Util
{
    static final BigInteger ZERO = BigInteger.valueOf(0);
    static final BigInteger ONE = BigInteger.valueOf(1);

    /**
     * Return a value that can be used as x1, x2, x3 or x4 during round 1.
     * <p>
     * The returned value is a random value in the range <code>[1, n-1]</code>.
     * @param n The order of the base point
     * @param random SecureRandom
     * @return A random value within [1, n-1]
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
     * Calculate X = [G] * x as done in round 1.
     * Also used to calculate T = [G] * t as seen in the initial user registration
     * 
     * @param g Base point G
     * @param x Scalar x
     * @return [G] * x
     */
    public static ECPoint calculateGx(
        ECPoint g,
        BigInteger x)
    {
        return g.multiply(x);
    }

    /**
     * Calculate the combined public key GA = X1 * X3 * X4 from three public keys X1, X3 and X4. 
     * 
     * @param gx1 Public key X1
     * @param gx3 Public key X3
     * @param gx4 Public key X4
     * @return The combined public key
     * @throws CryptoException  if any of the parameters are the infinity point on the elliptic curve.
     */
    public static ECPoint calculateGA(
        ECPoint gx1,
        ECPoint gx3,
        ECPoint gx4) throws CryptoException {

        if (gx1.isInfinity()) {
            throw new CryptoException("Public key X1 cannot be infinity");
        }
        if (gx3.isInfinity()) {
            throw new CryptoException("Public key X3 cannot be infinity");
        }
        if (gx4.isInfinity()) {
            throw new CryptoException("Public key X4 cannot be infinity");
        }

        ECPoint Gx = gx1.add(gx3).add(gx4);

        if (Gx.isInfinity()) {
            throw new CryptoException("The combined public key cannot be infinity");
        }

        return Gx;
    }


    /**
     * Calculate x2 * pi mod n as done in second pass of Owl.
     * 
     * @param n The order of the base point
     * @param x2 The private key x2
     * @param pi pi = H(t) mod n
     * @return x2 * pi mod n
     */
    public static BigInteger calculateX2s(
        BigInteger n,
        BigInteger x2,
        BigInteger pi)
    {
        return x2.multiply(pi).mod(n);
    }


    /**
     * Calculate alpha or beta as done in the second pass.
     */
    /**
     * Calculate the public key from a base point and a scalar
     * @param gA Base point
     * @param x2pi Scalar
     * @return [gA] * x2pi
     */
    public static ECPoint calculateA(
        ECPoint gA,
        BigInteger x2pi)
    {
        // alpha = Galpha^(x*pi)
        return gA.multiply(x2pi);
    }

    /**
     * Calculate t for the user's initial registration onto the server.
     * t is calculated by H(username||password) mod n
     * 
     * @param n The order of the base point
     * @param string xxx
     * @param digest Instance of Digest
     * @return t = H(username||password) mod n
     * @throws CryptoException if t = 0 mod n
     */
    public static BigInteger calculateT(
        BigInteger n,
        String string,
        Digest digest)
        throws CryptoException
    {
        BigInteger t = calculateHash(string, digest).mod(n);
        if (t.signum() == 0)
        {
            throw new CryptoException("MUST ensure t is not equal to 0 modulo n");
        }
        return t;
    }
    
    /**
     *  Calculate pi = H(t) mod(n) for initial registration.
     * 
     * @param n The order of the base point
     * @param t t = H(username||password) mod n
     * @param digest Instance of a one-way hash
     * @return pi
     * @throws CryptoException When pi = 0 mod n
     */
    public static BigInteger calculatePi(
        BigInteger n,
        BigInteger t,
        Digest digest)
        throws CryptoException
    {
        BigInteger pi = calculateHash(t, digest).mod(n);
        if(pi.compareTo(BigInteger.ZERO)==0){
            throw new CryptoException("MUST ensure that pi is not equal to 0 modulo n");
        }
        return pi;
    }
    /**
     * Calculate a zero-knowledge proof of x using Schnorr's signature.
     * The returned object has two fields {V = [G] * v, r = v-x*h} for x.
     * 
     * @param generator The base point on the curve
     * @param n The order of the base point
     * @param x The private key
     * @param X The public key
     * @param digest Instance of a one-way hash
     * @param userID The identity of the prover
     * @param random Instance of a secure random number generator
     * @return {@link ECSchnorrZKP}
     */
    public static ECSchnorrZKP calculateZeroknowledgeProof(
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
        BigInteger h = calculateHashForZeroknowledgeProof(generator, V, X, userID, digest); // h
        // r = v-x*h mod n   

        return new ECSchnorrZKP(V, v.subtract(x.multiply(h)).mod(n));
    }


    private static BigInteger calculateHash(
        String string,
        Digest digest)
    {
        digest.reset();

        byte[] byteArray = Strings.toUTF8ByteArray(string);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }

    private static BigInteger calculateHash(
        BigInteger bigint,
        Digest digest)
    {
        digest.reset();

        byte[] byteArray = bigint.toByteArray();
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }


    private static BigInteger calculateHashForZeroknowledgeProof(
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

    private static void updateDigestIncludingSize(
        Digest digest,
        BigInteger bigInteger)
    {
        byte[] byteArray = bigInteger.toByteArray();
        digest.update(intToByteArray(byteArray.length), 0, 4);
        digest.update(byteArray, 0, byteArray.length);
        Arrays.fill(byteArray, (byte)0);
    }

    /**
     * Validates the zero-knowledge proof (generated by
     * {@link #calculateZeroknowledgeProof(ECPoint, BigInteger, BigInteger, ECPoint, Digest, String, SecureRandom)})
     * is correct.
     *
     * @param generator The base point on the curve
     * @param X The public key
     * @param zkp The zero-knowledge proof {@link ECSchnorrZKP}
     * @param q The prime modulus for the coordinates
     * @param n The oder of the base point
     * @param curve The elliptic curve
     * @param coFactor The co-factor
     * @param userID The identity of the prover
     * @param digest Instance of a one-way hash
     * @throws CryptoException If the zero-knowledge proof is not correct
     */
    
    public static void validateZeroknowledgeProof(
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
        BigInteger h = calculateHashForZeroknowledgeProof(generator, V, X, userID, digest);

        // First, ensure X is a valid public key
        validatePublicKey(X, curve, q, coFactor);
        
        // Now check if V = G*r + X*h.
        // Given that {G, X} are valid points on the curve, the equality implies that V is also a point on the curve.
        if (!V.equals(generator.multiply(r).add(X.multiply(h.mod(n)))))
        {
            throw new CryptoException("Zero-knowledge proof validation failed: V = G*r + X*h must hold");
        }

    }

    /**
     * Validates that the given participant ids are not equal.
     * (For the Owl exchange, each participant must use a unique id.)
     *
     * @param participantId1 The identity of the first participant
     * @param participantId2 The identity of the second participate
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
     * each round all come from the same participant (client/server).
     * 
     * @param expectedParticipantId The expected participant's identity
     * @param actualParticipantId The actual participate's identity

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
     * Calculates the keying material, which can be done after {@link Owl_Client#authenticationFinish(Owl_AuthenticationServerResponse)} has completed
     * for client and when {@link Owl_Server#authenticationServerEnd(Owl_AuthenticationFinish)} has completed for server.
     * A session key must be derived from this key material using a secure key derivation function (KDF).
     * The KDF used to derive the key is handled externally (i.e. not by {@link Owl_Server} or {@link Owl_Client}).
     * <pre>
     * KeyingMaterial = [Beta - [X4] * x2pi] * x2
     * </pre>
     * 
     * @param gx4 Public key X4 = x4 * [G]
     * @param x2 Private key x2
     * @param x2pi Private key x2*pi
     * @param B The public key Beta 
     * @return Raw key material K = [Beta - [X4] * x2pi] * x2)
     */
    public static ECPoint calculateKeyingMaterial(
        ECPoint gx4,
        BigInteger x2,
        BigInteger x2pi,
        ECPoint B)
    {
        return B.subtract(gx4.multiply(x2pi)).multiply(x2);        
    }

    /**
     * Calculates the 'transcript' which is, in order, everything communicated between the two parties
     * in the login authentication protocol used to compute a common session key. 
     * Transcript is required for the calculation of r, as a compiler is used
     * to prove the knowledge of t in an asymmetric setting.
     * For more information: <a href= "https://eprint.iacr.org/2023/768.pdf"> Owl: An Augmented Password-Authenticated 
     * Key Exchange Scheme </a>
     * 
     * @param rawKey Raw key material
     * @param clientId Client identity
     * @param gx1 Public key X1
     * @param gx2 Public key X2
     * @param knowledgeProofX1 Zero-knowledge proof for X1
     * @param knowledgeProofX2 Zero-knowledge proof for X2
     * @param serverId Server identity
     * @param gx3 Public key X3
     * @param gx4 Public key X4 
     * @param knowledgeProofX3 Zero-knowledge proof for X3
     * @param knowledgeProofX4 Zero-knowledege proof for X4
     * @param beta Public key Beta
     * @param knowledgeProofBeta Zero-knowledge proof for Beta
     * @param alpha Public key Alpha
     * @param knowledgeProofAlpha Zero-knowledge proof for Alpha
     * @param digest Instance of MAC
     * @return Transcript
     */
    public static BigInteger calculateTranscript(
        ECPoint rawKey,
        String clientId,
        ECPoint gx1,
        ECPoint gx2,
        ECSchnorrZKP knowledgeProofX1,
        ECSchnorrZKP knowledgeProofX2,
        String serverId,
        ECPoint gx3,
        ECPoint gx4,
        ECSchnorrZKP knowledgeProofX3,
        ECSchnorrZKP knowledgeProofX4,
        ECPoint beta,
        ECSchnorrZKP knowledgeProofBeta,
        ECPoint alpha,
        ECSchnorrZKP knowledgeProofAlpha,
        Digest digest)
    {
        digest.reset();

        updateDigestIncludingSize(digest, rawKey);
        updateDigestIncludingSize(digest, clientId);
        updateDigestIncludingSize(digest, gx1);
        updateDigestIncludingSize(digest, gx2);
        updateDigestIncludingSize(digest, knowledgeProofX1.getV());
        updateDigestIncludingSize(digest, knowledgeProofX1.getr());
        updateDigestIncludingSize(digest, knowledgeProofX2.getV());
        updateDigestIncludingSize(digest, knowledgeProofX2.getr());
        updateDigestIncludingSize(digest, serverId);
        updateDigestIncludingSize(digest, gx3);
        updateDigestIncludingSize(digest, gx4);
        updateDigestIncludingSize(digest, knowledgeProofX3.getV());
        updateDigestIncludingSize(digest, knowledgeProofX3.getr());
        updateDigestIncludingSize(digest, knowledgeProofX4.getV());
        updateDigestIncludingSize(digest, knowledgeProofX4.getr());
        updateDigestIncludingSize(digest, beta);
        updateDigestIncludingSize(digest, knowledgeProofBeta.getV());
        updateDigestIncludingSize(digest, knowledgeProofBeta.getr());
        updateDigestIncludingSize(digest, alpha);
        updateDigestIncludingSize(digest, knowledgeProofAlpha.getV());
        updateDigestIncludingSize(digest, knowledgeProofAlpha.getr());

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }

    /**
     * Calculates r = x1 - t * h mod n, where h is the hashed key+transcript.
     * 
     * @param x1 Private key x1
     * @param t t = H(username||password) mod n
     * @param hTranscript Transcript 
     * @param n Order of the base point
     * @return r
     */
    public static BigInteger calculateR(
        BigInteger x1, 
        BigInteger t, 
        BigInteger hTranscript, 
        BigInteger n)
    {
        return x1.subtract(t.multiply(hTranscript)).mod(n);
    }

    /**
     * Validates r by checking [g] * r + [T] * h equals X1
     * 
     * @param r The client response r
     * @param gx1 Public key X1
     * @param h Transcript
     * @param gt Password verifier T
     * @param g Base point
     * @param n order of the base point
     * @throws CryptoException  if the validation fails i.e the values do not equal.
     */
    public static void validateR(
        BigInteger r, 
        ECPoint gx1,
        BigInteger h,
        ECPoint gt,
        ECPoint g,
        BigInteger n)
    throws CryptoException
    {
        if(!g.multiply(r).add(gt.multiply(h.mod(n))).equals(gx1))
        {
            throw new CryptoException("Verification for r failed, g^r . T^h = X1 must be true");
        }
    }
    
    /**
     * Validates that an EC point X is a valid public key on the designated elliptic curve.
     * 
     * @param X Public key 
     * @param curve Elliptic curve
     * @param q Prime field for the coordinates
     * @param coFactor Co-factor
     * @throws CryptoException if the public key validation fails
     */
    public static void validatePublicKey(ECPoint X, ECCurve curve, BigInteger q, BigInteger coFactor) throws CryptoException{
        
        /* Public key validation based on the following paper (Sec 3)
         * Antipa, A., Brown, D., Menezes, A., Struik, R. and Vanstone, S., 
         * "Validation of elliptic curve public keys," PKC, 2002
         * https://iacr.org/archive/pkc2003/25670211/25670211.pdf
         */
             
        // 1. X != infinity
        if (X.isInfinity())
        {
            throw new CryptoException("Public key validation failed: it cannot equal infinity");
        }

        ECPoint x_normalized = X.normalize();
        // 2. Check x and y coordinates are in Fq, i.e., x, y in [0, q-1]
        if (x_normalized.getAffineXCoord().toBigInteger().signum() < 0 ||
            x_normalized.getAffineXCoord().toBigInteger().compareTo(q) >= 0 ||
            x_normalized.getAffineYCoord().toBigInteger().signum() < 0 ||
            x_normalized.getAffineYCoord().toBigInteger().compareTo(q) >= 0)
        {
            throw new CryptoException("Public key validation failed: x and y coordiantes are not in the field");
        }      
        // 3. Check X lies on the curve
        try
        {
            curve.decodePoint(X.getEncoded(true));
        }
        catch (Exception e)
        {
            throw new CryptoException("Public key validation failed: it does not lie on the curve");
        }   
        // 4. Check that nX = infinity.
        // It is equivalent - but more efficient - to check the coFactor*X is not infinity
        if (X.multiply(coFactor).isInfinity())
        {
            throw new CryptoException("Public key validation failed: it is in a small order group");
        }
    }

    /**
     * Calculates the MacTag (to be used for key confirmation), as defined by
     * <a href= "https://csrc.nist.gov/pubs/sp/800/56/a/r3/final">NIST SP 800-56A Revision 3</a>,
     * Section 5.9.1 Unilateral Key Confirmation for Key Agreement Schemes.
     * <pre>
     * MacTag = HMAC(MacKey, MacLen, MacData)
     *
     * MacKey = H(K || "Owl_KC")
     *
     * MacData = "KC_1_U" || participantId || partnerParticipantId || gx1 || gx2 || gx3 || gx4
     *
     * Note that both participants use "KC_1_U" because the sender of the key confirmation message
     * is always the initiator for key confirmation.
     *
     * HMAC = {@link HMac} used with the given {@link Digest}
     * H = The given {@link Digest}
     * MacOutputBits = MacTagBits, hence truncation function omitted.
     * MacLen = length of MacTag
     * </pre>
     * 
     * @param participantId Participant's identity
     * @param partnerParticipantId The other participant's identity
     * @param gx1 Public key X1
     * @param gx2 Public key X2
     * @param gx3 Public key X3
     * @param gx4 Public key X4
     * @param keyingMaterial Keying material
     * @param digest Instance of a one-way hash
     * @return MacTag for key confirmation
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
     * MacKey = H(K || "Owl_KC")
     * </pre>
     * 
     * @param keyingMaterial Keying material K
     * @param digest Instance of a one-way hash
     * @return H(K || "Owl_KC")
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
        updateDigest(digest, "Owl_KC");

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return output;
    }

    /**
     * Validates the MacTag received from the partner participant.
     *
     * @param participantId The participant's identity
     * @param partnerParticipantId The other participant's identity
     * @param gx1 Public key X1
     * @param gx2 Public key X2
     * @param gx3 Public key X3
     * @param gx4 Public key X4
     * @param keyingMaterial Keying material
     * @param digest Instance of a one-way hash
     * @param partnerMacTag The MacTag received from the partner.
     * @throws CryptoException if the participantId strings are equal
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

    protected static byte[] intToByteArray(int value)
    {
        return new byte[]{
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value
        };
    }

}
