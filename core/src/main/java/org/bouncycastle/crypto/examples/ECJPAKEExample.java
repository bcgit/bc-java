package org.bouncycastle.crypto.examples;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKECurve;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKECurves;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKEParticipant;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound1Payload;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound2Payload;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound3Payload;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * An example of a J-PAKE exchange.
 * <p>
 * <p>
 * In this example, both Alice and Bob are on the same computer (in the same JVM, in fact).
 * In reality, Alice and Bob would be in different locations,
 * and would be sending their generated payloads to each other.
 */
public class ECJPAKEExample
{

    public static void main(String args[])
        throws CryptoException
    {
        // -DM 48 System.out.print
        /*
         * Initialization
         *
         * Pick an appropriate elliptic curve to use throughout the exchange.
         * Note that both participants must use the same group.
         */
        ECJPAKECurve curve = ECJPAKECurves.NIST_P256;

//        ECCurve ecCurve = curve.getCurve();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        ECPoint g = curve.getG();
        BigInteger h = curve.getH();
        BigInteger n = curve.getN();
        BigInteger q = curve.getQ();

        String alicePassword = "password";
        String bobPassword = "password";

        System.out.println("********* Initialization **********");
        System.out.println("Public parameters for the elliptic curve over prime field:");
        System.out.println("Curve param a (" + a.bitLength() + " bits): " + a.toString(16));
        System.out.println("Curve param b (" + b.bitLength() + " bits): " + b.toString(16));
        System.out.println("Co-factor h (" + h.bitLength() + " bits): " + h.toString(16));
        System.out.println("Base point G (" + g.getEncoded(true).length + " bytes): " + new BigInteger(g.getEncoded(true)).toString(16));
        System.out.println("X coord of G (G not normalised) (" + g.getXCoord().toBigInteger().bitLength() + " bits): " + g.getXCoord().toBigInteger().toString(16));
        System.out.println("y coord of G (G not normalised) (" + g.getYCoord().toBigInteger().bitLength() + " bits): " + g.getYCoord().toBigInteger().toString(16));
        System.out.println("Order of the base point n (" + n.bitLength() + " bits): " + n.toString(16));
        System.out.println("Prime field q (" + q.bitLength() + " bits): " + q.toString(16));
        System.out.println("");

        System.out.println("(Secret passwords used by Alice and Bob: " +
            "\"" + alicePassword + "\" and \"" + bobPassword + "\")\n");

        /*
         * Both participants must use the same hashing algorithm.
         */
        Digest digest = SHA256Digest.newInstance();
        SecureRandom random = new SecureRandom();

        ECJPAKEParticipant alice = new ECJPAKEParticipant("alice", alicePassword.toCharArray(), curve, digest, random);
        ECJPAKEParticipant bob = new ECJPAKEParticipant("bob", bobPassword.toCharArray(), curve, digest, random);

        /*
         * Round 1
         *
         * Alice and Bob each generate a round 1 payload, and send it to each other.
         */

        ECJPAKERound1Payload aliceRound1Payload = alice.createRound1PayloadToSend();
        ECJPAKERound1Payload bobRound1Payload = bob.createRound1PayloadToSend();

        System.out.println("************ Round 1 **************");
        System.out.println("Alice sends to Bob: ");
        System.out.println("g^{x1}=" + new BigInteger(aliceRound1Payload.getGx1().getEncoded(true)).toString(16));
        System.out.println("g^{x2}=" + new BigInteger(aliceRound1Payload.getGx2().getEncoded(true)).toString(16));
        System.out.println("KP{x1}: {V=" + new BigInteger(aliceRound1Payload.getKnowledgeProofForX1().getV().getEncoded(true)).toString(16) + "; r=" + aliceRound1Payload.getKnowledgeProofForX1().getr().toString(16) + "}");
        System.out.println("KP{x2}: {V=" + new BigInteger(aliceRound1Payload.getKnowledgeProofForX2().getV().getEncoded(true)).toString(16) + "; r=" + aliceRound1Payload.getKnowledgeProofForX2().getr().toString(16) + "}");
        System.out.println("");

        System.out.println("Bob sends to Alice: ");
        System.out.println("g^{x3}=" + new BigInteger(bobRound1Payload.getGx1().getEncoded(true)).toString(16));
        System.out.println("g^{x4}=" + new BigInteger(bobRound1Payload.getGx2().getEncoded(true)).toString(16));
        System.out.println("KP{x3}: {V=" + new BigInteger(bobRound1Payload.getKnowledgeProofForX1().getV().getEncoded(true)).toString(16) + "; r=" + bobRound1Payload.getKnowledgeProofForX1().getr().toString(16) + "}");
        System.out.println("KP{x4}: {V=" + new BigInteger(bobRound1Payload.getKnowledgeProofForX2().getV().getEncoded(true)).toString(16) + "; r=" + bobRound1Payload.getKnowledgeProofForX2().getr().toString(16) + "}");
        System.out.println("");

        /*
         * Each participant must then validate the received payload for round 1
         */

        alice.validateRound1PayloadReceived(bobRound1Payload);
        System.out.println("Alice checks g^{x4}!=1: OK");
        System.out.println("Alice checks KP{x3}: OK");
        System.out.println("Alice checks KP{x4}: OK");
        System.out.println("");

        bob.validateRound1PayloadReceived(aliceRound1Payload);
        System.out.println("Bob checks g^{x2}!=1: OK");
        System.out.println("Bob checks KP{x1},: OK");
        System.out.println("Bob checks KP{x2},: OK");
        System.out.println("");

        /*
         * Round 2
         *
         * Alice and Bob each generate a round 2 payload, and send it to each other.
         */

        ECJPAKERound2Payload aliceRound2Payload = alice.createRound2PayloadToSend();
        ECJPAKERound2Payload bobRound2Payload = bob.createRound2PayloadToSend();

        System.out.println("************ Round 2 **************");
        System.out.println("Alice sends to Bob: ");
        System.out.println("A=" + new BigInteger(aliceRound2Payload.getA().getEncoded(true)).toString(16));
        System.out.println("KP{x2*s}: {V=" + new BigInteger(aliceRound2Payload.getKnowledgeProofForX2s().getV().getEncoded(true)).toString(16) + ", r=" + aliceRound2Payload.getKnowledgeProofForX2s().getr().toString(16) + "}");
        System.out.println("");

        System.out.println("Bob sends to Alice");
        System.out.println("B=" + new BigInteger(bobRound2Payload.getA().getEncoded(true)).toString(16));
        System.out.println("KP{x4*s}: {V=" + new BigInteger(bobRound2Payload.getKnowledgeProofForX2s().getV().getEncoded(true)).toString(16) + ", r=" + bobRound2Payload.getKnowledgeProofForX2s().getr().toString(16) + "}");
        System.out.println("");

        /*
         * Each participant must then validate the received payload for round 2
         */

        alice.validateRound2PayloadReceived(bobRound2Payload);
        System.out.println("Alice checks KP{x4*s}: OK\n");

        bob.validateRound2PayloadReceived(aliceRound2Payload);
        System.out.println("Bob checks KP{x2*s}: OK\n");

        /*
         * After round 2, each participant computes the keying material.
         */

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        System.out.println("********* After round 2 ***********");
        System.out.println("Alice computes key material \t K=" + aliceKeyingMaterial.toString(16));
        System.out.println("Bob computes key material \t K=" + bobKeyingMaterial.toString(16));
        System.out.println();


        /*
         * You must derive a session key from the keying material applicable
         * to whatever encryption algorithm you want to use.
         */

        BigInteger aliceKey = deriveSessionKey(aliceKeyingMaterial);
        BigInteger bobKey = deriveSessionKey(bobKeyingMaterial);

        /*
         * At this point, you can stop and use the session keys if you want.
         * This is implicit key confirmation.
         *
         * If you want to explicitly confirm that the key material matches,
         * you can continue on and perform round 3.
         */

        /*
         * Round 3
         *
         * Alice and Bob each generate a round 3 payload, and send it to each other.
         */

        ECJPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);
        ECJPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        // -DM 11grad System.out.println
        System.out.println("************ Round 3 **************");
        System.out.println("Alice sends to Bob: ");
        System.out.println("MacTag=" + aliceRound3Payload.getMacTag().toString(16));
        System.out.println("");
        System.out.println("Bob sends to Alice: ");
        System.out.println("MacTag=" + bobRound3Payload.getMacTag().toString(16));
        System.out.println("");

        /*
         * Each participant must then validate the received payload for round 3
         */

        alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
        System.out.println("Alice checks MacTag: OK\n");

        bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);
        System.out.println("Bob checks MacTag: OK\n");

        System.out.println();
        System.out.println("MacTags validated, therefore the keying material matches.");
    }

    private static BigInteger deriveSessionKey(BigInteger keyingMaterial)
    {
        /*
         * You should use a secure key derivation function (KDF) to derive the session key.
         *
         * For the purposes of this example, I'm just going to use a hash of the keying material.
         */
        SavableDigest digest = SHA256Digest.newInstance();

        byte[] keyByteArray = keyingMaterial.toByteArray();

        byte[] output = new byte[digest.getDigestSize()];

        digest.update(keyByteArray, 0, keyByteArray.length);

        digest.doFinal(output, 0);

        return new BigInteger(output);
    }
}