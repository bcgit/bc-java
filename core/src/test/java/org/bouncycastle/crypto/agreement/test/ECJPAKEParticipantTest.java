package org.bouncycastle.crypto.agreement.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKEParticipant;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKECurve;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKECurves;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound1Payload;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound2Payload;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound3Payload;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKEUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.jupiter.api.Test;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class ECJPAKEParticipantTest {

    @Test
    public void testConstruction() 
    throws CryptoException
    {
        ECJPAKECurve curve = ECJPAKECurves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String participantId = "participantId";
        char[] password = "password".toCharArray();

        new ECJPAKEParticipant(participantId, password, curve, digest, random);

        // null participantID
        assertThrows(NullPointerException.class, () -> {
            new ECJPAKEParticipant(null, password, curve, digest, random);
        });

        // null password
        assertThrows(NullPointerException.class, () -> {
            new ECJPAKEParticipant(participantId, null, curve, digest, random);
        });

        // empty password
        assertThrows(IllegalArgumentException.class, () -> {
            new ECJPAKEParticipant(participantId, "".toCharArray(), curve, digest, random);
        });

        // null curve
        assertThrows(NullPointerException.class, () -> {
            new ECJPAKEParticipant(participantId, password, null, digest, random);
        });

        // null digest
        assertThrows(NullPointerException.class, () -> {
            new ECJPAKEParticipant(participantId, password, curve, null, random);
        });

        // null random
        assertThrows(NullPointerException.class, () -> {
            new ECJPAKEParticipant(participantId, password, curve, digest, null);
        });
    }

    @Test 
    public void testSuccessfulExchange()
    throws CryptoException
    {

        ECJPAKEParticipant alice = createAlice();
        ECJPAKEParticipant bob = createBob();

        ExchangeAfterRound2Creation exchange = runExchangeUntilRound2Creation(alice, bob);

        alice.validateRound2PayloadReceived(exchange.bobRound2Payload);
        bob.validateRound2PayloadReceived(exchange.aliceRound2Payload);

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        ECJPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);
        ECJPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
        bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);

        assertEquals(aliceKeyingMaterial, bobKeyingMaterial);

    }

    @Test
    public void testIncorrectPassword() 
    throws CryptoException
    {
        ECJPAKEParticipant alice = createAlice();
        ECJPAKEParticipant bob = createBobWithWrongPassword();

        ExchangeAfterRound2Creation exchange = runExchangeUntilRound2Creation(alice, bob);

        alice.validateRound2PayloadReceived(exchange.bobRound2Payload);
        bob.validateRound2PayloadReceived(exchange.aliceRound2Payload);

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        ECJPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);
        ECJPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        // Validate incorrect passwords result in a CryptoException
        assertThrows(CryptoException.class, () -> {
            alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
        });

        assertThrows(CryptoException.class, () -> {
            bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);
        });
    }

    @Test
    public void testStateValidation() 
    throws CryptoException
    {

        ECJPAKEParticipant alice = createAlice();
        ECJPAKEParticipant bob = createBob();

        // We're testing alice here. Bob is just used for help.

        // START ROUND 1 CHECKS

        assertEquals(ECJPAKEParticipant.STATE_INITIALIZED, alice.getState());

        // create round 2 before round 1
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound2PayloadToSend();
        });

        ECJPAKERound1Payload aliceRound1Payload = alice.createRound1PayloadToSend();

        assertEquals(ECJPAKEParticipant.STATE_ROUND_1_CREATED, alice.getState());

        // create round 1 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound1PayloadToSend();
        });

        // create round 2 before validating round 1
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound2PayloadToSend();
        });

        // validate round 2 before validating round 1
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound2PayloadReceived(null);
        });

        ECJPAKERound1Payload bobRound1Payload = bob.createRound1PayloadToSend();

        alice.validateRound1PayloadReceived(bobRound1Payload);

        assertEquals(ECJPAKEParticipant.STATE_ROUND_1_VALIDATED, alice.getState());

        // validate round 1 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound1PayloadReceived(bobRound1Payload);
        });

        bob.validateRound1PayloadReceived(aliceRound1Payload);

        // START ROUND 2 CHECKS

        ECJPAKERound2Payload aliceRound2Payload = alice.createRound2PayloadToSend();

        assertEquals(ECJPAKEParticipant.STATE_ROUND_2_CREATED, alice.getState());

        // create round 2 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound2PayloadToSend();
        });

        // create key before validating round 2
        assertThrows(IllegalStateException.class, () -> {
            alice.calculateKeyingMaterial();
        });

        // validate round 3 before validating round 2
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound3PayloadReceived(null, null);
        });

        ECJPAKERound2Payload bobRound2Payload = bob.createRound2PayloadToSend();

        alice.validateRound2PayloadReceived(bobRound2Payload);

        assertEquals(ECJPAKEParticipant.STATE_ROUND_2_VALIDATED, alice.getState());

        // validate round 2 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound2PayloadReceived(bobRound2Payload);
        });

        bob.validateRound2PayloadReceived(aliceRound2Payload);

        // create round 3 before calculating key
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound3PayloadToSend(BigInteger.ONE);
        });

        // START KEY CALCULATION CHECKS

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();

        assertEquals(ECJPAKEParticipant.STATE_KEY_CALCULATED, alice.getState());

        // calculate key twice
        assertThrows(IllegalStateException.class, () -> {
            alice.calculateKeyingMaterial();
        });

        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        // START ROUND 3 CHECKS

        ECJPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);

        assertEquals(ECJPAKEParticipant.STATE_ROUND_3_CREATED, alice.getState());

        // create round 3 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound3PayloadToSend(aliceKeyingMaterial);
        });

        ECJPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);

        assertEquals(ECJPAKEParticipant.STATE_ROUND_3_VALIDATED, alice.getState());

        // validate round 3 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
        });

        bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);


    }

    @Test
    public void testValidateRound1PayloadReceived() 
    throws CryptoException
    {

        // We're testing alice here. Bob is just used for help.
        ECJPAKERound1Payload bobRound1Payload = createBob().createRound1PayloadToSend();

        // should succeed
        createAlice().validateRound1PayloadReceived(bobRound1Payload);

        // alice verifies alice's payload
        assertThrows(CryptoException.class, () -> {
            ECJPAKEParticipant alice = createAlice();
            alice.validateRound1PayloadReceived(alice.createRound1PayloadToSend());
        });

        // g^x4 = infinity
        ECJPAKECurve curve = ECJPAKECurves.NIST_P256;
        assertThrows(CryptoException.class, () -> {
            createAlice().validateRound1PayloadReceived(new ECJPAKERound1Payload(
                bobRound1Payload.getParticipantId(),
                bobRound1Payload.getGx1(),
                curve.getCurve().getInfinity(),
                bobRound1Payload.getKnowledgeProofForX1(),
                bobRound1Payload.getKnowledgeProofForX2()));
        });

        // zero knowledge proof for x3 fails
        assertThrows(CryptoException.class, () -> {
            ECJPAKERound1Payload bobRound1Payload2 = createBob().createRound1PayloadToSend();
            createAlice().validateRound1PayloadReceived(new ECJPAKERound1Payload(
                bobRound1Payload.getParticipantId(),
                bobRound1Payload.getGx1(),
                bobRound1Payload.getGx2(),
                bobRound1Payload2.getKnowledgeProofForX1(),
                bobRound1Payload.getKnowledgeProofForX2()));
        });

        // zero knowledge proof for x4 fails
        assertThrows(CryptoException.class, () -> {
            ECJPAKERound1Payload bobRound1Payload2 = createBob().createRound1PayloadToSend();
            createAlice().validateRound1PayloadReceived(new ECJPAKERound1Payload(
                bobRound1Payload.getParticipantId(),
                bobRound1Payload.getGx1(),
                bobRound1Payload.getGx2(),
                bobRound1Payload.getKnowledgeProofForX1(),
                bobRound1Payload2.getKnowledgeProofForX2()));
        });
    }

    @Test
    public void testValidateRound2PayloadReceived() 
    throws CryptoException
    {

        // We're testing alice here. Bob is just used for help.

        // should succeed
        ExchangeAfterRound2Creation exchange1 = runExchangeUntilRound2Creation(createAlice(), createBob());
        exchange1.alice.validateRound2PayloadReceived(exchange1.bobRound2Payload);

        // alice verifies alice's payload
        ExchangeAfterRound2Creation exchange2 = runExchangeUntilRound2Creation(createAlice(), createBob());
        assertThrows(CryptoException.class, () -> {
            exchange2.alice.validateRound2PayloadReceived(exchange2.aliceRound2Payload);
        });

        // wrong z
        ExchangeAfterRound2Creation exchange3 = runExchangeUntilRound2Creation(createAlice(), createBob());
        ExchangeAfterRound2Creation exchange4 = runExchangeUntilRound2Creation(createAlice(), createBob());
        assertThrows(CryptoException.class, () -> {
            exchange3.alice.validateRound2PayloadReceived(exchange4.bobRound2Payload);
        });
    }

    private static class ExchangeAfterRound2Creation {

        public ECJPAKEParticipant alice;
        public ECJPAKERound2Payload aliceRound2Payload;
        public ECJPAKERound2Payload bobRound2Payload;

        public ExchangeAfterRound2Creation(
            ECJPAKEParticipant alice,
            ECJPAKERound2Payload aliceRound2Payload,
            ECJPAKERound2Payload bobRound2Payload)
        {
            this.alice = alice;
            this.aliceRound2Payload = aliceRound2Payload;
            this.bobRound2Payload = bobRound2Payload;
        }

    }

    private ExchangeAfterRound2Creation runExchangeUntilRound2Creation(ECJPAKEParticipant alice, ECJPAKEParticipant bob) 
    throws CryptoException
    {
        
        ECJPAKERound1Payload aliceRound1Payload = alice.createRound1PayloadToSend();
        ECJPAKERound1Payload bobRound1Payload = bob.createRound1PayloadToSend();

        alice.validateRound1PayloadReceived(bobRound1Payload);
        bob.validateRound1PayloadReceived(aliceRound1Payload);

        ECJPAKERound2Payload aliceRound2Payload = alice.createRound2PayloadToSend();
        ECJPAKERound2Payload bobRound2Payload = bob.createRound2PayloadToSend();

        return new ExchangeAfterRound2Creation(
            alice,
            aliceRound2Payload,
            bobRound2Payload);
    }

    private ECJPAKEParticipant createAlice()
    {
        return createParticipant("alice", "password");
    }

    private ECJPAKEParticipant createBob()
    {
        return createParticipant("bob", "password");
    }

    private ECJPAKEParticipant createBobWithWrongPassword()
    {
        return createParticipant("bob", "wrong");
    }

    private ECJPAKEParticipant createParticipant(String participantId, String password)
    {
        return new ECJPAKEParticipant(
            participantId,
            password.toCharArray(),
            ECJPAKECurves.NIST_P256);
    }
}