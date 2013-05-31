package org.bouncycastle.crypto.agreement.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroup;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroups;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound1Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound2Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound3Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKEUtil;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class JPAKEParticipantTest
    extends TestCase
{

    public void testConstruction()
        throws CryptoException
    {
        JPAKEPrimeOrderGroup group = JPAKEPrimeOrderGroups.SUN_JCE_1024;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String participantId = "participantId";
        char[] password = "password".toCharArray();

        // should succeed
        new JPAKEParticipant(participantId, password, group, digest, random);

        // null participantId
        try
        {
            new JPAKEParticipant(null, password, group, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null password
        try
        {
            new JPAKEParticipant(participantId, null, group, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // empty password
        try
        {
            new JPAKEParticipant(participantId, "".toCharArray(), group, digest, random);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // null group
        try
        {
            new JPAKEParticipant(participantId, password, null, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null digest
        try
        {
            new JPAKEParticipant(participantId, password, group, null, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null random
        try
        {
            new JPAKEParticipant(participantId, password, group, digest, null);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }
    }

    public void testSuccessfulExchange()
        throws CryptoException
    {

        JPAKEParticipant alice = createAlice();
        JPAKEParticipant bob = createBob();

        ExchangeAfterRound2Creation exchange = runExchangeUntilRound2Creation(alice, bob);

        alice.validateRound2PayloadReceived(exchange.bobRound2Payload);
        bob.validateRound2PayloadReceived(exchange.aliceRound2Payload);

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        JPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);
        JPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
        bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);

        assertEquals(aliceKeyingMaterial, bobKeyingMaterial);

    }

    public void testIncorrectPassword()
        throws CryptoException
    {

        JPAKEParticipant alice = createAlice();
        JPAKEParticipant bob = createBobWithWrongPassword();

        ExchangeAfterRound2Creation exchange = runExchangeUntilRound2Creation(alice, bob);

        alice.validateRound2PayloadReceived(exchange.bobRound2Payload);
        bob.validateRound2PayloadReceived(exchange.aliceRound2Payload);

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        JPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);
        JPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        try
        {
            alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        try
        {
            bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

    }

    /**
     * Tests that {@link JPAKEParticipant} throws appropriate {@link IllegalStateException}s
     * when the methods are called in the wrong order.
     */
    public void testStateValidation()
        throws CryptoException
    {

        JPAKEParticipant alice = createAlice();
        JPAKEParticipant bob = createBob();

        // We're testing alice here. Bob is just used for help.

        // START ROUND 1 CHECKS

        assertEquals(JPAKEParticipant.STATE_INITIALIZED, alice.getState());

        // create round 2 before round 1
        try
        {
            alice.createRound2PayloadToSend();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        JPAKERound1Payload aliceRound1Payload = alice.createRound1PayloadToSend();

        assertEquals(JPAKEParticipant.STATE_ROUND_1_CREATED, alice.getState());

        // create round 1 payload twice
        try
        {
            alice.createRound1PayloadToSend();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // create round 2 before validating round 1
        try
        {
            alice.createRound2PayloadToSend();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // validate round 2 before validating round 1
        try
        {
            alice.validateRound2PayloadReceived(null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        JPAKERound1Payload bobRound1Payload = bob.createRound1PayloadToSend();

        alice.validateRound1PayloadReceived(bobRound1Payload);

        assertEquals(JPAKEParticipant.STATE_ROUND_1_VALIDATED, alice.getState());

        // validate round 1 payload twice
        try
        {
            alice.validateRound1PayloadReceived(bobRound1Payload);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        bob.validateRound1PayloadReceived(aliceRound1Payload);

        // START ROUND 2 CHECKS

        JPAKERound2Payload aliceRound2Payload = alice.createRound2PayloadToSend();

        assertEquals(JPAKEParticipant.STATE_ROUND_2_CREATED, alice.getState());

        // create round 2 payload twice
        try
        {
            alice.createRound2PayloadToSend();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // create key before validating round 2
        try
        {
            alice.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // validate round 3 before validating round 2
        try
        {
            alice.validateRound3PayloadReceived(null, null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        JPAKERound2Payload bobRound2Payload = bob.createRound2PayloadToSend();

        alice.validateRound2PayloadReceived(bobRound2Payload);

        assertEquals(JPAKEParticipant.STATE_ROUND_2_VALIDATED, alice.getState());

        // validate round 2 payload twice
        try
        {
            alice.validateRound2PayloadReceived(bobRound2Payload);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        bob.validateRound2PayloadReceived(aliceRound2Payload);

        // create round 3 before calculating key
        try
        {
            alice.createRound3PayloadToSend(BigInteger.ONE);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // START KEY CALCULATION CHECKS

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();

        assertEquals(JPAKEParticipant.STATE_KEY_CALCULATED, alice.getState());

        // calculate key twice
        try
        {
            alice.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        // START ROUND 3 CHECKS

        JPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);

        assertEquals(JPAKEParticipant.STATE_ROUND_3_CREATED, alice.getState());

        // create round 3 payload twice
        try
        {
            alice.createRound3PayloadToSend(aliceKeyingMaterial);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        JPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);

        assertEquals(JPAKEParticipant.STATE_ROUND_3_VALIDATED, alice.getState());

        // validate round 3 payload twice
        try
        {
            alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);


    }

    /**
     * Tests that {@link JPAKEParticipant#validateRound1PayloadReceived(JPAKERound1Payload)}
     * calls the appropriate validate methods in {@link JPAKEUtil}.
     * Note that {@link JPAKEUtilTest} tests the individual validate methods
     * called by {@link JPAKEParticipant} more extensively.
     */
    public void testValidateRound1PayloadReceived()
        throws CryptoException
    {

        // We're testing alice here. Bob is just used for help.

        JPAKERound1Payload bobRound1Payload = createBob().createRound1PayloadToSend();

        // should succeed
        createAlice().validateRound1PayloadReceived(bobRound1Payload);

        // alice verifies alice's payload
        try
        {
            JPAKEParticipant alice = createAlice();
            alice.validateRound1PayloadReceived(alice.createRound1PayloadToSend());
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // g^x4 == 1
        try
        {
            createAlice().validateRound1PayloadReceived(new JPAKERound1Payload(
                bobRound1Payload.getParticipantId(),
                bobRound1Payload.getGx1(),
                BigInteger.ONE,
                bobRound1Payload.getKnowledgeProofForX1(),
                bobRound1Payload.getKnowledgeProofForX2()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // zero knowledge proof for x3 fails
        try
        {
            JPAKERound1Payload bobRound1Payload2 = createBob().createRound1PayloadToSend();
            createAlice().validateRound1PayloadReceived(new JPAKERound1Payload(
                bobRound1Payload.getParticipantId(),
                bobRound1Payload.getGx1(),
                bobRound1Payload.getGx2(),
                bobRound1Payload2.getKnowledgeProofForX1(),
                bobRound1Payload.getKnowledgeProofForX2()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // zero knowledge proof for x4 fails
        try
        {
            JPAKERound1Payload bobRound1Payload2 = createBob().createRound1PayloadToSend();
            createAlice().validateRound1PayloadReceived(new JPAKERound1Payload(
                bobRound1Payload.getParticipantId(),
                bobRound1Payload.getGx1(),
                bobRound1Payload.getGx2(),
                bobRound1Payload.getKnowledgeProofForX1(),
                bobRound1Payload2.getKnowledgeProofForX2()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

    }

    /**
     * Tests that {@link JPAKEParticipant#validateRound2PayloadReceived(JPAKERound2Payload)}
     * calls the appropriate validate methods in {@link JPAKEUtil}.
     * Note that {@link JPAKEUtilTest} tests the individual validate methods
     * called by {@link JPAKEParticipant} more extensively.
     */
    public void testValidateRound2PayloadReceived()
        throws CryptoException
    {

        // We're testing alice here. Bob is just used for help.

        // should succeed
        ExchangeAfterRound2Creation exchange1 = runExchangeUntilRound2Creation(createAlice(), createBob());
        exchange1.alice.validateRound2PayloadReceived(exchange1.bobRound2Payload);

        // alice verifies alice's payload
        ExchangeAfterRound2Creation exchange2 = runExchangeUntilRound2Creation(createAlice(), createBob());
        try
        {
            exchange2.alice.validateRound2PayloadReceived(exchange2.aliceRound2Payload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // wrong z
        ExchangeAfterRound2Creation exchange3 = runExchangeUntilRound2Creation(createAlice(), createBob());
        ExchangeAfterRound2Creation exchange4 = runExchangeUntilRound2Creation(createAlice(), createBob());
        try
        {
            exchange3.alice.validateRound2PayloadReceived(exchange4.bobRound2Payload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

    }

    private static class ExchangeAfterRound2Creation
    {

        public JPAKEParticipant alice;
        public JPAKERound2Payload aliceRound2Payload;
        public JPAKERound2Payload bobRound2Payload;

        public ExchangeAfterRound2Creation(
            JPAKEParticipant alice,
            JPAKERound2Payload aliceRound2Payload,
            JPAKERound2Payload bobRound2Payload)
        {
            this.alice = alice;
            this.aliceRound2Payload = aliceRound2Payload;
            this.bobRound2Payload = bobRound2Payload;
        }

    }

    private ExchangeAfterRound2Creation runExchangeUntilRound2Creation(JPAKEParticipant alice, JPAKEParticipant bob)
        throws CryptoException
    {
        JPAKERound1Payload aliceRound1Payload = alice.createRound1PayloadToSend();
        JPAKERound1Payload bobRound1Payload = bob.createRound1PayloadToSend();

        alice.validateRound1PayloadReceived(bobRound1Payload);
        bob.validateRound1PayloadReceived(aliceRound1Payload);

        JPAKERound2Payload aliceRound2Payload = alice.createRound2PayloadToSend();
        JPAKERound2Payload bobRound2Payload = bob.createRound2PayloadToSend();

        return new ExchangeAfterRound2Creation(
            alice,
            aliceRound2Payload,
            bobRound2Payload);
    }

    private JPAKEParticipant createAlice()
    {
        return createParticipant("alice", "password");
    }

    private JPAKEParticipant createBob()
    {
        return createParticipant("bob", "password");
    }

    private JPAKEParticipant createBobWithWrongPassword()
    {
        return createParticipant("bob", "wrong");
    }

    private JPAKEParticipant createParticipant(String participantId, String password)
    {
        return new JPAKEParticipant(
            participantId,
            password.toCharArray(),
            JPAKEPrimeOrderGroups.SUN_JCE_1024);
    }

}
