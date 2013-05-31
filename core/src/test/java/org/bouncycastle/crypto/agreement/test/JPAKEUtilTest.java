package org.bouncycastle.crypto.agreement.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroup;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroups;
import org.bouncycastle.crypto.agreement.jpake.JPAKEUtil;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class JPAKEUtilTest
    extends TestCase
{
    private static final BigInteger TEN = BigInteger.valueOf(10);

    public void testValidateGx4()
        throws CryptoException
    {
        JPAKEUtil.validateGx4(TEN);

        try
        {
            JPAKEUtil.validateGx4(BigInteger.ONE);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateGa()
        throws CryptoException
    {
        JPAKEUtil.validateGa(TEN);

        try
        {
            JPAKEUtil.validateGa(BigInteger.ONE);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateParticipantIdsDiffer()
        throws CryptoException
    {
        JPAKEUtil.validateParticipantIdsDiffer("a", "b");
        JPAKEUtil.validateParticipantIdsDiffer("a", "A");

        try
        {
            JPAKEUtil.validateParticipantIdsDiffer("a", "a");
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateParticipantIdsEqual()
        throws CryptoException
    {
        JPAKEUtil.validateParticipantIdsEqual("a", "a");

        try
        {
            JPAKEUtil.validateParticipantIdsEqual("a", "b");
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateMacTag()
        throws CryptoException
    {
        JPAKEPrimeOrderGroup pg1 = JPAKEPrimeOrderGroups.SUN_JCE_1024;

        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();

        BigInteger x1 = JPAKEUtil.generateX1(pg1.getQ(), random);
        BigInteger x2 = JPAKEUtil.generateX2(pg1.getQ(), random);
        BigInteger x3 = JPAKEUtil.generateX1(pg1.getQ(), random);
        BigInteger x4 = JPAKEUtil.generateX2(pg1.getQ(), random);

        BigInteger gx1 = JPAKEUtil.calculateGx(pg1.getP(), pg1.getG(), x1);
        BigInteger gx2 = JPAKEUtil.calculateGx(pg1.getP(), pg1.getG(), x2);
        BigInteger gx3 = JPAKEUtil.calculateGx(pg1.getP(), pg1.getG(), x3);
        BigInteger gx4 = JPAKEUtil.calculateGx(pg1.getP(), pg1.getG(), x4);

        BigInteger gB = JPAKEUtil.calculateGA(pg1.getP(), gx3, gx1, gx2);

        BigInteger s = JPAKEUtil.calculateS("password".toCharArray());

        BigInteger xs = JPAKEUtil.calculateX2s(pg1.getQ(), x4, s);

        BigInteger B = JPAKEUtil.calculateA(pg1.getP(), pg1.getQ(), gB, xs);

        BigInteger keyingMaterial = JPAKEUtil.calculateKeyingMaterial(pg1.getP(), pg1.getQ(), gx4, x2, s, B);

        BigInteger macTag = JPAKEUtil.calculateMacTag("participantId", "partnerParticipantId", gx1, gx2, gx3, gx4, keyingMaterial, digest);

        // should succed
        JPAKEUtil.validateMacTag("partnerParticipantId", "participantId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag);

        // validating own macTag (as opposed to the other party's mactag)
        try
        {
            JPAKEUtil.validateMacTag("participantId", "partnerParticipantId", gx1, gx2, gx3, gx4, keyingMaterial, digest, macTag);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // participant ids switched
        try
        {
            JPAKEUtil.validateMacTag("participantId", "partnerParticipantId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateNotNull()
    {
        JPAKEUtil.validateNotNull("a", "description");

        try
        {
            JPAKEUtil.validateNotNull(null, "description");
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }
    }

    public void testValidateZeroKnowledgeProof()
        throws CryptoException
    {
        JPAKEPrimeOrderGroup pg1 = JPAKEPrimeOrderGroups.SUN_JCE_1024;

        SecureRandom random = new SecureRandom();
        Digest digest1 = new SHA256Digest();

        BigInteger x1 = JPAKEUtil.generateX1(pg1.getQ(), random);
        BigInteger gx1 = JPAKEUtil.calculateGx(pg1.getP(), pg1.getG(), x1);
        String participantId1 = "participant1";

        BigInteger[] zkp1 = JPAKEUtil.calculateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), gx1, x1, participantId1, digest1, random);

        // should succeed
        JPAKEUtil.validateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), gx1, zkp1, participantId1, digest1);

        // wrong group
        JPAKEPrimeOrderGroup pg2 = JPAKEPrimeOrderGroups.NIST_3072;
        try
        {
            JPAKEUtil.validateZeroKnowledgeProof(pg2.getP(), pg2.getQ(), pg2.getG(), gx1, zkp1, participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // wrong digest
        Digest digest2 = new SHA1Digest();
        try
        {
            JPAKEUtil.validateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), gx1, zkp1, participantId1, digest2);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // wrong participant
        String participantId2 = "participant2";
        try
        {
            JPAKEUtil.validateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), gx1, zkp1, participantId2, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // wrong gx
        BigInteger x2 = JPAKEUtil.generateX1(pg1.getQ(), random);
        BigInteger gx2 = JPAKEUtil.calculateGx(pg1.getP(), pg1.getG(), x2);
        try
        {
            JPAKEUtil.validateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), gx2, zkp1, participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // wrong zkp
        BigInteger[] zkp2 = JPAKEUtil.calculateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), gx2, x2, participantId1, digest1, random);
        try
        {
            JPAKEUtil.validateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), gx1, zkp2, participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // gx <= 0
        try
        {
            JPAKEUtil.validateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), BigInteger.ZERO, zkp1, participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // gx >= p
        try
        {
            JPAKEUtil.validateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), pg1.getP(), zkp1, participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // gx mod q == 1
        try
        {
            JPAKEUtil.validateZeroKnowledgeProof(pg1.getP(), pg1.getQ(), pg1.getG(), pg1.getQ().add(BigInteger.ONE), zkp1, participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }
}
