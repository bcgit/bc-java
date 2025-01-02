package org.bouncycastle.crypto.agreement.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement;
import org.junit.jupiter.api.Test;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKEUtil;
import org.bouncycastle.crypto.agreement.ecjpake.ECSchnorrZKP;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKECurves;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKECurve;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ECJPAKEUtilTest
{
    private static final BigInteger TEN = BigInteger.valueOf(10);
    private static final BigInteger ONE = BigInteger.valueOf(1);

    @Test
    public void testValidateParticipantIdsDiffer()
    throws CryptoException
    {
        ECJPAKEUtil.validateParticipantIdsDiffer("a", "b");
        ECJPAKEUtil.validateParticipantIdsDiffer("a", "A");

        CryptoException exception = assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateParticipantIdsDiffer("a", "a");
        });
    }

    @Test
    public void testValidateParticipantIdsEqual()
    throws CryptoException
    {
        ECJPAKEUtil.validateParticipantIdsEqual("a", "a");

        CryptoException exception = assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateParticipantIdsEqual("a", "b");
        });
    }

    @Test
    public void testValidateMacTag()
    throws CryptoException
    {
        ECJPAKECurve curve1 = ECJPAKECurves.NIST_P256;

        SecureRandom random = new SecureRandom();
        Digest digest = SHA256Digest.newInstance();

        BigInteger x1 = ECJPAKEUtil.generateX1(curve1.getN(), random);
        BigInteger x2 = ECJPAKEUtil.generateX1(curve1.getN(), random);
        BigInteger x3 = ECJPAKEUtil.generateX1(curve1.getN(), random);
        BigInteger x4 = ECJPAKEUtil.generateX1(curve1.getN(), random);

        ECPoint gx1 = ECJPAKEUtil.calculateGx(curve1.getG(), x1);
        ECPoint gx2 = ECJPAKEUtil.calculateGx(curve1.getG(), x2);
        ECPoint gx3 = ECJPAKEUtil.calculateGx(curve1.getG(), x3);
        ECPoint gx4 = ECJPAKEUtil.calculateGx(curve1.getG(), x4);

        ECPoint gB = ECJPAKEUtil.calculateGA(gx3, gx1, gx2);

        BigInteger s = ECJPAKEUtil.calculateS(curve1.getN(), "password".toCharArray());

        BigInteger xs = ECJPAKEUtil.calculateX2s(curve1.getN(), x4, s);

        ECPoint B = ECJPAKEUtil.calculateA(gB, xs);

        BigInteger keyingMaterial = ECJPAKEUtil.calculateKeyingMaterial(curve1.getN(), gx4, x2, s, B);

        BigInteger macTag = ECJPAKEUtil.calculateMacTag("participantId", "partnerParticipantId", gx1, gx2, gx3, gx4, keyingMaterial, digest);

        ECJPAKEUtil.validateMacTag("partnerParticipantId", "participantId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag);

        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateMacTag("participantId", "partnerParticipantId", gx1, gx2, gx3, gx4, keyingMaterial, digest, macTag);
        });

        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateMacTag("participantId", "partnerParticipantId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag);
        });
    }

    @Test
    public void testValidateNotNull()
    throws CryptoException
    {
        ECJPAKEUtil.validateNotNull("a", "description");

        assertThrows(NullPointerException.class, () -> {
            ECJPAKEUtil.validateNotNull(null, "description");
        });
    }

    public void testValidateZeroKnowledgeProof()
    throws CryptoException
    {
        ECJPAKECurve curve1 = ECJPAKECurves.NIST_P256;

        SecureRandom random = new SecureRandom();
        Digest digest1 = SHA256Digest.newInstance();

        BigInteger x1 = ECJPAKEUtil.generateX1(curve1.getN(), random);
        ECPoint gx1 = ECJPAKEUtil.calculateGx(curve1.getG(), x1);
        String participantId1 = "participant1";

        ECSchnorrZKP zkp1 = ECJPAKEUtil.calculateZeroKnowledgeProof(curve1.getG(), curve1.getN(), x1, gx1, digest1, participantId1, random);

        // should succeed
        ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), gx1, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);

        // wrong group
        ECJPAKECurve curve2 = ECJPAKECurves.NIST_P256; // make sure to change this to an incorrect group
        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve2.getG(), gx1, zkp1, curve2.getQ(), curve2.getN(), curve2.getCurve(), curve2.getH(), participantId1, digest1);
        });

        // wrong digest
        Digest digest2 = new SHA1Digest();
        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), gx1, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest2);
        });

        // wrong participant
        String participantId2 = "participant2";
        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), gx1, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId2, digest1);
        });

        // wrong gx
        BigInteger x2 = ECJPAKEUtil.generateX1(curve1.getN(), random);
        ECPoint gx2 = ECJPAKEUtil.calculateGx(curve1.getG(), x2);
        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), gx2, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
        });


        // wrong zkp, we need to change the zkp in some way to test if it catches it
        ECSchnorrZKP zkp2 = ECJPAKEUtil.calculateZeroKnowledgeProof(curve1.getG(), curve1.getN(), x2, gx2, digest1, participantId1, random);        
        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), gx1, zkp2, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
        });

        // gx <= Infinity
        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), curve1.getCurve().getInfinity(), zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
        });
        
        // (x,y) elements for Gx are not in Fq ie: not in [0,q-1]
        ECCurve.Fp curve = (ECCurve.Fp) curve1.getCurve();
        ECPoint invalidGx_1 = curve.createPoint(ONE.negate(), ONE);
        ECPoint invalidGx_2 = curve.createPoint(ONE, ONE.negate());
        ECPoint invalidGx_3 = curve.createPoint(curve1.getQ(), ONE);
        ECPoint invalidGx_4 = curve.createPoint(ONE, curve1.getQ());
        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), invalidGx_1, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
        });

        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), invalidGx_2, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
        });

        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), invalidGx_3, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
        });

        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), invalidGx_4, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId1, digest1);
        });

        // gx is not on the curve
        ECPoint invalidPoint = curve.createPoint(ONE, ONE);//Must come back and test this since (1,1) may exist on certain curves. Not for p256 though.
        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), invalidPoint, zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId2, digest1);
        });
    
        /*  gx is such that n*gx == infinity
         *  Taking gx as any multiple of the generator G will create such a point
        */

        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), curve1.getG(), zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId2, digest1);
        });

        /*  V is not a point on the curve
         *  i.e. V != G*r + X*h
        */

        assertThrows(CryptoException.class, () -> {
            ECJPAKEUtil.validateZeroKnowledgeProof(curve1.getG(), curve.createPoint(ONE, ONE), zkp1, curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(), participantId2, digest1);
        });
    }
}