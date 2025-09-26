package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;


public class Owl_UtilTest
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    @Test
    public void testCalculateGA() throws CryptoException
    {
        // test gx is infinity

        Owl_Curve curve = Owl_Curves.NIST_P256;
        SecureRandom random = new SecureRandom();

        ECPoint gx1 = Owl_Util.calculateGx(curve.getG(), Owl_Util.generateX1(curve.getN(), random));
        ECPoint gx2 = Owl_Util.calculateGx(curve.getG(), Owl_Util.generateX1(curve.getN(), random));
        // gx3 is infinity
        assertThrows(CryptoException.class,
            () -> Owl_Util.calculateGA(gx1, gx2, curve.getCurve().getInfinity())
        );

        // gx2 is infinity
        assertThrows(CryptoException.class,
            () -> Owl_Util.calculateGA(gx1, curve.getCurve().getInfinity(), gx2)
        );

        // gx1 is infinity
        assertThrows(CryptoException.class,
            () -> Owl_Util.calculateGA(curve.getCurve().getInfinity(), gx2, gx1)
        );
    }
    @Test
    public void testValidateParticipantIdsDiffer() throws CryptoException
    {
        Owl_Util.validateParticipantIdsDiffer("a", "b");
        Owl_Util.validateParticipantIdsDiffer("a", "A");

        assertThrows(CryptoException.class, () -> Owl_Util.validateParticipantIdsDiffer("a", "a"));
    }
    @Test
    public void testValidateParticipantIdsEqual() throws CryptoException
    {
        Owl_Util.validateParticipantIdsEqual("a", "a");

        assertThrows(CryptoException.class, () -> Owl_Util.validateParticipantIdsEqual("a", "b"));
    }

    @Test
    void testValidateMacTag() throws CryptoException {
        Owl_Curve curve1 = Owl_Curves.NIST_P256;

        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();  // <- if you actually have SHA256Digest.newInstance(), swap back

        BigInteger x1 = Owl_Util.generateX1(curve1.getN(), random);
        BigInteger x2 = Owl_Util.generateX1(curve1.getN(), random);
        BigInteger x3 = Owl_Util.generateX1(curve1.getN(), random);
        BigInteger x4 = Owl_Util.generateX1(curve1.getN(), random);

        ECPoint gx1 = Owl_Util.calculateGx(curve1.getG(), x1);
        ECPoint gx2 = Owl_Util.calculateGx(curve1.getG(), x2);
        ECPoint gx3 = Owl_Util.calculateGx(curve1.getG(), x3);
        ECPoint gx4 = Owl_Util.calculateGx(curve1.getG(), x4);

        ECPoint alphaG = Owl_Util.calculateGA(gx4, gx1, gx2);

        BigInteger pi = Owl_Util.calculatePi(
            curve1.getN(),
            Owl_Util.calculateT(curve1.getN(), "password", digest),
            digest
        );

        BigInteger x4pi = Owl_Util.calculateX2s(curve1.getN(), x4, pi);
        BigInteger x2pi = Owl_Util.calculateX2s(curve1.getN(), x2, pi);

        ECPoint alpha = Owl_Util.calculateA(alphaG, x2pi);
        ECPoint rawKey = Owl_Util.calculateKeyingMaterial(gx2, x4, x4pi, alpha);

        BigInteger keyingMaterial = rawKey.normalize().getAffineXCoord().toBigInteger();

        BigInteger macTag = Owl_Util.calculateMacTag(
            "serverId", "clientId", gx3, gx4, gx1, gx2, keyingMaterial, digest
        );

        //Valid case should not throw
        assertDoesNotThrow(() ->
            Owl_Util.validateMacTag("clientId", "serverId", gx1, gx2, gx3, gx4, keyingMaterial, digest, macTag)
        );

        //Validating own macTag should fail
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateMacTag("serverId", "clientId", gx1, gx2, gx3, gx4, keyingMaterial, digest, macTag)
        );

        //Switched participant ids should fail
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateMacTag("serverId", "clientId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag)
        );
    }

    @Test
    public void testValidateNotNull()
        throws NullPointerException
    {
        Owl_Util.validateNotNull("a", "description");

        assertThrows(NullPointerException.class, () -> Owl_Util.validateNotNull(null, "description"));
    }
    @Test
    public void testValidateR()
        throws CryptoException
    {
        Owl_Curve curve = Owl_Curves.NIST_P256;
        Digest digest  = SHA256Digest.newInstance();
        SecureRandom random = new SecureRandom();
        ECPoint g = curve.getG();
        BigInteger n = curve.getN();
        BigInteger t = Owl_Util.calculateT(n, "usernameAndPassword", digest);
        ECPoint gt = Owl_Util.calculateGx(g, t);
        ECPoint gx1 = Owl_Util.calculateGx(g, Owl_Util.generateX1(n, random));
        BigInteger h = Owl_Util.generateX1(n, random);
        BigInteger r = Owl_Util.calculateR(Owl_Util.generateX1(n, random), t, h, n);
        //incorrect r
        assertThrows(CryptoException.class, () -> Owl_Util.validateR(r, gx1, h, gt, g, n));
    }
    @Test
    public void testvalidateZeroknowledgeProof()
        throws CryptoException
    {
        Owl_Curve curve1 = Owl_Curves.NIST_P256;

        SecureRandom random = new SecureRandom();
        Digest digest1 = SHA256Digest.newInstance();

        BigInteger x1 = Owl_Util.generateX1(curve1.getN(), random);
        ECPoint gx1 = Owl_Util.calculateGx(curve1.getG(), x1);
        String participantId1 = "participant1";

        ECSchnorrZKP zkp1 = Owl_Util.calculateZeroknowledgeProof(curve1.getG(), curve1.getN(), x1, gx1, digest1, participantId1, random);

        //Should succeed
        assertDoesNotThrow(() ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), gx1, zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1
            )
        );

        //Wrong group
        Owl_Curve curve2 = Owl_Curves.NIST_P384;
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve2.getG(), gx1, zkp1,
                curve2.getQ(), curve2.getN(), curve2.getCurve(), curve2.getH(),
                participantId1, digest1
            )
        );

        //Wrong digest
        Digest digest2 = new SHA1Digest();
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), gx1, zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest2
            )
        );

        //Wrong participant ID
        String participantId2 = "participant2";
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), gx1, zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId2, digest1
            )
        );

        //Wrong gx
        BigInteger x2 = Owl_Util.generateX1(curve1.getN(), random);
        ECPoint gx2 = Owl_Util.calculateGx(curve1.getG(), x2);
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), gx2, zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1
            )
        );

        //Wrong ZKP
        ECSchnorrZKP zkp2 = Owl_Util.calculateZeroknowledgeProof(
            curve1.getG(), curve1.getN(), x2, gx2, digest1, participantId1, random
        );
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), gx1, zkp2,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1
            )
        );

        //gx is Infinity
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), curve1.getCurve().getInfinity(), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1
            )
        );

        //Invalid coordinates (outside Fq)
        ECCurve.AbstractFp curve = curve1.getCurve();
        assertThrows(Exception.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(ONE.negate(), ONE), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1
            )
        );
        assertThrows(Exception.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(ONE, ONE.negate()), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1
            )
        );
        assertThrows(Exception.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(curve1.getQ(), ONE), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1
            )
        );
        assertThrows(Exception.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(ONE, curve1.getQ()), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1
            )
        );

        //gx not on curve
        ECPoint invalidPoint = curve.createPoint(ONE, ONE);
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), invalidPoint, zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId2, digest1
            )
        );

        //n*gx == infinity (using generator)
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), curve1.getG(), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId2, digest1
            )
        );

        //V not on curve (fake)
        assertThrows(CryptoException.class, () ->
            Owl_Util.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(ONE, ONE), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId2, digest1
            )
        );
    }
}