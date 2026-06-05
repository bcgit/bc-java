package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;


public class OwlUtilTest
    extends TestCase
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    public void testCalculateGA()
        throws CryptoException
    {
        // test gx is infinity
        OwlCurve curve = OwlCurves.NIST_P256;
        SecureRandom random = new SecureRandom();

        ECPoint gx1 = OwlUtil.calculateGx(curve.getG(), OwlUtil.generateX1(curve.getN(), random));
        ECPoint gx2 = OwlUtil.calculateGx(curve.getG(), OwlUtil.generateX1(curve.getN(), random));

        // gx3 is infinity
        try
        {
            OwlUtil.calculateGA(gx1, gx2, curve.getCurve().getInfinity());
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // gx2 is infinity
        try
        {
            OwlUtil.calculateGA(gx1, curve.getCurve().getInfinity(), gx2);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // gx1 is infinity
        try
        {
            OwlUtil.calculateGA(curve.getCurve().getInfinity(), gx2, gx1);
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
        OwlUtil.validateParticipantIdsDiffer("a", "b");
        OwlUtil.validateParticipantIdsDiffer("a", "A");

        try
        {
            OwlUtil.validateParticipantIdsDiffer("a", "a");
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
        OwlUtil.validateParticipantIdsEqual("a", "a");

        try
        {
            OwlUtil.validateParticipantIdsEqual("a", "b");
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
        OwlCurve curve1 = OwlCurves.NIST_P256;

        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();

        BigInteger x1 = OwlUtil.generateX1(curve1.getN(), random);
        BigInteger x2 = OwlUtil.generateX1(curve1.getN(), random);
        BigInteger x3 = OwlUtil.generateX1(curve1.getN(), random);
        BigInteger x4 = OwlUtil.generateX1(curve1.getN(), random);

        ECPoint gx1 = OwlUtil.calculateGx(curve1.getG(), x1);
        ECPoint gx2 = OwlUtil.calculateGx(curve1.getG(), x2);
        ECPoint gx3 = OwlUtil.calculateGx(curve1.getG(), x3);
        ECPoint gx4 = OwlUtil.calculateGx(curve1.getG(), x4);

        ECPoint alphaG = OwlUtil.calculateGA(gx4, gx1, gx2);

        BigInteger pi = OwlUtil.calculatePi(
            curve1.getN(),
            OwlUtil.calculateT(curve1.getN(), "password", digest),
            digest);

        BigInteger x4pi = OwlUtil.calculateX2s(curve1.getN(), x4, pi);
        BigInteger x2pi = OwlUtil.calculateX2s(curve1.getN(), x2, pi);

        ECPoint alpha = OwlUtil.calculateA(alphaG, x2pi);
        ECPoint rawKey = OwlUtil.calculateKeyingMaterial(gx2, x4, x4pi, alpha);

        BigInteger keyingMaterial = rawKey.normalize().getAffineXCoord().toBigInteger();

        BigInteger macTag = OwlUtil.calculateMacTag(
            "serverId", "clientId", gx3, gx4, gx1, gx2, keyingMaterial, digest);

        // Valid case should not throw
        OwlUtil.validateMacTag("clientId", "serverId", gx1, gx2, gx3, gx4, keyingMaterial, digest, macTag);

        // Validating own macTag should fail
        try
        {
            OwlUtil.validateMacTag("serverId", "clientId", gx1, gx2, gx3, gx4, keyingMaterial, digest, macTag);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Switched participant ids should fail
        try
        {
            OwlUtil.validateMacTag("serverId", "clientId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateNotNull()
    {
        OwlUtil.validateNotNull("a", "description");

        try
        {
            OwlUtil.validateNotNull(null, "description");
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }
    }

    public void testValidateR()
        throws CryptoException
    {
        OwlCurve curve = OwlCurves.NIST_P256;
        Digest digest = SHA256Digest.newInstance();
        SecureRandom random = new SecureRandom();
        ECPoint g = curve.getG();
        BigInteger n = curve.getN();
        BigInteger t = OwlUtil.calculateT(n, "usernameAndPassword", digest);
        ECPoint gt = OwlUtil.calculateGx(g, t);
        ECPoint gx1 = OwlUtil.calculateGx(g, OwlUtil.generateX1(n, random));
        BigInteger h = OwlUtil.generateX1(n, random);
        BigInteger r = OwlUtil.calculateR(OwlUtil.generateX1(n, random), t, h, n);
        // incorrect r
        try
        {
            OwlUtil.validateR(r, gx1, h, gt, g, n);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testValidateZeroknowledgeProof()
        throws CryptoException
    {
        OwlCurve curve1 = OwlCurves.NIST_P256;

        SecureRandom random = new SecureRandom();
        Digest digest1 = SHA256Digest.newInstance();

        BigInteger x1 = OwlUtil.generateX1(curve1.getN(), random);
        ECPoint gx1 = OwlUtil.calculateGx(curve1.getG(), x1);
        String participantId1 = "participant1";

        ECSchnorrZKP zkp1 = OwlUtil.calculateZeroknowledgeProof(curve1.getG(), curve1.getN(), x1, gx1, digest1, participantId1, random);

        // Should succeed
        OwlUtil.validateZeroknowledgeProof(
            curve1.getG(), gx1, zkp1,
            curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
            participantId1, digest1);

        // Wrong group
        OwlCurve curve2 = OwlCurves.NIST_P384;
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve2.getG(), gx1, zkp1,
                curve2.getQ(), curve2.getN(), curve2.getCurve(), curve2.getH(),
                participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Wrong digest
        Digest digest2 = new SHA1Digest();
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), gx1, zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest2);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Wrong participant ID
        String participantId2 = "participant2";
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), gx1, zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId2, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Wrong gx
        BigInteger x2 = OwlUtil.generateX1(curve1.getN(), random);
        ECPoint gx2 = OwlUtil.calculateGx(curve1.getG(), x2);
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), gx2, zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Wrong ZKP
        ECSchnorrZKP zkp2 = OwlUtil.calculateZeroknowledgeProof(
            curve1.getG(), curve1.getN(), x2, gx2, digest1, participantId1, random);
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), gx1, zkp2,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // gx is Infinity
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), curve1.getCurve().getInfinity(), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // Invalid coordinates (outside Fq)
        ECCurve.AbstractFp curve = curve1.getCurve();
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(ONE.negate(), ONE), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1);
            fail();
        }
        catch (Exception e)
        {
            // pass
        }
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(ONE, ONE.negate()), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1);
            fail();
        }
        catch (Exception e)
        {
            // pass
        }
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(curve1.getQ(), ONE), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1);
            fail();
        }
        catch (Exception e)
        {
            // pass
        }
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(ONE, curve1.getQ()), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId1, digest1);
            fail();
        }
        catch (Exception e)
        {
            // pass
        }

        // gx not on curve
        ECPoint invalidPoint = curve.createPoint(ONE, ONE);
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), invalidPoint, zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId2, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // n*gx == infinity (using generator)
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), curve1.getG(), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId2, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // V not on curve (fake)
        try
        {
            OwlUtil.validateZeroknowledgeProof(
                curve1.getG(), curve.createPoint(ONE, ONE), zkp1,
                curve1.getQ(), curve1.getN(), curve1.getCurve(), curve1.getH(),
                participantId2, digest1);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }
}
