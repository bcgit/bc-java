package org.bouncycastle.math.ec.test;

import java.math.BigInteger;
import java.util.Enumeration;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Explicit EC domain parameters must not be able to declare a subgroup order or cofactor larger than the
 * curve can have (Hasse's theorem), since the order is used as a scalar when a point is validated.
 */
public class ECCurveOrderBoundTest
    extends TestCase
{
    private static final BigInteger TWO = BigIntegers.TWO;

    private static BigInteger allOnes(int bits)
    {
        return BigIntegers.ONE.shiftLeft(bits).subtract(BigIntegers.ONE);
    }

    private static X9ECParameters p256()
    {
        return ECNamedCurveTable.getByName("P-256");
    }

    private static ECCurve.Fp fpCurve(X9ECParameters base, BigInteger order, BigInteger cofactor)
    {
        ECCurve curve = base.getCurve();
        return new ECCurve.Fp(curve.getField().getCharacteristic(), curve.getA().toBigInteger(),
            curve.getB().toBigInteger(), order, cofactor);
    }

    public void testFpOrderBound()
    {
        X9ECParameters p256 = p256();
        int qBits = p256.getCurve().getFieldSize();

        // the largest order Hasse's bound allows is accepted
        fpCurve(p256, allOnes(qBits + 1), TWO);
        fpCurve(p256, allOnes(qBits + 2), TWO);

        try
        {
            fpCurve(p256, allOnes(qBits + 3), TWO);
            fail("oversized order accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("EC curve order out of range", e.getMessage());
        }

        try
        {
            fpCurve(p256, p256.getN(), allOnes(200000));
            fail("oversized cofactor accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("EC curve cofactor out of range", e.getMessage());
        }
    }

    public void testF2mOrderBound()
    {
        BigInteger a = BigIntegers.ONE;
        BigInteger b = BigIntegers.ONE;

        // sect163k1 shape: m = 163, pentanomial 3, 6, 7
        new ECCurve.F2m(163, 3, 6, 7, a, b, allOnes(165), TWO);

        try
        {
            new ECCurve.F2m(163, 3, 6, 7, a, b, allOnes(166), TWO);
            fail("oversized order accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("EC curve order out of range", e.getMessage());
        }

        try
        {
            new ECCurve.F2m(163, 3, 6, 7, a, b, allOnes(163), allOnes(10000));
            fail("oversized cofactor accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("EC curve cofactor out of range", e.getMessage());
        }
    }

    public void testDomainParametersBound()
    {
        X9ECParameters p256 = p256();
        int qBits = p256.getCurve().getFieldSize();

        try
        {
            new ECDomainParameters(p256.getCurve(), p256.getG(), allOnes(qBits + 3), BigIntegers.ONE);
            fail("oversized n accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("n out of range for curve", e.getMessage());
        }

        try
        {
            new ECDomainParameters(p256.getCurve(), p256.getG(), p256.getN(), allOnes(qBits + 3));
            fail("oversized h accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("h out of range for curve", e.getMessage());
        }
    }

    /**
     * The reported shape: a genuine P-256 curve and generator with cofactor 2 and a 200,000 bit order, carried as
     * explicit parameters in a SubjectPublicKeyInfo. The parse must fail on the order, not after point validation.
     */
    public void testExplicitParametersPublicKey()
        throws Exception
    {
        X9ECParameters p256 = p256();
        BigInteger bigOrder = allOnes(200000);

        // build the encoding by hand, as the curve classes will no longer construct the parameters
        ECCurve.Fp honest = fpCurve(p256, p256.getN(), BigIntegers.ONE);
        ECPoint g = honest.createPoint(p256.getG().getAffineXCoord().toBigInteger(),
            p256.getG().getAffineYCoord().toBigInteger());
        X9ECParameters encodable = new X9ECParameters(honest, new X9ECPoint(g, false), p256.getN(), BigIntegers.ONE);
        byte[] der = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
            new X962Parameters(encodable)), g.getEncoded(false)).getEncoded();

        byte[] n = p256.getN().toByteArray();
        byte[] hostile = replaceParameters(der, n, bigOrder.toByteArray());

        long start = System.currentTimeMillis();
        try
        {
            PublicKeyFactory.createKey(hostile);
            fail("oversized order accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(messageChainContains(e, "EC curve order out of range"));
        }
        assertTrue("rejection took too long", System.currentTimeMillis() - start < 2000);
    }

    /**
     * Every registered named curve must still construct through the public constructors.
     */
    public void testNamedCurvesUnaffected()
    {
        Enumeration names = ECNamedCurveTable.getNames();
        while (names.hasMoreElements())
        {
            String name = (String)names.nextElement();
            X9ECParameters x9 = ECNamedCurveTable.getByName(name);
            ECCurve curve = x9.getCurve();

            if (ECAlgorithms.isFpCurve(curve))
            {
                new ECCurve.Fp(curve.getField().getCharacteristic(), curve.getA().toBigInteger(),
                    curve.getB().toBigInteger(), curve.getOrder(), curve.getCofactor());
            }
            else
            {
                int[] exponents = ((PolynomialExtensionField)curve.getField()).getMinimalPolynomial().getExponentsPresent();
                int m = exponents[exponents.length - 1];
                if (exponents.length == 3)
                {
                    new ECCurve.F2m(m, exponents[1], curve.getA().toBigInteger(), curve.getB().toBigInteger(),
                        curve.getOrder(), curve.getCofactor());
                }
                else
                {
                    new ECCurve.F2m(m, exponents[1], exponents[2], exponents[3], curve.getA().toBigInteger(),
                        curve.getB().toBigInteger(), curve.getOrder(), curve.getCofactor());
                }
            }

            new ECDomainParameters(curve, x9.getG(), x9.getN(), x9.getH());
        }
    }

    private static boolean messageChainContains(Throwable t, String msg)
    {
        for (; t != null; t = t.getCause())
        {
            if (t.getMessage() != null && t.getMessage().indexOf(msg) >= 0)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Replace the INTEGER holding the order (and set the cofactor to 2) in a DER SubjectPublicKeyInfo carrying
     * explicit parameters, re-encoding through the ASN.1 classes so the lengths stay consistent.
     */
    private static byte[] replaceParameters(byte[] der, byte[] oldN, byte[] newN)
        throws Exception
    {
        ASN1Sequence spki = ASN1Sequence.getInstance(der);
        ASN1Sequence algId = ASN1Sequence.getInstance(spki.getObjectAt(0));
        ASN1Sequence params = ASN1Sequence.getInstance(algId.getObjectAt(1));

        // ECParameters ::= SEQUENCE { version, fieldID, curve, base, order, cofactor OPTIONAL }
        assertTrue(Arrays.areEqual(oldN,
            ASN1Integer.getInstance(params.getObjectAt(4)).getValue().toByteArray()));
        ASN1EncodableVector nv = new ASN1EncodableVector();
        for (int i = 0; i != 4; i++)
        {
            nv.add(params.getObjectAt(i));
        }
        nv.add(new ASN1Integer(new BigInteger(1, newN)));
        nv.add(new ASN1Integer(TWO));

        ASN1EncodableVector av = new ASN1EncodableVector();
        av.add(algId.getObjectAt(0));
        av.add(new DERSequence(nv));

        ASN1EncodableVector sv = new ASN1EncodableVector();
        sv.add(new DERSequence(av));
        sv.add(spki.getObjectAt(1));

        return new DERSequence(sv).getEncoded();
    }
}
