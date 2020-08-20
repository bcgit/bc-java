package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;

/**
 * EC-DSA as described in X9.62
 */
public class ECDSASigner
    implements ECConstants, DSAExt
{
    private final DSAKCalculator kCalculator;

    private ECKeyParameters key;
    private SecureRandom    random;

    /**
     * Default configuration, random K values.
     */
    public ECDSASigner()
    {
        this.kCalculator = new RandomDSAKCalculator();
    }

    /**
     * Configuration with an alternate, possibly deterministic calculator of K.
     *
     * @param kCalculator a K value calculator.
     */
    public ECDSASigner(DSAKCalculator kCalculator)
    {
        this.kCalculator = kCalculator;
    }

    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        SecureRandom providedRandom = null;

        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                this.key = (ECPrivateKeyParameters)rParam.getParameters();
                providedRandom = rParam.getRandom();
            }
            else
            {
                this.key = (ECPrivateKeyParameters)param;
            }
        }
        else
        {
            this.key = (ECPublicKeyParameters)param;
        }

        this.random = initSecureRandom(forSigning && !kCalculator.isDeterministic(), providedRandom);
    }

    public BigInteger getOrder()
    {
        return key.getParameters().getN();
    }

    // 5.3 pg 28
    /**
     * generate a signature for the given message using the key we were
     * initialised with. For conventional DSA the message should be a SHA-1
     * hash of the message of interest.
     *
     * @param message the message that will be verified later.
     */
    public BigInteger[] generateSignature(
        byte[] message)
    {
        ECDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();
        BigInteger e = calculateE(n, message);
        BigInteger d = ((ECPrivateKeyParameters)key).getD();

        if (kCalculator.isDeterministic())
        {
            kCalculator.init(n, d, message);
        }
        else
        {
            kCalculator.init(n, random);
        }

        BigInteger r, s;

        ECMultiplier basePointMultiplier = createBasePointMultiplier();

        // 5.3.2
        do // generate s
        {
            BigInteger k;
            do // generate r
            {
                k = kCalculator.nextK();

                ECPoint p = basePointMultiplier.multiply(ec.getG(), k).normalize();

                // 5.3.3
                r = p.getAffineXCoord().toBigInteger().mod(n);
            }
            while (r.equals(ZERO));

            s = BigIntegers.modOddInverse(n, k).multiply(e.add(d.multiply(r))).mod(n);
        }
        while (s.equals(ZERO));

        return new BigInteger[]{ r, s };
    }

    // 5.4 pg 29
    /**
     * return true if the value r and s represent a DSA signature for
     * the passed in message (for standard DSA the message should be
     * a SHA-1 hash of the real message to be verified).
     */
    public boolean verifySignature(
        byte[]      message,
        BigInteger  r,
        BigInteger  s)
    {
        ECDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();
        BigInteger e = calculateE(n, message);

        // r in the range [1,n-1]
        if (r.compareTo(ONE) < 0 || r.compareTo(n) >= 0)
        {
            return false;
        }

        // s in the range [1,n-1]
        if (s.compareTo(ONE) < 0 || s.compareTo(n) >= 0)
        {
            return false;
        }

        BigInteger c = BigIntegers.modOddInverseVar(n, s);

        BigInteger u1 = e.multiply(c).mod(n);
        BigInteger u2 = r.multiply(c).mod(n);

        ECPoint G = ec.getG();
        ECPoint Q = ((ECPublicKeyParameters)key).getQ();

        ECPoint point = ECAlgorithms.sumOfTwoMultiplies(G, u1, Q, u2);

        // components must be bogus.
        if (point.isInfinity())
        {
            return false;
        }

        /*
         * If possible, avoid normalizing the point (to save a modular inversion in the curve field).
         * 
         * There are ~cofactor elements of the curve field that reduce (modulo the group order) to 'r'.
         * If the cofactor is known and small, we generate those possible field values and project each
         * of them to the same "denominator" (depending on the particular projective coordinates in use)
         * as the calculated point.X. If any of the projected values matches point.X, then we have:
         *     (point.X / Denominator mod p) mod n == r
         * as required, and verification succeeds.
         * 
         * Based on an original idea by Gregory Maxwell (https://github.com/gmaxwell), as implemented in
         * the libsecp256k1 project (https://github.com/bitcoin/secp256k1).
         */
        ECCurve curve = point.getCurve();
        if (curve != null)
        {
            BigInteger cofactor = curve.getCofactor();
            if (cofactor != null && cofactor.compareTo(EIGHT) <= 0)
            {
                ECFieldElement D = getDenominator(curve.getCoordinateSystem(), point);
                if (D != null && !D.isZero())
                {
                    ECFieldElement X = point.getXCoord();
                    while (curve.isValidFieldElement(r))
                    {
                        ECFieldElement R = curve.fromBigInteger(r).multiply(D);
                        if (R.equals(X))
                        {
                            return true;
                        }
                        r = r.add(n);
                    }
                    return false;
                }
            }
        }

        BigInteger v = point.normalize().getAffineXCoord().toBigInteger().mod(n);
        return v.equals(r);
    }

    protected BigInteger calculateE(BigInteger n, byte[] message)
    {
        int log2n = n.bitLength();
        int messageBitLength = message.length * 8;

        BigInteger e = new BigInteger(1, message);
        if (log2n < messageBitLength)
        {
            e = e.shiftRight(messageBitLength - log2n);
        }
        return e;
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }

    protected ECFieldElement getDenominator(int coordinateSystem, ECPoint p)
    {
        switch (coordinateSystem)
        {
        case ECCurve.COORD_HOMOGENEOUS:
        case ECCurve.COORD_LAMBDA_PROJECTIVE:
        case ECCurve.COORD_SKEWED:
            return p.getZCoord(0);
        case ECCurve.COORD_JACOBIAN:
        case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
        case ECCurve.COORD_JACOBIAN_MODIFIED:
            return p.getZCoord(0).square();
        default:
            return null;
        }
    }

    protected SecureRandom initSecureRandom(boolean needed, SecureRandom provided)
    {
        return needed ? CryptoServicesRegistrar.getSecureRandom(provided) : null;
    }
}
