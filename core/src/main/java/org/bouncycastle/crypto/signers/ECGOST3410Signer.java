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
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * GOST R 34.10-2001 Signature Algorithm
 */
public class ECGOST3410Signer
    implements DSAExt
{
    ECKeyParameters key;

    SecureRandom    random;

    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom    rParam = (ParametersWithRandom)param;

                this.random = rParam.getRandom();
                this.key = (ECPrivateKeyParameters)rParam.getParameters();
            }
            else
            {
                this.random = CryptoServicesRegistrar.getSecureRandom();
                this.key = (ECPrivateKeyParameters)param;
            }
        }
        else
        {
            this.key = (ECPublicKeyParameters)param;
        }
    }

    public BigInteger getOrder()
    {
        return key.getParameters().getN();
    }

    /**
     * generate a signature for the given message using the key we were
     * initialised with. For conventional GOST3410 the message should be a GOST3411
     * hash of the message of interest.
     *
     * @param message the message that will be verified later.
     */
    public BigInteger[] generateSignature(
        byte[] message)
    {
        byte[] mRev = Arrays.reverse(message); // conversion is little-endian
        BigInteger e = new BigInteger(1, mRev);

        ECDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();
        BigInteger d = ((ECPrivateKeyParameters)key).getD();

        BigInteger r, s;

        ECMultiplier basePointMultiplier = createBasePointMultiplier();

        do // generate s
        {
            BigInteger k;
            do // generate r
            {
                do
                {
                    k = BigIntegers.createRandomBigInteger(n.bitLength(), random);
                }
                while (k.equals(ECConstants.ZERO));

                ECPoint p = basePointMultiplier.multiply(ec.getG(), k).normalize();

                r = p.getAffineXCoord().toBigInteger().mod(n);
            }
            while (r.equals(ECConstants.ZERO));

            s = (k.multiply(e)).add(d.multiply(r)).mod(n);
        }
        while (s.equals(ECConstants.ZERO));

        return new BigInteger[]{ r, s };
    }

    /**
     * return true if the value r and s represent a GOST3410 signature for
     * the passed in message (for standard GOST3410 the message should be
     * a GOST3411 hash of the real message to be verified).
     */
    public boolean verifySignature(
        byte[]      message,
        BigInteger  r,
        BigInteger  s)
    {
        byte[] mRev = Arrays.reverse(message); // conversion is little-endian
        BigInteger e = new BigInteger(1, mRev);
        BigInteger n = key.getParameters().getN();

        // r in the range [1,n-1]
        if (r.compareTo(ECConstants.ONE) < 0 || r.compareTo(n) >= 0)
        {
            return false;
        }

        // s in the range [1,n-1]
        if (s.compareTo(ECConstants.ONE) < 0 || s.compareTo(n) >= 0)
        {
            return false;
        }

        BigInteger v = BigIntegers.modOddInverseVar(n, e);

        BigInteger z1 = s.multiply(v).mod(n);
        BigInteger z2 = (n.subtract(r)).multiply(v).mod(n);

        ECPoint G = key.getParameters().getG(); // P
        ECPoint Q = ((ECPublicKeyParameters)key).getQ();

        ECPoint point = ECAlgorithms.sumOfTwoMultiplies(G, z1, Q, z2).normalize();

        // components must be bogus.
        if (point.isInfinity())
        {
            return false;
        }

        BigInteger R = point.getAffineXCoord().toBigInteger().mod(n);

        return R.equals(r);
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
