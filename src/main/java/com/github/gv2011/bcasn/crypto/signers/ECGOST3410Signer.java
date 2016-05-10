package com.github.gv2011.bcasn.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.github.gv2011.bcasn.crypto.CipherParameters;
import com.github.gv2011.bcasn.crypto.DSA;
import com.github.gv2011.bcasn.crypto.params.ECDomainParameters;
import com.github.gv2011.bcasn.crypto.params.ECKeyParameters;
import com.github.gv2011.bcasn.crypto.params.ECPrivateKeyParameters;
import com.github.gv2011.bcasn.crypto.params.ECPublicKeyParameters;
import com.github.gv2011.bcasn.crypto.params.ParametersWithRandom;
import com.github.gv2011.bcasn.math.ec.ECAlgorithms;
import com.github.gv2011.bcasn.math.ec.ECConstants;
import com.github.gv2011.bcasn.math.ec.ECMultiplier;
import com.github.gv2011.bcasn.math.ec.ECPoint;
import com.github.gv2011.bcasn.math.ec.FixedPointCombMultiplier;

/**
 * GOST R 34.10-2001 Signature Algorithm
 */
public class ECGOST3410Signer
    implements DSA
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
                this.random = new SecureRandom();
                this.key = (ECPrivateKeyParameters)param;
            }
        }
        else
        {
            this.key = (ECPublicKeyParameters)param;
        }
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
        byte[] mRev = new byte[message.length]; // conversion is little-endian
        for (int i = 0; i != mRev.length; i++)
        {
            mRev[i] = message[mRev.length - 1 - i];
        }

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
                    k = new BigInteger(n.bitLength(), random);
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
        byte[] mRev = new byte[message.length]; // conversion is little-endian
        for (int i = 0; i != mRev.length; i++)
        {
            mRev[i] = message[mRev.length - 1 - i];
        }
        
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

        BigInteger v = e.modInverse(n);

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
