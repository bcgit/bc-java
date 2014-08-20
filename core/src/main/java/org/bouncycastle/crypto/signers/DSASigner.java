package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/**
 * The Digital Signature Algorithm - as described in "Handbook of Applied
 * Cryptography", pages 452 - 453.
 */
public class DSASigner
    implements DSA
{
    private final DSAKCalculator kCalculator;

    private DSAKeyParameters key;
    private SecureRandom    random;

    /**
     * Default configuration, random K values.
     */
    public DSASigner()
    {
        this.kCalculator = new RandomDSAKCalculator();
    }

    /**
     * Configuration with an alternate, possibly deterministic calculator of K.
     *
     * @param kCalculator a K value calculator.
     */
    public DSASigner(DSAKCalculator kCalculator)
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

                this.key = (DSAPrivateKeyParameters)rParam.getParameters();
                providedRandom = rParam.getRandom();
            }
            else
            {
                this.key = (DSAPrivateKeyParameters)param;
            }
        }
        else
        {
            this.key = (DSAPublicKeyParameters)param;
        }

        this.random = initSecureRandom(forSigning && !kCalculator.isDeterministic(), providedRandom);
    }

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
        DSAParameters   params = key.getParameters();
        BigInteger      q = params.getQ();
        BigInteger      m = calculateE(q, message);
        BigInteger      x = ((DSAPrivateKeyParameters)key).getX();

        if (kCalculator.isDeterministic())
        {
            kCalculator.init(q, x, message);
        }
        else
        {
            kCalculator.init(q, random);
        }

        BigInteger  k = kCalculator.nextK();

        BigInteger  r = params.getG().modPow(k, params.getP()).mod(q);

        k = k.modInverse(q).multiply(m.add(x.multiply(r)));

        BigInteger  s = k.mod(q);

        return new BigInteger[]{ r, s };
    }

    /**
     * return true if the value r and s represent a DSA signature for
     * the passed in message for standard DSA the message should be a
     * SHA-1 hash of the real message to be verified.
     */
    public boolean verifySignature(
        byte[]      message,
        BigInteger  r,
        BigInteger  s)
    {
        DSAParameters   params = key.getParameters();
        BigInteger      q = params.getQ();
        BigInteger      m = calculateE(q, message);
        BigInteger      zero = BigInteger.valueOf(0);

        if (zero.compareTo(r) >= 0 || q.compareTo(r) <= 0)
        {
            return false;
        }

        if (zero.compareTo(s) >= 0 || q.compareTo(s) <= 0)
        {
            return false;
        }

        BigInteger  w = s.modInverse(q);

        BigInteger  u1 = m.multiply(w).mod(q);
        BigInteger  u2 = r.multiply(w).mod(q);

        BigInteger p = params.getP();
        u1 = params.getG().modPow(u1, p);
        u2 = ((DSAPublicKeyParameters)key).getY().modPow(u2, p);

        BigInteger  v = u1.multiply(u2).mod(p).mod(q);

        return v.equals(r);
    }

    private BigInteger calculateE(BigInteger n, byte[] message)
    {
        if (n.bitLength() >= message.length * 8)
        {
            return new BigInteger(1, message);
        }
        else
        {
            byte[] trunc = new byte[n.bitLength() / 8];

            System.arraycopy(message, 0, trunc, 0, trunc.length);

            return new BigInteger(1, trunc);
        }
    }

    protected SecureRandom initSecureRandom(boolean needed, SecureRandom provided)
    {
        return !needed ? null : (provided != null) ? provided : new SecureRandom();
    }
}
