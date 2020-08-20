package org.bouncycastle.crypto.generators;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.math.Primes;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;

/**
 * an RSA key pair generator.
 */
public class RSAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private RSAKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (RSAKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair result = null;
        boolean done = false;

        //
        // p and q values should have a length of half the strength in bits
        //
        int strength = param.getStrength();
        int pbitlength = (strength + 1) / 2;
        int qbitlength = strength - pbitlength;
        int mindiffbits = (strength / 2) - 100;

        if (mindiffbits < strength / 3)
        {
            mindiffbits = strength / 3;
        }

        int minWeight = strength >> 2;

        // d lower bound is 2^(strength / 2)
        BigInteger dLowerBound = BigInteger.valueOf(2).pow(strength / 2);
        // squared bound (sqrt(2)*2^(nlen/2-1))^2
        BigInteger squaredBound = ONE.shiftLeft(strength - 1);
        // 2^(nlen/2 - 100)
        BigInteger minDiff = ONE.shiftLeft(mindiffbits);

        while (!done)
        {
            BigInteger p, q, n, d, e, pSub1, qSub1, gcd, lcm;

            e = param.getPublicExponent();

            p = chooseRandomPrime(pbitlength, e, squaredBound);

            //
            // generate a modulus of the required length
            //
            for (; ; )
            {
                q = chooseRandomPrime(qbitlength, e, squaredBound);

                // p and q should not be too close together (or equal!)
                BigInteger diff = q.subtract(p).abs();
                if (diff.bitLength() < mindiffbits || diff.compareTo(minDiff) <= 0)
                {
                    continue;
                }

                //
                // calculate the modulus
                //
                n = p.multiply(q);

                if (n.bitLength() != strength)
                {
                    //
                    // if we get here our primes aren't big enough, make the largest
                    // of the two p and try again
                    //
                    p = p.max(q);
                    continue;
                }

	            /*
                 * Require a minimum weight of the NAF representation, since low-weight composites may
	             * be weak against a version of the number-field-sieve for factoring.
	             *
	             * See "The number field sieve for integers of low weight", Oliver Schirokauer.
	             */
                if (WNafUtil.getNafWeight(n) < minWeight)
                {
                    p = chooseRandomPrime(pbitlength, e, squaredBound);
                    continue;
                }

                break;
            }

            if (p.compareTo(q) < 0)
            {
                gcd = p;
                p = q;
                q = gcd;
            }

            pSub1 = p.subtract(ONE);
            qSub1 = q.subtract(ONE);
            gcd = pSub1.gcd(qSub1);
            lcm = pSub1.divide(gcd).multiply(qSub1);

            //
            // calculate the private exponent
            //
            d = e.modInverse(lcm);

            if (d.compareTo(dLowerBound) <= 0)
            {
                continue;
            }
            else
            {
                done = true;
            }

            //
            // calculate the CRT factors
            //
            BigInteger dP, dQ, qInv;

            dP = d.remainder(pSub1);
            dQ = d.remainder(qSub1);
            qInv = BigIntegers.modOddInverse(p, q);

            result = new AsymmetricCipherKeyPair(
                new RSAKeyParameters(false, n, e),
                new RSAPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));
        }

        return result;
    }

    /**
     * Choose a random prime value for use with RSA
     *
     * @param bitlength the bit-length of the returned prime
     * @param e         the RSA public exponent
     * @return A prime p, with (p-1) relatively prime to e
     */
    protected BigInteger chooseRandomPrime(int bitlength, BigInteger e, BigInteger sqrdBound)
    {
        for (int i = 0; i != 5 * bitlength; i++)
        {
            BigInteger p = BigIntegers.createRandomPrime(bitlength, 1, param.getRandom());

            if (p.mod(e).equals(ONE))
            {
                continue;
            }

            if (p.multiply(p).compareTo(sqrdBound) < 0)
            {
                continue;
            }

            if (!isProbablePrime(p))
            {
                continue;
            }

            if (!e.gcd(p.subtract(ONE)).equals(ONE))
            {
                continue;
            }

            return p;
        }

        throw new IllegalStateException("unable to generate prime number for RSA key");
    }

    protected boolean isProbablePrime(BigInteger x)
    {
        int iterations = getNumberOfIterations(x.bitLength(), param.getCertainty());

        /*
         * Primes class for FIPS 186-4 C.3 primality checking
         */
        return !Primes.hasAnySmallFactors(x) && Primes.isMRProbablePrime(x, param.getRandom(), iterations);
    }

    private static int getNumberOfIterations(int bits, int certainty)
    {
        /*
         * NOTE: We enforce a minimum 'certainty' of 100 for bits >= 1024 (else 80). Where the
         * certainty is higher than the FIPS 186-4 tables (C.2/C.3) cater to, extra iterations
         * are added at the "worst case rate" for the excess.
         */
        if (bits >= 1536)
        {
            return  certainty <= 100 ? 3
                :   certainty <= 128 ? 4
                :   4 + (certainty - 128 + 1) / 2;
        }
        else if (bits >= 1024)
        {
            return  certainty <= 100 ? 4
                :   certainty <= 112 ? 5
                :   5 + (certainty - 112 + 1) / 2;
        }
        else if (bits >= 512)
        {
            return  certainty <= 80  ? 5
                :   certainty <= 100 ? 7
                :   7 + (certainty - 100 + 1) / 2;
        }
        else
        {
            return  certainty <= 80  ? 40
                :   40 + (certainty - 80 + 1) / 2;
        }
    }
}
