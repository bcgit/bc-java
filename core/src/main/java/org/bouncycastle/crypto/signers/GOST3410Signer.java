package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.params.GOST3410KeyParameters;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.crypto.params.GOST3410PrivateKeyParameters;
import org.bouncycastle.crypto.params.GOST3410PublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * GOST R 34.10-94 Signature Algorithm
 */
public class GOST3410Signer
        implements DSAExt
{
        GOST3410KeyParameters key;

        SecureRandom    random;

        public void init(boolean forSigning, CipherParameters param)
        {
            if (forSigning)
            {
                SecureRandom providedRandom = null;
                if (param instanceof ParametersWithRandom)
                {
                    ParametersWithRandom withRandom = (ParametersWithRandom)param;
                    providedRandom = withRandom.getRandom();
                    param = withRandom.getParameters();
                }

                this.key = (GOST3410PrivateKeyParameters)param;
                this.random = CryptoServicesRegistrar.getSecureRandom(providedRandom);
            }
            else
            {
                this.key = (GOST3410PublicKeyParameters)param;
                this.random = null;
            }

            CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("GOST3410", key, forSigning));
        }

        public BigInteger getOrder()
        {
            return key.getParameters().getQ();
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
            GOST3410Parameters   params = key.getParameters();
            // m is public, and the digest can exceed q, which modMult below rejects rather than reduces
            BigInteger      m = new BigInteger(1, mRev).mod(params.getQ());
            // GOST R 34.10-94, as RFC 5832 for 2001: m = 0 becomes 1, otherwise s = x * r and the key is s * r^-1
            if (m.signum() == 0)
            {
                m = BigIntegers.ONE;
            }
            BigInteger      k;

            do
            {
                k = BigIntegers.createRandomBigInteger(params.getQ().bitLength(), random);
            }
            while (k.signum() == 0 || k.compareTo(params.getQ()) >= 0);

            // the randomizer conceals timing information related to k, which is what s below would
            // give up the private key from if it leaked. a has order q by construction, so a^q = 1
            // (mod p) and adding a multiple of q to k leaves r alone - the same randomizer DSASigner
            // applies to its own k.
            BigInteger  blindedK = BigIntegers.createBlindedExponent(k, params.getQ(), random);

            BigInteger  r = params.getA().modPow(blindedK, params.getP()).mod(params.getQ());

            // the secret x and nonce k are kept off BigInteger.mod, whose cost follows the quotient; x is in [1, q-1] by GOST3410PrivateKeyParameters, k is drawn below q above, r is reduced, and q is prime and so odd
            BigInteger  s = BigIntegers.modAdd(params.getQ(),
                                BigIntegers.modMult(params.getQ(), k, m),
                                BigIntegers.modMult(params.getQ(), ((GOST3410PrivateKeyParameters)key).getX(), r));

            BigInteger[]  res = new BigInteger[2];

            res[0] = r;
            res[1] = s;

            return res;
        }

        /**
         * return true if the value r and s represent a GOST3410 signature for
         * the passed in message for standard GOST3410 the message should be a
         * GOST3411 hash of the real message to be verified.
         */
        public boolean verifySignature(
            byte[]      message,
            BigInteger  r,
            BigInteger  s)
        {
            byte[] mRev = Arrays.reverse(message); // conversion is little-endian
            GOST3410Parameters params = key.getParameters();
            // as on signing, m is reduced and m = 0 becomes 1, so (r = 1, any s) no longer verifies over such a digest
            BigInteger           m = new BigInteger(1, mRev).mod(params.getQ());
            if (m.signum() == 0)
            {
                m = BigIntegers.ONE;
            }
            BigInteger           zero = BigInteger.valueOf(0);

            if (zero.compareTo(r) >= 0 || params.getQ().compareTo(r) <= 0)
            {
                return false;
            }

            if (zero.compareTo(s) >= 0 || params.getQ().compareTo(s) <= 0)
            {
                return false;
            }

            BigInteger  v = m.modPow(params.getQ().subtract(new BigInteger("2")),params.getQ());

            BigInteger  z1 = s.multiply(v).mod(params.getQ());
            BigInteger  z2 = (params.getQ().subtract(r)).multiply(v).mod(params.getQ());
            
            z1 = params.getA().modPow(z1, params.getP());
            z2 = ((GOST3410PublicKeyParameters)key).getY().modPow(z2, params.getP());

            BigInteger  u = z1.multiply(z2).mod(params.getP()).mod(params.getQ());

            return u.equals(r);
        }
}
