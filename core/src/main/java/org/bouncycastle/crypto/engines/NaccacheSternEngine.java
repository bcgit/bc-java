package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;

/**
 * NaccacheStern Engine. For details on this cipher, please see
 * https://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 */
public class NaccacheSternEngine
    implements AsymmetricBlockCipher
{
    private boolean forEncryption;

    private NaccacheSternKeyParameters key;

    // one fixed-length encoding per possible digit, per small prime. Fixed length so the search in
    // decryption can compare byte by byte without the length itself saying anything.
    private byte[][][] lookup = null;

    // phi(n) / p for each small prime p, the exponent decryption raises the ciphertext to. Worked
    // out once when the tables are built rather than divided out again for every block; no more
    // sensitive than the tables themselves.
    private BigInteger[] phiNOverPrime = null;

    private int modulusLength;

    // CRT recombination data, derived only from the small primes: for each prime p_i, sigma / p_i
    // (at the accumulator length) and its inverse mod p_i; and sigma * 2^j for the final reduction
    private int crtLength;
    private int[][] crtCofactors;
    private int[] crtInverses;
    private int[][] crtSigmaMultiples;

    private SecureRandom random;

    private boolean debug = false;

    private static BigInteger ONE = BigInteger.valueOf(1);

    /**
     * Initializes this algorithm. Must be called before all other Functions.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#init(boolean,
     *      org.bouncycastle.crypto.CipherParameters)
     */
    public void init(boolean forEncryption, CipherParameters param)
    {
        this.forEncryption = forEncryption;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;

            param = rParam.getParameters();
            this.random = CryptoServicesRegistrar.getSecureRandom(rParam.getRandom());
        }
        else
        {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        key = (NaccacheSternKeyParameters)param;

        this.modulusLength = (key.getModulus().bitLength() + 7) / 8;

        // construct lookup table for faster decryption if necessary
        if (!this.forEncryption)
        {
            if (debug)
            {
                // -DM System.out.print
                System.out.println("Constructing lookup Array");
            }
            NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
            Vector primes = priv.getSmallPrimes();
            int count = primes.size();

            // sum_i d_i * (sigma / p_i) * ((sigma / p_i)^-1 mod p_i) is below count * sigma, so
            // bitLength(count) masked subtractions of sigma * 2^j reduce it mod sigma; the
            // accumulator is sized for that sum
            BigInteger sigma = ONE;
            for (int i = 0; i < count; i++)
            {
                sigma = sigma.multiply((BigInteger)primes.elementAt(i));
            }

            int reductions = Integers.bitLength(count);
            int crtBits = sigma.bitLength() + reductions;

            BigInteger[] cofactors = new BigInteger[count];
            crtLength = (crtBits + 31) >>> 5;
            crtCofactors = new int[count][];
            crtInverses = new int[count];
            for (int i = 0; i < count; i++)
            {
                BigInteger prime = (BigInteger)primes.elementAt(i);

                cofactors[i] = exactDivide(sigma, prime, sigma.bitLength());
                crtCofactors[i] = Nat.fromBigInteger(crtBits, cofactors[i]);
                crtInverses[i] = cofactors[i].modInverse(prime).intValue();
            }

            crtSigmaMultiples = new int[reductions][];
            for (int j = 0; j < reductions; j++)
            {
                crtSigmaMultiples[j] = Nat.fromBigInteger(crtBits, sigma.shiftLeft(j));
            }

            // phi(n) / p_i = (phi(n) / sigma) * (sigma / p_i), so one exact division serves every
            // prime. sigma divides phi(n), and the quotient is below 2^k for k the modulus bit length.
            BigInteger phiNOverSigma = exactDivide(priv.getPhi_n(), sigma, priv.getModulus().bitLength());

            lookup = new byte[count][][];
            phiNOverPrime = new BigInteger[count];
            for (int i = 0; i < count; i++)
            {
                BigInteger actualPrime = (BigInteger)primes.elementAt(i);
                int actualPrimeValue = actualPrime.intValue();

                lookup[i] = new byte[actualPrimeValue][];
                lookup[i][0] = BigIntegers.asUnsignedByteArray(modulusLength, ONE);

                if (debug)
                {
                    // -DM System.out.print
                    System.out.println("Constructing lookup ArrayList for " + actualPrimeValue);
                }

                phiNOverPrime[i] = phiNOverSigma.multiply(cofactors[i]);

                // entry j is g^(j * phi(n) / p) = h^j for h = g^(phi(n) / p), so one exponentiation
                // and then repeated multiplication build the table. The exponent carries phi(n),
                // which is the private key, so it is randomised with a multiple of phi(n) before the
                // variable-time modPow sees it; g is coprime to n, so h is unchanged. The entries are
                // as sensitive as the key - h - 1 shares a prime factor with n - so the chain uses
                // the fixed-time modMult rather than multiply and mod, whose reduction follows the
                // value. If p divides both P - 1 and Q - 1 for n = PQ (always so for p = 2), then
                // h = 1 for every g, every entry is 1, and that digit always decrypts as 0; the key
                // is invalid but this does not detect it.
                BigInteger exponent = BigIntegers.createBlindedExponent(phiNOverPrime[i], priv.getPhi_n(), random);
                BigInteger h = priv.getG().modPow(exponent, priv.getModulus());
                BigInteger entry = ONE;

                for (int j = 1; j < actualPrimeValue; j++)
                {
                    entry = BigIntegers.modMult(priv.getModulus(), entry, h);
                    lookup[i][j] = BigIntegers.asUnsignedByteArray(modulusLength, entry);
                }
            }
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
                "NaccacheStern", ConstraintUtils.bitsOfSecurityFor(key.getModulus()), param, Utils.getPurpose(forEncryption)));
    }

    public void setDebug(boolean debug)
    {
        this.debug = debug;
    }

    /**
     * Returns the input block size of this algorithm.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#getInputBlockSize()
     */
    public int getInputBlockSize()
    {
        if (forEncryption)
        {
            // We can only encrypt values up to lowerSigmaBound
            return (key.getLowerSigmaBound() + 7) / 8 - 1;
        }
        else
        {
            // We pad to modulus-size bytes for easier decryption.
            return key.getModulus().toByteArray().length;
        }
    }

    /**
     * Returns the output block size of this algorithm.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#getOutputBlockSize()
     */
    public int getOutputBlockSize()
    {
        if (forEncryption)
        {
            // encrypted Data is always padded up to modulus size
            return key.getModulus().toByteArray().length;
        }
        else
        {
            // decrypted Data has upper limit lowerSigmaBound
            return (key.getLowerSigmaBound() + 7) / 8 - 1;
        }
    }

    /**
     * Process a single Block using the Naccache-Stern algorithm.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#processBlock(byte[],
     *      int, int)
     */
    public byte[] processBlock(byte[] in, int inOff, int len) throws InvalidCipherTextException
    {
        if (key == null)
        {
            throw new IllegalStateException("NaccacheStern engine not initialised");
        }
        if (len > (getInputBlockSize() + 1))
        {
            throw new DataLengthException("input too large for Naccache-Stern cipher.\n");
        }

        if (!forEncryption)
        {
            // At decryption make sure that we receive padded data blocks
            if (len < getInputBlockSize())
            {
                throw new InvalidCipherTextException("BlockLength does not match modulus for Naccache-Stern cipher.\n");
            }
        }

        byte[] block;

        if (inOff != 0 || len != in.length)
        {
            block = new byte[len];
            System.arraycopy(in, inOff, block, 0, len);
        }
        else
        {
            block = in;
        }

        // transform input into BigInteger
        BigInteger input = new BigInteger(1, block);
        if (debug)
        {
            // -DM System.out.print
            System.out.println("input as BigInteger: " + input);
        }
        byte[] output;
        if (forEncryption)
        {
            output = encrypt(input);
        }
        else
        {
            NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
            Vector primes = priv.getSmallPrimes();

            // The plaintext is recombined from its digits d_i = plaintext mod p_i by the CRT, in a
            // fixed-length accumulator so that neither the digits nor the sum steer the work
            // (BigInteger arithmetic shortcuts zero operands, sizes products by their values, and
            // reduces by a division that follows the quotient).
            int[] acc = Nat.create(crtLength);
            int[] tmp = Nat.create(crtLength);
            try
            {
                for (int i = 0; i < primes.size(); i++)
                {
                    // input is the caller's ciphertext and the exponent is derived from phi(n), which
                    // is the private key - recovering it factors the modulus - so the exponent is
                    // randomised before the variable-time modPow sees it. input^phi(n) = 1 (mod n) by
                    // Euler for any input coprime to n, so the result is unchanged; an input sharing
                    // a factor with n decrypts to a different value than before, but it failed the
                    // lookup below either way, and producing one means the caller has already
                    // factored the modulus.
                    BigInteger exponent = BigIntegers.createBlindedExponent(
                        phiNOverPrime[i], priv.getPhi_n(), random);

                    BigInteger exp = input.modPow(exponent, priv.getModulus());
                    byte[][] al = lookup[i];
                    if (al.length != ((BigInteger)primes.elementAt(i)).intValue())
                    {
                        if (debug)
                        {
                            // -DM System.out.println
                            System.out.println("Prime is " + primes.elementAt(i) + ", lookup table has size " + al.length);
                        }
                        throw new InvalidCipherTextException("Error in lookup Array for "
                                        + ((BigInteger)primes.elementAt(i)).intValue()
                                        + ": Size mismatch. Expected ArrayList with length "
                                        + ((BigInteger)primes.elementAt(i)).intValue() + " but found ArrayList of length "
                                        + al.length);
                    }

                    // the CRT term d_i * (sigma / p_i) * ((sigma / p_i)^-1 mod p_i) mod sigma is
                    // (sigma / p_i) * t_i for t_i = d_i * (sigma / p_i)^-1 mod p_i, and the lookup
                    // yields t_i directly, so each term is below sigma and needs no reduction of its
                    // own
                    int t = fixedTimeLookup(al, BigIntegers.asUnsignedByteArray(modulusLength, exp), crtInverses[i]);

                    if (t < 0)
                    {
                        if (debug)
                        {
                            // -DM 3 System.out.print
                            System.out.println("Actual prime is " + primes.elementAt(i));
                            System.out.println("Decrypted value is " + exp);

                            System.out.println("LookupList for " + primes.elementAt(i) + " with size " + al.length
                                            + " is: ");
                            for (int j = 0; j < al.length; j++)
                            {
                                // -DM System.out.println
                                System.out.println(new BigInteger(1, al[j]));
                            }
                        }
                        throw new InvalidCipherTextException("Lookup failed");
                    }

                    Nat.mulWordAddTo(crtLength, t, crtCofactors[i], 0, acc, 0);
                }

                // acc < count * sigma <= 2^reductions * sigma, and each masked subtraction of
                // sigma * 2^j halves the bound, leaving acc < sigma
                for (int j = crtSigmaMultiples.length - 1; j >= 0; --j)
                {
                    int borrow = Nat.sub(crtLength, acc, crtSigmaMultiples[j], tmp);
                    Nat.cmov(crtLength, ~borrow, tmp, 0, acc, 0);
                }

                // No check that g^test re-encrypts to the input: a valid ciphertext need not equal
                // g^test, since probabilistic encryption multiplies in x^sigma and addCryptedBlocks
                // can leave a sum beyond sigma
                // TODO[api] Encode the plaintext straight from acc, without the BigInteger round
                // trip, and unsigned as the RSA and ElGamal engines do: the signed toByteArray adds
                // a 0x00 when the top bit is set (the value is never negative), which can take the
                // output past getOutputBlockSize(). processData concatenates these value-length
                // blocks, so decrypting there also loses any block's leading zero bytes.
                BigInteger test = Nat.toBigInteger(crtLength, acc);

                output = test.toByteArray();
            }
            finally
            {
                Arrays.clear(acc);
                Arrays.clear(tmp);
            }
        }

        return output;
    }

    /**
     * Encrypts a BigInteger aka Plaintext with the public key.
     * 
     * @param plain
     *            The BigInteger to encrypt
     * @return The byte[] representation of the encrypted BigInteger (i.e.
     *         crypted.toByteArray())
     */
    public byte[] encrypt(BigInteger plain)
    {
        // Always return modulus size values 0-padded at the beginning
        // 0-padding at the beginning is correctly parsed by BigInteger :)
        byte[] output = key.getModulus().toByteArray();
        Arrays.fill(output, (byte)0);
        byte[] tmp = key.getG().modPow(plain, key.getModulus()).toByteArray();
        System
                .arraycopy(tmp, 0, output, output.length - tmp.length,
                        tmp.length);
        if (debug)
        {
           // -DM System.out.print
            System.out
                    .println("Encrypted value is:  " + new BigInteger(output));
        }
        return output;
    }

    /**
     * Adds the contents of two encrypted blocks mod sigma
     * 
     * @param block1
     *            the first encrypted block
     * @param block2
     *            the second encrypted block
     * @return encrypt((block1 + block2) mod sigma)
     * @throws InvalidCipherTextException
     */
    public byte[] addCryptedBlocks(byte[] block1, byte[] block2)
            throws InvalidCipherTextException
    {
        // check for correct blocksize
        if (forEncryption)
        {
            if ((block1.length > getOutputBlockSize())
                    || (block2.length > getOutputBlockSize()))
            {
                throw new InvalidCipherTextException(
                        "BlockLength too large for simple addition.\n");
            }
        }
        else
        {
            if ((block1.length > getInputBlockSize())
                    || (block2.length > getInputBlockSize()))
            {
                throw new InvalidCipherTextException(
                        "BlockLength too large for simple addition.\n");
            }
        }

        // calculate resulting block
        BigInteger m1Crypt = new BigInteger(1, block1);
        BigInteger m2Crypt = new BigInteger(1, block2);
        BigInteger m1m2Crypt = m1Crypt.multiply(m2Crypt);
        m1m2Crypt = m1m2Crypt.mod(key.getModulus());
        if (debug)
        {
            // -DM 3 System.out.print
            System.out.println("c(m1) as BigInteger:....... " + m1Crypt);
            System.out.println("c(m2) as BigInteger:....... " + m2Crypt);
            System.out.println("c(m1)*c(m2)%n = c(m1+m2)%n: " + m1m2Crypt);
        }

        byte[] output = key.getModulus().toByteArray();
        Arrays.fill(output, (byte)0);
        System.arraycopy(m1m2Crypt.toByteArray(), 0, output, output.length
                - m1m2Crypt.toByteArray().length,
                m1m2Crypt.toByteArray().length);

        return output;
    }

    /**
     * Convenience Method for data exchange with the cipher.
     * 
     * Determines blocksize and splits data to blocksize.
     *
     * @param data the data to be processed
     * @return the data after it went through the NaccacheSternEngine.
     * @throws InvalidCipherTextException 
     */
    public byte[] processData(byte[] data) throws InvalidCipherTextException
    {
        if (debug)
        {
            // -DM System.out.println
            System.out.println();
        }
        if (data.length > getInputBlockSize())
        {
            int inBlocksize = getInputBlockSize();
            int outBlocksize = getOutputBlockSize();
            if (debug)
            {
                // -DM 3 System.out.print
                System.out.println("Input blocksize is:  " + inBlocksize + " bytes");
                System.out.println("Output blocksize is: " + outBlocksize + " bytes");
                System.out.println("Data has length:.... " + data.length + " bytes");
            }
            int datapos = 0;
            int retpos = 0;
            byte[] retval = new byte[(data.length / inBlocksize + 1) * outBlocksize];
            while (datapos < data.length)
            {
                byte[] tmp;
                if (datapos + inBlocksize < data.length)
                {
                    tmp = processBlock(data, datapos, inBlocksize);
                    datapos += inBlocksize;
                }
                else
                {
                    tmp = processBlock(data, datapos, data.length - datapos);
                    datapos += data.length - datapos;
                }
                if (debug)
                {
                    // -DM System.out.println
                    System.out.println("new datapos is " + datapos);
                }
                if (tmp != null)
                {
                    System.arraycopy(tmp, 0, retval, retpos, tmp.length);
                    
                    retpos += tmp.length;
                }
                else
                {
                    if (debug)
                    {
                        // -DM System.out.println
                        System.out.println("cipher returned null");
                    }
                    throw new InvalidCipherTextException("cipher returned null");
                }
            }
            byte[] ret = new byte[retpos];
            System.arraycopy(retval, 0, ret, 0, retpos);
            if (debug)
            {
                // -DM System.out.println
                System.out.println("returning " + ret.length + " bytes");
            }
            return ret;
        }
        else
        {
            if (debug)
            {
                // -DM System.out.println
                System.out.println("data size is less then input block size, processing directly");
            }
            return processBlock(data, 0, data.length);
        }
    }

    /**
     * x / d for odd d dividing x, with the quotient below 2^bits, without BigInteger.divide, whose
     * running time follows the quotient: it is x * d^-1 mod 2^bits, one multiplication and a mask.
     * Only correct when d divides x, which is why it stays private to this engine.
     */
    private static BigInteger exactDivide(BigInteger x, BigInteger d, int bits)
    {
        BigInteger m = ONE.shiftLeft(bits);

        return x.multiply(d.modInverse(m)).and(m.subtract(ONE));
    }

    /**
     * The index of the match is the plaintext digit d for this prime (the table length p), so
     * returning as soon as it is found - which Vector.indexOf did - made the running time reveal it.
     * Scan the whole table instead and select by mask. The CRT needs d only as d * inv mod p, so that
     * is what is selected, from a running j * inv mod p.
     *
     * @return d * inv mod p, or -1 if the value is not in the table.
     */
    private static int fixedTimeLookup(byte[][] table, byte[] value, int inv)
    {
        int p = table.length;

        int found = 0;                                      // -1 once something has matched
        int r = 0;                                          // j * inv mod p
        int result = 0;

        for (int j = 0; j < p; ++j)
        {
            byte[] candidate = table[j];
            int diff = 0;

            for (int k = 0; k < value.length; ++k)
            {
                diff |= (candidate[k] ^ value[k]) & 0xFF;
            }

            int isEqual = (diff - 1) >> 31;                 // -1 when equal, 0 otherwise

            result |= r & isEqual & ~found;
            found |= isEqual;

            // r + inv < 2p, and with p below 2^31 the difference r + inv - p is in (-2^31, 2^31)
            int s = r + inv;
            int below = (s - p) >> 31;                      // all ones when s < p
            r = s - (p & ~below);
        }

        return result | ~found;
    }
}
