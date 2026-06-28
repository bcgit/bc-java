package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.ElGamalKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.BigIntegers;

/**
 * this does your basic ElGamal algorithm.
 */
public class ElGamalEngine
    implements AsymmetricBlockCipher
{
    private ElGamalKeyParameters    key;
    private SecureRandom            random;
    private boolean                 forEncryption;
    private int                     bitSize;

    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /**
     * initialise the ElGamal engine.
     *
     * @param forEncryption true if we are encrypting, false otherwise.
     * @param param the necessary ElGamal key parameters.
     */
    public void init(
        boolean             forEncryption,
        CipherParameters    param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    p = (ParametersWithRandom)param;

            this.key = (ElGamalKeyParameters)p.getParameters();
            this.random = p.getRandom();
        }
        else
        {
            this.key = (ElGamalKeyParameters)param;
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        this.forEncryption = forEncryption;

        BigInteger p = key.getParameters().getP();

        bitSize = p.bitLength();

        if (forEncryption)
        {
            if (!(key instanceof ElGamalPublicKeyParameters))
            {
                throw new IllegalArgumentException("ElGamalPublicKeyParameters are required for encryption.");
            }
        }
        else
        {
            if (!(key instanceof ElGamalPrivateKeyParameters))
            {
                throw new IllegalArgumentException("ElGamalPrivateKeyParameters are required for decryption.");
            }
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("RSA", ConstraintUtils.bitsOfSecurityFor(key.getParameters().getP()), key, Utils.getPurpose(forEncryption)));
    }

    /**
     * Return the maximum size for an input block to this engine.
     * For ElGamal this is always one byte less than the size of P on
     * encryption, and twice the length as the size of P on decryption.
     *
     * @return maximum size for an input block.
     */
    public int getInputBlockSize()
    {
        if (forEncryption)
        {
            return (bitSize - 1) / 8;
        }

        return 2 * ((bitSize + 7) / 8);
    }

    /**
     * Return the maximum size for an output block to this engine.
     * For ElGamal this is always one byte less than the size of P on
     * decryption, and twice the length as the size of P on encryption.
     *
     * @return maximum size for an output block.
     */
    public int getOutputBlockSize()
    {
        if (forEncryption)
        {
            return 2 * ((bitSize + 7) / 8);
        }

        return (bitSize - 1) / 8;
    }

    /**
     * Process a single block using the basic ElGamal algorithm.
     *
     * @param in the input array.
     * @param inOff the offset into the input buffer where the data starts.
     * @param inLen the length of the data to be processed.
     * @return the result of the ElGamal process.
     * @exception DataLengthException the input block is too large.
     */
    public byte[] processBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
    {
        if (key == null)
        {
            throw new IllegalStateException("ElGamal engine not initialised");
        }

        int maxLength = forEncryption
            ?   (bitSize - 1 + 7) / 8
            :   getInputBlockSize();

        BigInteger  p = key.getParameters().getP();

        if (key instanceof ElGamalPrivateKeyParameters) // decryption
        {
            if (inLen != maxLength)
            {
                throw new DataLengthException("input is the wrong size for ElGamal cipher.");
            }

            int half = inLen / 2;
            BigInteger gamma = BigIntegers.fromUnsignedByteArray(in, inOff, half);
            BigInteger phi = BigIntegers.fromUnsignedByteArray(in, inOff + half, half);

            // Both ciphertext components are peer-supplied, and gamma is raised below to the
            // (potentially static, reused) private-key-derived exponent, so both must be valid
            // public values in [2, p-2]. Otherwise a peer can submit a small-order or out-of-range
            // element to mount a small-subgroup confinement attack and, with a decryption oracle and
            // a reused key, recover the private key.
            BigInteger pSub1 = p.subtract(ONE);
            if ((gamma.compareTo(ONE) <= 0 || gamma.compareTo(pSub1) >= 0) ||
                (phi.compareTo(ONE) <= 0 || phi.compareTo(pSub1) >= 0))
            {
                throw new IllegalArgumentException("ElGamal ciphertext element is weak");
            }

            ElGamalPrivateKeyParameters priv = (ElGamalPrivateKeyParameters)key;
            // a shortcut, which generally relies on p being prime amongst other things.
            // if a problem with this shows up, check the p and g values!
            BigInteger m = gamma.modPow(pSub1.subtract(priv.getX()), p).multiply(phi).mod(p);

            return BigIntegers.asUnsignedByteArray(m);
        }
        else // encryption
        {
            if (inLen > maxLength)
            {
                throw new DataLengthException("input too large for ElGamal cipher.");
            }

            BigInteger tmp = BigIntegers.fromUnsignedByteArray(in, inOff, inLen);

            if (tmp.compareTo(p) >= 0)
            {
                throw new DataLengthException("input too large for ElGamal cipher.");
            }

            ElGamalPublicKeyParameters pub = (ElGamalPublicKeyParameters)key;

            // TODO In theory, a series of 'k', 'g.modPow(k, p)' and 'y.modPow(k, p)' can be pre-calculated
            BigInteger k;
            do
            {
                k = BigIntegers.createRandomBigInteger(p.bitLength(), random);
            }
            while (k.equals(ZERO) || k.compareTo(p.subtract(TWO)) > 0);

            BigInteger g = key.getParameters().getG();
            BigInteger gamma = g.modPow(k, p);
            BigInteger phi = pub.getY().modPow(k, p).multiply(tmp).mod(p);

            int half = (bitSize + 7) / 8;
            byte[] output = new byte[2 * half];
            BigIntegers.asUnsignedByteArray(gamma, output, 0, half);
            BigIntegers.asUnsignedByteArray(phi, output, half, half);
            return output;
        }
    }
}
