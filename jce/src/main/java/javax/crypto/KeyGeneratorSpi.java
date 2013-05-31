package javax.crypto;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidParameterException;
import java.security.InvalidAlgorithmParameterException;

/**
 * This class defines the <i>Service Provider Interface</i> (<b>SPI</b>)
 * for the <code>KeyGenerator</code> class.
 * All the abstract methods in this class must be implemented by each 
 * cryptographic service provider who wishes to supply the implementation
 * of a key generator for a particular algorithm.
 *
 * @see SecretKey
 */
public abstract class KeyGeneratorSpi
{
    public KeyGeneratorSpi()
    {
    }

    /**
     * Initializes the key generator.
     * 
     * @param random the source of randomness for this generator
     */
    protected abstract void engineInit(
        SecureRandom    random);

    /**
     * Initializes the key generator with the specified parameter
     * set and a user-provided source of randomness.
     *
     * @param params the key generation parameters
     * @param random the source of randomness for this key generator
     * @exception InvalidAlgorithmParameterException if <code>params</code> is
     * inappropriate for this key generator
     */
    protected abstract void engineInit(
        AlgorithmParameterSpec  params,
        SecureRandom            random)
    throws InvalidAlgorithmParameterException;

    /**
     * Initializes this key generator for a certain keysize, using the given
     * source of randomness.
     *
     * @param keysize the keysize. This is an algorithm-specific metric, specified in number of bits.
     * @param random the source of randomness for this key generator.
     * @exception InvalidParameterException if keysize is wrong or not supported.
     */
    protected abstract void engineInit(
        int             keysize,
        SecureRandom    random)
    throws InvalidParameterException;

    /**
     * Generates a secret key.
     *
     * @return the new key.
     */
    protected abstract SecretKey engineGenerateKey();
}
