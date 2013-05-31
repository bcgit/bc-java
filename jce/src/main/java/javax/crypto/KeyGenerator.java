package javax.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class provides the functionality of a (symmetric) key generator.
 * <p>
 * Key generators are constructed using one of the <code>getInstance</code>
 * class methods of this class.
 * <p>
 * KeyGenerator objects are reusable, i.e., after a key has been
 * generated, the same KeyGenerator object can be re-used to generate further
 * keys.
 * <p>
 * There are two ways to generate a key: in an algorithm-independent manner,
 * and in an algorithm-specific manner. The only difference between the two is
 * the initialization of the object:
 *
 * <ul>
 * <li><b>Algorithm-Independent Initialization</b>
 * <p>All key generators share the concepts of a <i>keysize</i> and a
 * <i>source of randomness</i>.
 * There is an 
 * <a href = "#init(int, java.security.SecureRandom)">init</a> 
 * method in this KeyGenerator class that takes these two universally
 * shared types of arguments. There is also one that takes just a
 * <code>keysize</code> argument, and uses the SecureRandom implementation
 * of the highest-priority installed provider as the source of randomness
 * (or a system-provided source of randomness if none of the installed
 * providers supply a SecureRandom implementation), and one that takes just a
 * source of randomness.
 * <p>
 * Since no other parameters are specified when you call the above
 * algorithm-independent <code>init</code> methods, it is up to the
 * provider what to do about the algorithm-specific parameters (if any) to be
 * associated with each of the keys.
 * <p>
 * <li><b>Algorithm-Specific Initialization</b>
 * <p>For situations where a set of algorithm-specific parameters already
 * exists, there are two
 * <a href = "#init(java.security.spec.AlgorithmParameterSpec)">init</a>
 * methods that have an <code>AlgorithmParameterSpec</code>
 * argument. One also has a <code>SecureRandom</code> argument, while the
 * other uses the SecureRandom implementation
 * of the highest-priority installed provider as the source of randomness
 * (or a system-provided source of randomness if none of the installed
 * providers supply a SecureRandom implementation).
 * </ul>
 *
 * <p>In case the client does not explicitly initialize the KeyGenerator
 * (via a call to an <code>init</code> method), each provider must
 * supply (and document) a default initialization.
 *
 * @see SecretKey
 */
public class KeyGenerator
{
    private KeyGeneratorSpi keyGenerator;
    private Provider        provider;
    private String          algorithm;

    /**
     * Creates a KeyGenerator object.
     *
     * @param keyGenSpi the delegate
     * @param provider the provider
     * @param algorithm the algorithm
     */
    protected KeyGenerator(
        KeyGeneratorSpi     keyGenSpi,
        Provider            provider,
        String              algorithm)
    {
        this.keyGenerator = keyGenSpi;
        this.provider = provider;
        this.algorithm = algorithm;
    }

    /**
     * Returns the algorithm name of this <code>KeyGenerator</code> object.
     * <p>
     * This is the same name that was specified in one of the
     * <code>getInstance</code> calls that created this
     * <code>KeyGenerator</code> object.
     *
     * @return the algorithm name of this <code>KeyGenerator</code> object.
     */
    public final String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Generates a <code>KeyGenerator</code> object for the specified algorithm.
     * If the default provider package provides an implementation of the
     * requested key generator, an instance of <code>KeyGenerator</code> containing
     * that implementation is returned. If the requested key generator is not available
     * in the default provider package, other provider packages are searched.
     *
     * @param algorithm the standard name of the requested key algorithm. See Appendix A in the
     * Java Cryptography Extension API Specification &amp; Reference for information about standard
     * algorithm names.
     * @return the new <code>KeyGenerator</code> object
     * @exception NoSuchAlgorithmException if a key generator for the specified algorithm is not
     * available in the default provider package or any of the other provider packages that were searched.
     */
    public static final KeyGenerator getInstance(
        String  algorithm)
    throws NoSuchAlgorithmException
    {
        try
        {
            JCEUtil.Implementation imp = JCEUtil.getImplementation("KeyGenerator", algorithm, (String) null);

            if (imp == null)
            {
                throw new NoSuchAlgorithmException(algorithm + " not found");
            }

            KeyGenerator keyGen = new KeyGenerator((KeyGeneratorSpi)imp.getEngine(), imp.getProvider(), algorithm);

            return keyGen;
        }
        catch (NoSuchProviderException e)
        {
            throw new NoSuchAlgorithmException(algorithm + " not found");
        }
    }
    
    /**
     * Generates a <code>KeyGenerator</code> object for the specified key
     * algorithm from the specified provider.
     *
     * @param algorithm the standard name of the requested key algorithm. See Appendix A in the
     * Java Cryptography Extension API Specification &amp; Reference for information about standard
     * algorithm names.
     * @param provider the provider
     * @return the new <code>KeyGenerator</code> object
     * @exception NoSuchAlgorithmException if a key generator for the specified algorithm is not
     * available from the specified provider.
     */
	public static final KeyGenerator getInstance(
			String   algorithm,
			Provider provider) 
	throws NoSuchAlgorithmException 
	{
        if (provider == null)
        {
            throw new IllegalArgumentException("No provider specified to KeyGenerator.getInstance()");
        }

        JCEUtil.Implementation imp = JCEUtil.getImplementation("KeyGenerator", algorithm, provider);

        if (imp == null)
        {
            throw new NoSuchAlgorithmException(algorithm + " not found");
        }

        KeyGenerator keyGen = new KeyGenerator((KeyGeneratorSpi)imp.getEngine(), imp.getProvider(), algorithm);

        return keyGen;
	}

    /**
     * Generates a <code>KeyGenerator</code> object for the specified key
     * algorithm from the specified provider.
     *
     * @param algorithm the standard name of the requested key algorithm. See Appendix A in the
     * Java Cryptography Extension API Specification &amp; Reference for information about standard
     * algorithm names.
     * @param provider the name of the provider
     * @return the new <code>KeyGenerator</code> object
     * @exception NoSuchAlgorithmException if a key generator for the specified algorithm is not
     * available from the specified provider.
     * @exception NoSuchProviderException if the specified provider has not been configured.
     */
    public static final KeyGenerator getInstance(
        String      algorithm,
        String      provider)
    throws NoSuchAlgorithmException, NoSuchProviderException
    {
        if (provider == null)
        {
            throw new IllegalArgumentException("No provider specified to KeyGenerator.getInstance()");
        }

        JCEUtil.Implementation imp = JCEUtil.getImplementation("KeyGenerator", algorithm, provider);

        if (imp == null)
        {
            throw new NoSuchAlgorithmException(algorithm + " not found");
        }

        KeyGenerator keyGen = new KeyGenerator((KeyGeneratorSpi)imp.getEngine(), imp.getProvider(), algorithm);

        return keyGen;
    }

    /**
     * Returns the provider of this <code>KeyGenerator</code> object.
     *
     * @return the provider of this <code>KeyGenerator</code> object
     */
    public final Provider getProvider()
    {
        return provider;
    }

    /**
     * Initializes this key generator.
     *
     * @param random the source of randomness for this generator
     */
    public final void init(
        SecureRandom    random)
    {
        keyGenerator.engineInit(random);
    }

    /**
     * Initializes this key generator with the specified parameter set.
     * <p>
     * If this key generator requires any random bytes, it will get them
     * using the * <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
     * <code>SecureRandom</code></a> implementation of the highest-priority installed
     * provider as the source of randomness.
     * (If none of the installed providers supply an implementation of
     * SecureRandom, a system-provided source of randomness will be used.)
     *
     * @param params the key generation parameters
     * @exception InvalidAlgorithmParameterException if the given parameters are inappropriate
     * for this key generator
     */
    public final void init(
        AlgorithmParameterSpec  params)
    throws InvalidAlgorithmParameterException
    {
        keyGenerator.engineInit(params, new SecureRandom());
    }

    /**
     * Initializes this key generator with the specified parameter set and a user-provided source of randomness.
     *
     * @param params the key generation parameters
     * @param random the source of randomness for this key generator
     * @exception InvalidAlgorithmParameterException if <code>params</code> is inappropriate for this key generator
     */
    public final void init(
        AlgorithmParameterSpec  params,
        SecureRandom            random)
    throws InvalidAlgorithmParameterException
    {
        keyGenerator.engineInit(params, random);
    }

    /**
     * Initializes this key generator for a certain keysize.
     * <p>
     * If this key generator requires any random bytes, it will get them using the
     * <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
     * <code>SecureRandom</code></a> implementation of the highest-priority installed provider as
     * the source of randomness. (If none of the installed providers supply an implementation of
     * SecureRandom, a system-provided source of randomness will be used.)
     *
     * @param keysize the keysize. This is an algorithm-specific metric, specified in number of bits.
     * @exception InvalidParameterException if the keysize is wrong or not supported.
     */
    public final void init(
        int keysize)
    {
        keyGenerator.engineInit(keysize, new SecureRandom());
    }

    /**
     * Initializes this key generator for a certain keysize, using a user-provided source of randomness.
     *
     * @param keysize the keysize. This is an algorithm-specific metric, specified in number of bits.
     * @param random the source of randomness for this key generator
     * @exception InvalidParameterException if the keysize is wrong or not supported.
     */
    public final void init(
        int             keysize,
        SecureRandom    random)
    {
        keyGenerator.engineInit(keysize, random);
    }

    /**
     * Generates a secret key.
     *
     * @return the new key
     */
    public final SecretKey generateKey()
    {
        return keyGenerator.engineGenerateKey();
    }
}
