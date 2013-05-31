package javax.crypto;

import java.security.Provider;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;

/**
 * This class represents a factory for secret keys.
 *
 * <p>
 * Key factories are used to convert <I>keys</I> (opaque
 * cryptographic keys of type <code>Key</code>) into <I>key specifications</I>
 * (transparent representations of the underlying key material), and vice versa.
 * Secret key factories operate only on secret (symmetric) keys.
 * <p>
 * Key factories are bi-directional, i.e., they allow to build an opaque
 * key object from a given key specification (key material), or to retrieve
 * the underlying key material of a key object in a suitable format.
 * <p>
 * Application developers should refer to their provider's documentation
 * to find out which key specifications are supported by the
 * <a href="#generateSecret(java.security.spec.KeySpec)">generateSecret</a> and
 * <a href="#getKeySpec(javax.crypto.SecretKey, java.lang.Class)">getKeySpec</a> methods.
 * For example, the DES secret-key factory supplied by the "SunJCE" provider
 * supports <code>DESKeySpec</code> as a transparent representation of DES
 * keys, and that provider's secret-key factory for Triple DES keys supports
 * <code>DESedeKeySpec</code> as a transparent representation of Triple DES keys.
 *
 * @see SecretKey
 * @see javax.crypto.spec.DESKeySpec
 * @see javax.crypto.spec.DESedeKeySpec
 * @see javax.crypto.spec.PBEKeySpec
 */
public class SecretKeyFactory
{
    SecretKeyFactorySpi keyFacSpi;
    Provider            provider;
    String              algorithm;

    /**
     * Creates a SecretKeyFactory object.
     *
     * @param keyFacSpi the delegate
     * @param provider the provider
     * @param algorithm the secret-key algorithm
     */
    protected SecretKeyFactory(
        SecretKeyFactorySpi keyFacSpi,
        Provider            provider,
        String              algorithm)
    {
        this.keyFacSpi = keyFacSpi;
        this.provider = provider;
        this.algorithm = algorithm;
    }

    /**
     * Generates a <code>SecretKeyFactory</code> object for the specified secret-key algorithm.
     * If the default provider package provides an implementation of the
     * requested factory, an instance of <code>SecretKeyFactory</code>
     * containing that implementation is returned.
     * If the requested factory is not available in the default provider
     * package, other provider packages are searched.
     *
     * @param algorithm the standard name of the requested secret-key algorithm. 
     * See Appendix A in the Java Cryptography Extension API Specification &amp; Reference </a> 
     * for information about standard algorithm names.
     * @return a <code>SecretKeyFactory</code> object for the specified secret-key algorithm.
     * @exception NoSuchAlgorithmException if a secret-key factory for the specified algorithm
     * is not available in the default provider package or any of the other provider packages
     * that were searched.
     */
    public static final SecretKeyFactory getInstance(
        String      algorithm)
    throws NoSuchAlgorithmException
    {
        try
        {
            JCEUtil.Implementation imp = JCEUtil.getImplementation("SecretKeyFactory", algorithm, (String) null);

            if (imp == null)
            {
                throw new NoSuchAlgorithmException(algorithm + " not found");
            }

            SecretKeyFactory keyFact = new SecretKeyFactory(
                                    (SecretKeyFactorySpi)imp.getEngine(), imp.getProvider(), algorithm);

            return keyFact;
        }
        catch (NoSuchProviderException e)
        {
            throw new NoSuchAlgorithmException(algorithm + " not found");
        }
    }

    /**
     * Generates a <code>SecretKeyFactory</code> object for the specified
     * secret-key algorithm from the specified provider.
     *
     * @param algorithm the standard name of the requested secret-key algorithm. 
     * See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
     * for information about standard algorithm names.
     * @param provider the name of the provider.
     * @return a <code>SecretKeyFactory</code> object for the specified secret-key algorithm.
     * @exception NoSuchAlgorithmException if a secret-key factory for the specified algorithm is not
     * available from the specified provider.
     * @exception NoSuchProviderException if the specified provider has not been configured.
     */
    public static final SecretKeyFactory getInstance(
        String  algorithm,
        String  provider)
    throws NoSuchAlgorithmException, NoSuchProviderException
    {
        if (provider == null)
        {
            throw new IllegalArgumentException("No provider specified to SecretKeyFactory.getInstance()");
        }

        JCEUtil.Implementation imp = JCEUtil.getImplementation("SecretKeyFactory", algorithm, provider);

        if (imp == null)
        {
            throw new NoSuchAlgorithmException(algorithm + " not found");
        }

        SecretKeyFactory keyFact = new SecretKeyFactory(
                                    (SecretKeyFactorySpi)imp.getEngine(), imp.getProvider(), algorithm);

        return keyFact;
    }

    /**
     * Generates a <code>SecretKeyFactory</code> object for the specified
     * secret-key algorithm from the specified provider.
     *
     * @param algorithm the standard name of the requested secret-key algorithm. 
     * See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
     * for information about standard algorithm names.
     * @param provider the provider.
     * @return a <code>SecretKeyFactory</code> object for the specified secret-key algorithm.
     * @exception NoSuchAlgorithmException if a secret-key factory for the specified algorithm is not
     * available from the specified provider.
     */
    public static final SecretKeyFactory getInstance(
        String    algorithm,
        Provider  provider)
    throws NoSuchAlgorithmException
    {
        if (provider == null)
        {
            throw new IllegalArgumentException("No provider specified to SecretKeyFactory.getInstance()");
        }

        JCEUtil.Implementation imp = JCEUtil.getImplementation("SecretKeyFactory", algorithm, provider);

        if (imp == null)
        {
            throw new NoSuchAlgorithmException(algorithm + " not found");
        }

        SecretKeyFactory keyFact = new SecretKeyFactory(
                                    (SecretKeyFactorySpi)imp.getEngine(), imp.getProvider(), algorithm);

        return keyFact;
    }

    /**
     * Returns the provider of this <code>SecretKeyFactory</code> object.
     *
     * @return the provider of this <code>SecretKeyFactory</code> object
     */
    public final Provider getProvider()
    {
        return provider;
    }

    /**
     * Returns the algorithm name of this <code>SecretKeyFactory</code> object.
     * <p>
     * This is the same name that was specified in one of the <code>getInstance</code> calls
     * that created this <code>SecretKeyFactory</code> object.
     *
     * @return the algorithm name of this <code>SecretKeyFactory</code> object.
     */
    public final String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Generates a <code>SecretKey</code> object from the provided key specification (key material).
     *
     * @param keySpec the specification (key material) of the secret key
     * @return the secret key
     * @exception InvalidKeySpecException if the given key specification
     * is inappropriate for this secret-key factory to produce a secret key.
     */
    public final SecretKey generateSecret(
        KeySpec     keySpec)
    throws InvalidKeySpecException
    {
        return keyFacSpi.engineGenerateSecret(keySpec);
    }

    /**
     * Returns a specification (key material) of the given key object
     * in the requested format.
     *
     * @param key the key
     * @param keySpec the requested format in which the key material shall be
     * returned
     * @return the underlying key specification (key material) in the requested format
     * @exception InvalidKeySpecException if the requested key specification is inappropriate for
     * the given key (e.g., the algorithms associated with <code>key</code> and <code>keySpec</code> do
     * not match, or <code>key</code> references a key on a cryptographic hardware device whereas
     * <code>keySpec</code> is the specification of a software-based key), or the given key cannot be dealt with
     * (e.g., the given key has an algorithm or format not supported by this secret-key factory).
     */
    public final KeySpec getKeySpec(
        SecretKey   key,
        Class       keySpec)
    throws InvalidKeySpecException
    {
        return keyFacSpi.engineGetKeySpec(key, keySpec);
    }

    /**
     * Translates a key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding key object of this secret-key factory.
     *
     * @param key the key whose provider is unknown or untrusted
     * @return the translated key
     * @exception InvalidKeyException if the given key cannot be processed by this secret-key factory.
     */
    public final SecretKey translateKey(
        SecretKey   key)
        throws InvalidKeyException
    {
        return keyFacSpi.engineTranslateKey(key);
    }
}
