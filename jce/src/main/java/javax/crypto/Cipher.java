package javax.crypto;

import java.util.StringTokenizer;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class provides the functionality of a cryptographic cipher for
 * encryption and decryption. It forms the core of the Java Cryptographic
 * Extension (JCE) framework.
 * <p>
 * In order to create a Cipher object, the application calls the
 * Cipher's <code>getInstance</code> method, and passes the name of the
 * requested <i>transformation</i> to it. Optionally, the name of a provider
 * may be specified.
 * <p>
 * A <i>transformation</i> is a string that describes the operation (or
 * set of operations) to be performed on the given input, to produce some
 * output. A transformation always includes the name of a cryptographic
 * algorithm (e.g., <i>DES</i>), and may be followed by a feedback mode and
 * padding scheme.
 * 
 * <p> A transformation is of the form:<p>
 * 
 * <ul>
 * <li>"<i>algorithm/mode/padding</i>" or
 * <p>
 * <li>"<i>algorithm</i>"
 * </ul>
 * 
 * <P> (in the latter case,
 * provider-specific default values for the mode and padding scheme are used).
 * For example, the following is a valid transformation:<p>
 * 
 * <pre>
 *     Cipher c = Cipher.getInstance("<i>DES/CBC/PKCS5Padding</i>");
 * </pre>
 * <p>
 * When requesting a block cipher in stream cipher mode (e.g.,
 * <code>DES</code> in <code>CFB</code> or <code>OFB</code> mode), the user may
 * optionally specify the number of bits to be
 * processed at a time, by appending this number to the mode name as shown in
 * the "<i>DES/CFB8/NoPadding</i>" and "<i>DES/OFB32/PKCS5Padding</i>"
 * transformations. If no such number is specified, a provider-specific default
 * is used. (For example, the "SunJCE" provider uses a default of 64 bits.)
 */
public class Cipher
{
    static private final int    UNINITIALIZED     = 0;

    static public final int     ENCRYPT_MODE    = 1;
    static public final int     DECRYPT_MODE    = 2;
    static public final int     WRAP_MODE       = 3;
    static public final int     UNWRAP_MODE     = 4;

    static public final int     PUBLIC_KEY      = 1;
    static public final int     PRIVATE_KEY     = 2;
    static public final int     SECRET_KEY      = 3;

    private CipherSpi   cipherSpi;
    private Provider    provider;
    private String      transformation;

    private int         mode = UNINITIALIZED;

    /**
     * Creates a Cipher object.
     *
     * @param cipherSpi the delegate
     * @param provider the provider
     * @param transformation the transformation
     */
    protected Cipher(
        CipherSpi       cipherSpi,
        Provider        provider,
        String          transformation)
    {
        this.cipherSpi = cipherSpi;
        this.provider = provider;
        this.transformation = transformation;
    }

    /**
     * Generates a <code>Cipher</code> object that implements the specified
     * transformation.
     * <p>
     * If the default provider package supplies an implementation of the
     * requested transformation, an instance of <code>Cipher</code> containing
     * that implementation is returned.
     * If the transformation is not available in the default provider package,
     * other provider packages are searched.
     *
     * @param transformation the name of the transformation, e.g., <i>DES/CBC/PKCS5Padding</i>.
     * See Appendix A in the Java Cryptography Extension API Specification &amp; Reference
     * for information about standard transformation names.
     *
     * @return a cipher that implements the requested transformation
     * @exception NoSuchAlgorithmException if the specified transformation is not available in the default
     * provider package or any of the other provider packages that were searched.
     * @exception NoSuchPaddingException if <code>transformation</code> contains a padding scheme that is
     * not available.
     */
    public static final Cipher getInstance(
        String transformation)
    throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        try
        {
            JCEUtil.Implementation  imp = JCEUtil.getImplementation("Cipher", transformation, (String) null);

            if (imp != null)
            {
                return new Cipher((CipherSpi)imp.getEngine(), imp.getProvider(), transformation);
            }

            //
            // try the long way
            //
            StringTokenizer tok = new StringTokenizer(transformation, "/");
            String          algorithm = tok.nextToken();

            imp = JCEUtil.getImplementation("Cipher", algorithm, (String) null);

            if (imp == null)
            {
                throw new NoSuchAlgorithmException(transformation + " not found");
            }

            CipherSpi cipherSpi = (CipherSpi)imp.getEngine();

            //
            // make sure we don't get fooled by a "//" in the string
            //
            if (tok.hasMoreTokens() && !transformation.regionMatches(algorithm.length(), "//", 0, 2))
            {
                cipherSpi.engineSetMode(tok.nextToken());
            }

            if (tok.hasMoreTokens())
            {
                cipherSpi.engineSetPadding(tok.nextToken());
            }

            return new Cipher(cipherSpi, imp.getProvider(), transformation);
        }
        catch (NoSuchProviderException e)
        {
            throw new NoSuchAlgorithmException(transformation + " not found");
        }
    }

    /**
     * Creates a <code>Cipher</code> object that implements the specified
     * transformation, as supplied by the specified provider.
     *
     * @param transformation the name of the transformation, e.g., <i>DES/CBC/PKCS5Padding</i>.
     * See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
     * for information about standard transformation names.
     *
     * @param provider the provider
     * @return a cipher that implements the requested transformation
     * @exception NoSuchAlgorithmException if no transformation was specified, or if the specified
     * transformation is not available from the specified provider.
     * @exception NoSuchPaddingException if <code>transformation</code> contains a padding scheme
     * that is not available.
     */
    public static final Cipher getInstance(
        String      transformation,
        Provider    provider)
    throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        if (transformation == null)
        {
            throw new IllegalArgumentException("No transformation specified for Cipher.getInstance()");
        }

        JCEUtil.Implementation  imp = JCEUtil.getImplementation("Cipher", transformation, provider);

        if (imp != null)
        {
            return new Cipher((CipherSpi)imp.getEngine(), imp.getProvider(), transformation);
        }

        //
        // try the long way
        //
        StringTokenizer tok = new StringTokenizer(transformation, "/");
        String          algorithm = tok.nextToken();

        imp = JCEUtil.getImplementation("Cipher", algorithm, provider);

        if (imp == null)
        {
            throw new NoSuchAlgorithmException(transformation + " not found");
        }

        CipherSpi cipherSpi = (CipherSpi)imp.getEngine();

        //
        // make sure we don't get fooled by a "//" in the string
        //
        if (tok.hasMoreTokens() && !transformation.regionMatches(algorithm.length(), "//", 0, 2))
        {
            cipherSpi.engineSetMode(tok.nextToken());
        }

        if (tok.hasMoreTokens())
        {
            cipherSpi.engineSetPadding(tok.nextToken());
        }

        return new Cipher(cipherSpi, imp.getProvider(), transformation);
    }

    /**
     * Creates a <code>Cipher</code> object that implements the specified
     * transformation, as supplied by the specified provider.
     *
     * @param transformation the name of the transformation, e.g., <i>DES/CBC/PKCS5Padding</i>.
     * See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
     * for information about standard transformation names.
     *
     * @param provider the name of the provider
     * @return a cipher that implements the requested transformation
     * @exception NoSuchAlgorithmException if no transformation was specified, or if the specified
     * transformation is not available from the specified provider.
     * @exception NoSuchProviderException if the specified provider has not been configured.
     * @exception NoSuchPaddingException if <code>transformation</code> contains a padding scheme
     * that is not available.
     */
    public static final Cipher getInstance(
        String      transformation,
        String      provider)
    throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
    {
        if (transformation == null)
        {
            throw new IllegalArgumentException("No transformation specified for Cipher.getInstance()");
        }

        JCEUtil.Implementation  imp = JCEUtil.getImplementation("Cipher", transformation, provider);

        if (imp != null)
        {
            return new Cipher((CipherSpi)imp.getEngine(), imp.getProvider(), transformation);
        }

        //
        // try the long way
        //
        StringTokenizer tok = new StringTokenizer(transformation, "/");
        String          algorithm = tok.nextToken();

        imp = JCEUtil.getImplementation("Cipher", algorithm, provider);

        if (imp == null)
        {
            throw new NoSuchAlgorithmException(transformation + " not found");
        }

        CipherSpi cipherSpi = (CipherSpi)imp.getEngine();

        //
        // make sure we don't get fooled by a "//" in the string
        //
        if (tok.hasMoreTokens() && !transformation.regionMatches(algorithm.length(), "//", 0, 2))
        {
            cipherSpi.engineSetMode(tok.nextToken());
        }

        if (tok.hasMoreTokens())
        {
            cipherSpi.engineSetPadding(tok.nextToken());
        }

        return new Cipher(cipherSpi, imp.getProvider(), transformation);
    }

    /**
     * Returns the provider of this <code>Cipher</code> object.
     *
     * @return the provider of this <code>Cipher</code> object
     */
    public final Provider getProvider()
    {
        return provider;
    }

    /**
     * Returns the algorithm name of this <code>Cipher</code> object.
     * <p>
     * This is the same name that was specified in one of the
     * <code>getInstance</code> calls that created this <code>Cipher</code>
     * object..
     *
     * @return the algorithm name of this <code>Cipher</code> object.
     */
    public final String getAlgorithm()
    {
        return transformation;
    }

    /**
     * Returns the block size (in bytes).
     *
     * @return the block size (in bytes), or 0 if the underlying algorithm is not a block cipher
     */
    public final int getBlockSize()
    {
        return cipherSpi.engineGetBlockSize();
    }

    /**
     * Returns the length in bytes that an output buffer would need to be in
     * order to hold the result of the next <code>update</code> or
     * <code>doFinal</code> operation, given the input length <code>inputLen</code> (in bytes).
     * <p>
     * This call takes into account any unprocessed (buffered) data from a
     * previous <code>update</code> call, and padding.
     * <p>
     * The actual output length of the next <code>update</code> or
     * <code>doFinal</code> call may be smaller than the length returned by
     * this method.
     *
     * @param inputLen the input length (in bytes)
     * @return the required output buffer size (in bytes)
     * @exception java.lang.IllegalStateException if this cipher is in a wrong state (e.g., has not
     * yet been initialized)
     */
    public final int getOutputSize(
        int     inputLen)
    throws IllegalStateException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        return cipherSpi.engineGetOutputSize(inputLen);
    }

    /**
     * Returns the initialization vector (IV) in a new buffer.
     * <p>
     * This is useful in the case where a random IV was created,
     * or in the context of password-based encryption or decryption, where the IV
     * is derived from a user-supplied password.
     *
     * @return the initialization vector in a new buffer, or null if the
     * underlying algorithm does not use an IV, or if the IV has not yet been set.
     */
    public final byte[] getIV()
    {
        return cipherSpi.engineGetIV();
    }

    /**
     * Returns the parameters used with this cipher.
     * <p>
     * The returned parameters may be the same that were used to initialize
     * this cipher, or may contain a combination of default and random
     * parameter values used by the underlying cipher implementation if this
     * cipher requires algorithm parameters but was not initialized with any.
     *
     * @return the parameters used with this cipher, or null if this cipher
     * does not use any parameters.
     */
    public final AlgorithmParameters getParameters()
    {
        return cipherSpi.engineGetParameters();
    }

    /**
     * Returns the exemption mechanism object used with this cipher.
     *
     * @return the exemption mechanism object used with this cipher, or
     * null if this cipher does not use any exemption mechanism.
     */
    public final ExemptionMechanism getExemptionMechanism()
    {
        return null;
    }

    /**
     * Initializes this cipher with a key.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending
     * on the value of <code>opmode</code>.
     * <p>
     * If this cipher requires any algorithm parameters that cannot be
     * derived from the given <code>key</code>, the underlying cipher
     * implementation is supposed to generate the required parameters itself
     * (using provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidKeyException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * <a href = "#getParameters()">getParameters</a> or
     * <a href = "#getIV()">getIV</a> (if the parameter is an IV).
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them using the <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
     * <code>SecureRandom</code></a> implementation of the highest-priority
     * installed provider as the source of randomness.
     * (If none of the installed providers supply an implementation of
     * SecureRandom, a system-provided source of randomness will be used.)
     * <p>
     * Note that when a Cipher object is initialized, it loses all 
     * previously-acquired state. In other words, initializing a Cipher is 
     * equivalent to creating a new instance of that Cipher and initializing 
     * it.
     *
     * @param opmode the operation mode of this cipher (this is one of the following:
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key the key
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher, or if this cipher is being initialized for
     * decryption and requires algorithm parameters that cannot be
     * determined from the given key, or if the given key has a keysize that
     * exceeds the maximum allowable keysize (as determined from the
     * configured jurisdiction policy files). Note: Jurisdiction files are ignored
     * in this implementation.
     */
    public final void init(
        int     opmode,
        Key     key)
    throws InvalidKeyException
    {
        cipherSpi.engineInit(opmode, key, new SecureRandom());
        mode = opmode;
    }

    /**
     * Initializes this cipher with a key and a source of randomness.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or  key unwrapping, depending
     * on the value of <code>opmode</code>.
     * <p>
     * If this cipher requires any algorithm parameters that cannot be
     * derived from the given <code>key</code>, the underlying cipher
     * implementation is supposed to generate the required parameters itself
     * (using provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidKeyException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * <a href = "#engineGetParameters()">engineGetParameters</a> or
     * <a href = "#engineGetIV()">engineGetIV</a> (if the parameter is an IV).
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <code>random</code>.
     * <p>
     * Note that when a Cipher object is initialized, it loses all 
     * previously-acquired state. In other words, initializing a Cipher is 
     * equivalent to creating a new instance of that Cipher and initializing 
     * it.
     * @param opmode the operation mode of this cipher (this is one of the
     * following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param random the source of randomness
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher, or if this cipher is being initialized for
     * decryption and requires algorithm parameters that cannot be
     * determined from the given key, or if the given key has a keysize that
     * exceeds the maximum allowable keysize (as determined from the
     * configured jurisdiction policy files). Note: Jurisdiction files are ignored
     * in this implementation.
     */
    public final void init(
        int             opmode,
        Key             key,
        SecureRandom    random)
    throws InvalidKeyException
    {
        cipherSpi.engineInit(opmode, key, random);
        mode = opmode;
    }

    /**
     * Initializes this cipher with a key and a set of algorithm parameters.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or  key unwrapping, depending
     * on the value of <code>opmode</code>.
     * <p>
     * If this cipher requires any algorithm parameters and
     * <code>params</code> is null, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidAlgorithmParameterException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * <a href = "#getParameters()">getParameters</a> or
     * <a href = "#getIV()">getIV</a> (if the parameter is an IV).
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them using the
     * <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
     * <code>SecureRandom</code></a> implementation of the highest-priority
     * installed provider as the source of randomness.
     * (If none of the installed providers supply an implementation of
     * SecureRandom, a system-provided source of randomness will be used.)
     * <p>
     * Note that when a Cipher object is initialized, it loses all 
     * previously-acquired state. In other words, initializing a Cipher is 
     * equivalent to creating a new instance of that Cipher and initializing 
     * it.
     *
     * @param opmode the operation mode of this cipher (this is one of the
     * following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code>
     * or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param params the algorithm parameters
     * @exception InvalidKeyException if the given key is inappropriate for initializing this
     * cipher, or its keysize exceeds the maximum allowable keysize (as determined from the
     * configured jurisdiction policy files).
     * @exception InvalidAlgorithmParameterException if the given algorithm parameters are
     * inappropriate for this cipher, or this cipher is being initialized for decryption and
     * requires algorithm parameters and <code>params</code> is null, or the given algorithm
     * parameters imply a cryptographic strength that would exceed the legal limits (as determined
     * from the configured jurisdiction policy files). Note: Jurisdiction files are ignored
     * in this implementation.
     */
    public final void init(
        int                     opmode,
        Key                     key,
        AlgorithmParameterSpec  params)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        cipherSpi.engineInit(opmode, key, params, new SecureRandom());
        mode = opmode;
    }

    /**
     * Initializes this cipher with a key, a set of algorithm
     * parameters, and a source of randomness.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or  key unwrapping, depending
     * on the value of <code>opmode</code>.
     * <p>
     * If this cipher requires any algorithm parameters and
     * <code>params</code> is null, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidAlgorithmParameterException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * <a href = "#getParameters()">getParameters</a> or
     * <a href = "#getIV()">getIV</a> (if the parameter is an IV).
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <code>random</code>.
     * <p>
     * Note that when a Cipher object is initialized, it loses all 
     * previously-acquired state. In other words, initializing a Cipher is 
     * equivalent to creating a new instance of that Cipher and initializing 
     * it.
     * 
     * @param opmode the operation mode of this cipher (this is one of the
     * following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher, or its keysize exceeds the maximum allowable
     * keysize (as determined from the configured jurisdiction policy files).
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters are inappropriate for this cipher,
     * or this cipher is being initialized for decryption and requires
     * algorithm parameters and <code>params</code> is null, or the given
     * algorithm parameters imply a cryptographic strength that would exceed
     * the legal limits (as determined from the configured jurisdiction
     * policy files).
     * Note: Jurisdiction files are ignored in this implementation.
     */
    public final void init(
        int                     opmode,
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        cipherSpi.engineInit(opmode, key, params, random);
        mode = opmode;
    }

    /**
     * Initializes this cipher with a key and a set of algorithm
     * parameters.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or  key unwrapping, depending
     * on the value of <code>opmode</code>.
     * <p>
     * If this cipher requires any algorithm parameters and
     * <code>params</code> is null, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidAlgorithmParameterException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * <a href = "#getParameters()">getParameters</a> or
     * <a href = "#getIV()">getIV</a> (if the parameter is an IV).
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them using the
     * <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
     * <code>SecureRandom</code></a> implementation of the highest-priority
     * installed provider as the source of randomness.
     * (If none of the installed providers supply an implementation of
     * SecureRandom, a system-provided source of randomness will be used.)
     * <p>
     * Note that when a Cipher object is initialized, it loses all 
     * previously-acquired state. In other words, initializing a Cipher is 
     * equivalent to creating a new instance of that Cipher and initializing 
     * it.
     *
     * @param opmode the operation mode of this cipher (this is one of the
     * following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code>
     * or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param params the algorithm parameters
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher, or its keysize exceeds the maximum allowable
     * keysize (as determined from the configured jurisdiction policy files).
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters are inappropriate for this cipher,
     * or this cipher is being initialized for decryption and requires
     * algorithm parameters and <code>params</code> is null, or the given
     * algorithm parameters imply a cryptographic strength that would exceed
     * the legal limits (as determined from the configured jurisdiction
     * policy files).
     * Note: Jurisdiction files are ignored in this implementation.
     */
    public final void init(
        int                     opmode,
        Key                     key,
        AlgorithmParameters     params)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        cipherSpi.engineInit(opmode, key, params, new SecureRandom());
        mode = opmode;
    }

    /**
     * Initializes this cipher with a key, a set of algorithm
     * parameters, and a source of randomness.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or  key unwrapping, depending
     * on the value of <code>opmode</code>.
     * <p>
     * If this cipher requires any algorithm parameters and
     * <code>params</code> is null, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidAlgorithmParameterException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * <a href = "#getParameters()">getParameters</a> or
     * <a href = "#getIV()">getIV</a> (if the parameter is an IV).
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <code>random</code>.
     * <p>
     * Note that when a Cipher object is initialized, it loses all 
     * previously-acquired state. In other words, initializing a Cipher is 
     * equivalent to creating a new instance of that Cipher and initializing 
     * it.
     *
     * @param opmode the operation mode of this cipher (this is one of the
     * following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code>
     * or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher, or its keysize exceeds the maximum allowable
     * keysize (as determined from the configured jurisdiction policy files).
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters are inappropriate for this cipher,
     * or this cipher is being initialized for decryption and requires
     * algorithm parameters and <code>params</code> is null, or the given
     * algorithm parameters imply a cryptographic strength that would exceed
     * the legal limits (as determined from the configured jurisdiction
     * policy files).
     * Note: Jurisdiction files are ignored in this implementation.
     */
    public final void init(
        int                 opmode,
        Key                 key,
        AlgorithmParameters params,
        SecureRandom        random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        cipherSpi.engineInit(opmode, key, params, random);
        mode = opmode;
    }

    /**
     * Initializes this cipher with the public key from the given certificate.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or  key unwrapping, depending
     * on the value of <code>opmode</code>.
     * <p>
     * If the certificate is of type X.509 and has a <i>key usage</i>
     * extension field marked as critical, and the value of the <i>key usage</i>
     * extension field implies that the public key in
     * the certificate and its corresponding private key are not
     * supposed to be used for the operation represented by the value 
     * of <code>opmode</code>,
     * an <code>InvalidKeyException</code>
     * is thrown.
     * <p>
     * If this cipher requires any algorithm parameters that cannot be
     * derived from the public key in the given certificate, the underlying 
     * cipher
     * implementation is supposed to generate the required parameters itself
     * (using provider-specific default or ramdom values) if it is being
     * initialized for encryption or key wrapping, and raise an <code>
     * InvalidKeyException</code> if it is being initialized for decryption or 
     * key unwrapping.
     * The generated parameters can be retrieved using
     * <a href = "#getParameters()">getParameters</a> or
     * <a href = "#getIV()">getIV</a> (if the parameter is an IV).
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them using the
     * <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
     * <code>SecureRandom</code></a>
     * implementation of the highest-priority installed provider as the source of randomness.
     * (If none of the installed providers supply an implementation of
     * SecureRandom, a system-provided source of randomness will be used.)
     * <p>
     * Note that when a Cipher object is initialized, it loses all 
     * previously-acquired state. In other words, initializing a Cipher is 
     * equivalent to creating a new instance of that Cipher and initializing 
     * it.
     * @param opmode the operation mode of this cipher (this is one of the
     * following:
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param certificate the certificate
     * @exception InvalidKeyException if the public key in the given
     * certificate is inappropriate for initializing this cipher, or this
     * cipher is being initialized for decryption or unwrapping keys and
     * requires algorithm parameters that cannot be determined from the
     * public key in the given certificate, or the keysize of the public key
     * in the given certificate has a keysize that exceeds the maximum
     * allowable keysize (as determined by the configured jurisdiction policy
     * files).
     * Note: Jurisdiction files are ignored in this implementation.
     */
    public final void init(
        int             opmode,
        Certificate     certificate)
    throws InvalidKeyException
    {
        cipherSpi.engineInit(opmode, certificate.getPublicKey(), new SecureRandom());
        mode = opmode;
    }

    /**
     * Initializes this cipher with the public key from the given certificate
     * and a source of randomness.
     * <p>The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping
     * or key unwrapping, depending on
     * the value of <code>opmode</code>.
     * <p>  
     * If the certificate is of type X.509 and has a <i>key usage</i>
     * extension field marked as critical, and the value of the <i>key usage</i>
     * extension field implies that the public key in
     * the certificate and its corresponding private key are not
     * supposed to be used for the operation represented by the value of
     * <code>opmode</code>,
     * an <code>InvalidKeyException</code>
     * is thrown.
     * <p>  
     * If this cipher requires any algorithm parameters that cannot be
     * derived from the public key in the given <code>certificate</code>,
     * the underlying cipher
     * implementation is supposed to generate the required parameters itself
     * (using provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidKeyException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * <a href = "#engineGetParameters()">engineGetParameters</a> or
     * <a href = "#engineGetIV()">engineGetIV</a> (if the parameter is an IV).
     * <p>  
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <code>random</code>.
     * <p>  
     * Note that when a Cipher object is initialized, it loses all 
     * previously-acquired state. In other words, initializing a Cipher is 
     * equivalent to creating a new instance of that Cipher and initializing 
     * it.
     *
     * @param opmode the operation mode of this cipher (this is one of the
     * following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param certificate the certificate
     * @param random the source of randomness
     * @exception InvalidKeyException if the public key in the given
     * certificate is inappropriate for initializing this cipher, or this
     * cipher is being initialized for decryption or unwrapping keys and
     * requires algorithm parameters that cannot be determined from the
     * public key in the given certificate, or the keysize of the public key
     * in the given certificate has a keysize that exceeds the maximum
     * allowable keysize (as determined by the configured jurisdiction policy
     * files).
     */
    public final void init(
        int             opmode,
        Certificate     certificate,
        SecureRandom    random)
    throws InvalidKeyException
    {
        cipherSpi.engineInit(opmode, certificate.getPublicKey(), random);
        mode = opmode;
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     * <p>
     * The bytes in the <code>input</code> buffer are processed, and the
     * result is stored in a new buffer.
     * <p>
     * If <code>input</code> has a length of zero, this method returns
     * <code>null</code>.
     *
     * @param input the input buffer
     * @return the new buffer with the result, or null if the underlying
     * cipher is a block cipher and the input data is too short to result in a
     * new block.
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     */
    public final byte[] update(
        byte[]      input)
    throws IllegalStateException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        if (input == null)
        {
            throw new IllegalArgumentException("Null input buffer");
        }

        if (input.length == 0)
        {
            return null;
        }

        return cipherSpi.engineUpdate(input, 0, input.length);
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, are processed,
     * and the result is stored in a new buffer.
     * <p>
     * If <code>inputLen</code> is zero, this method returns
     * <code>null</code>.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     * starts
     * @param inputLen the input length
     * @return the new buffer with the result, or null if the underlying
     * cipher is a block cipher and the input data is too short to result in a
     * new block.
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     */
    public final byte[] update(
        byte[]      input,
        int         inputOffset,
        int         inputLen)
    throws IllegalStateException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        if (input == null)
        {
            throw new IllegalArgumentException("Null input passed");
        }

        if (inputLen < 0 || inputOffset < 0
            || inputLen > (input.length - inputOffset))
        {
            throw new IllegalArgumentException("Bad inputOffset/inputLen");
        }

        if (inputLen == 0)
        {
            return null;
        }

        return cipherSpi.engineUpdate(input, inputOffset, inputLen);
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, are processed,
     * and the result is stored in the <code>output</code> buffer.
     * <p>
     * If the <code>output</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown. In this case, repeat this
     * call with a larger output buffer. Use 
     * <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
     * the output buffer should be.
     * <p>
     * If <code>inputLen</code> is zero, this method returns
     * a length of zero.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @return the number of bytes stored in <code>output</code>
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     * @exception ShortBufferException if the given output buffer is too small
     * to hold the result
     */
    public final int update(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output)
    throws IllegalStateException, ShortBufferException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        if (input == null)
        {
            throw new IllegalArgumentException("Null input passed");
        }

        if (inputLen < 0 || inputOffset < 0
            || inputLen > (input.length - inputOffset))
        {
            throw new IllegalArgumentException("Bad inputOffset/inputLen");
        }

        if (output == null)
        {
            throw new IllegalArgumentException("Null output passed");
        }

        if (inputLen == 0)
        {
            return 0;
        }

        return cipherSpi.engineUpdate(input, inputOffset, inputLen, output, 0);
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, are processed,
     * and the result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code> inclusive.
     * <p>
     * If the <code>output</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown. In this case, repeat this
     * call with a larger output buffer. Use 
     * <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
     * the output buffer should be.
     * <p>
     * If <code>inputLen</code> is zero, this method returns
     * a length of zero.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result
     * is stored
     * @return the number of bytes stored in <code>output</code>
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     * @exception ShortBufferException if the given output buffer is too small
     * to hold the result
     */
    public final int update(
        byte[]      input,
        int         inputOffset,
        int         inputLen,
        byte[]      output,
        int         outputOffset)
    throws IllegalStateException, ShortBufferException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        if (input == null)
        {
            throw new IllegalArgumentException("Null input passed");
        }

        if (inputLen < 0 || inputOffset < 0
            || inputLen > (input.length - inputOffset))
        {
            throw new IllegalArgumentException("Bad inputOffset/inputLen");
        }

        if (output == null)
        {
            throw new IllegalArgumentException("Null output passed");
        }

        if (outputOffset < 0 || outputOffset >= output.length)
        {
            throw new IllegalArgumentException("Bad outputOffset");
        }

        if (inputLen == 0)
        {
            return 0;
        }

        return cipherSpi.engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    /**
     * Finishes a multiple-part encryption or decryption operation, depending
     * on how this cipher was initialized.
     * <p>
     * Input data that may have been buffered during a previous
     * <code>update</code> operation is processed, with padding (if requested)
     * being applied.
     * The result is stored in a new buffer.
     * <p>
     * A call to this method resets this cipher object to the state 
     * it was in when previously initialized via a call to <code>init</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>init</code>) more data.
     * @return the new buffer with the result
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     */
    public final byte[] doFinal()
    throws java.lang.IllegalStateException, IllegalBlockSizeException,
        BadPaddingException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        return cipherSpi.engineDoFinal(null, 0, 0);
    }

    /**
     * Finishes a multiple-part encryption or decryption operation, depending
     * on how this cipher was initialized.
     * <p>
     * Input data that may have been buffered during a previous
     * <code>update</code> operation is processed, with padding (if requested)
     * being applied.
     * The result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code> inclusive.
     * <p>
     * If the <code>output</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown. In this case, repeat this
     * call with a larger output buffer. Use 
     * <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
     * the output buffer should be.
     * <p>
     * A call to this method resets this cipher object to the state 
     * it was in when previously initialized via a call to <code>init</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>init</code>) more data.
     *
     * @param output the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result
     * is stored
     * @return the number of bytes stored in <code>output</code>
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size
     * @exception ShortBufferException if the given output buffer is too small
     * to hold the result
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     */
    public final int doFinal(
        byte[]      output,
        int         outputOffset)
    throws IllegalStateException, IllegalBlockSizeException,
         ShortBufferException, BadPaddingException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        if (output == null)
        {
            throw new IllegalArgumentException("Null output passed");
        }

        if (outputOffset < 0 || outputOffset >= output.length)
        {
            throw new IllegalArgumentException("Bad outputOffset");
        }

        return cipherSpi.engineDoFinal(null, 0, 0, output, outputOffset);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted,
     * depending on how this cipher was initialized.
     * <p>
     * The bytes in the <code>input</code> buffer, and any input bytes that
     * may have been buffered during a previous <code>update</code> operation,
     * are processed, with padding (if requested) being applied.
     * The result is stored in a new buffer.
     * <p>
     * A call to this method resets this cipher object to the state 
     * it was in when previously initialized via a call to <code>init</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>init</code>) more data.
     *
     * @param input the input buffer
     * @return the new buffer with the result
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     */
    public final byte[] doFinal(
        byte[]      input)
    throws java.lang.IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        if (input == null)
        {
            throw new IllegalArgumentException("Null input passed");
        }

        return cipherSpi.engineDoFinal(input, 0, input.length);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted,
     * depending on how this cipher was initialized.
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, and any input
     * bytes that may have been buffered during a previous <code>update</code>
     * operation, are processed, with padding (if requested) being applied.
     * The result is stored in a new buffer.
     * <p>A call to this method resets this cipher object to the state 
     * it was in when previously initialized via a call to <code>init</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>init</code>) more data.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @return the new buffer with the result
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     */
    public final byte[] doFinal(
        byte[]      input,
        int         inputOffset,
        int         inputLen)
    throws IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        if (input == null)
        {
            throw new IllegalArgumentException("Null input passed");
        }

        if (inputLen < 0 || inputOffset < 0
            || inputLen > (input.length - inputOffset))
        {
            throw new IllegalArgumentException("Bad inputOffset/inputLen");
        }

        return cipherSpi.engineDoFinal(input, inputOffset, inputLen);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted,
     * depending on how this cipher was initialized.
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, and any input
     * bytes that may have been buffered during a previous <code>update</code>
     * operation, are processed, with padding (if requested) being applied.
     * The result is stored in the <code>output</code> buffer.
     * <p>
     * If the <code>output</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown. In this case, repeat this
     * call with a larger output buffer. Use 
     * <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
     * the output buffer should be.
     * <p>
     * A call to this method resets this cipher object to the state 
     * it was in when previously initialized via a call to <code>init</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>init</code>) more data.
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @return the number of bytes stored in <code>output</code>
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size
     * @exception ShortBufferException if the given output buffer is too small
     * to hold the result
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     */
    public final int doFinal(
        byte[]      input,
        int         inputOffset,
        int         inputLen,
        byte[]      output)
    throws IllegalStateException, ShortBufferException,
                IllegalBlockSizeException, BadPaddingException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        if (input == null)
        {
            throw new IllegalArgumentException("Null input passed");
        }

        if (inputLen < 0 || inputOffset < 0
            || inputLen > (input.length - inputOffset))
        {
            throw new IllegalArgumentException("Bad inputOffset/inputLen");
        }

        if (output == null)
        {
            throw new IllegalArgumentException("Null output passed");
        }

        return cipherSpi.engineDoFinal(input, inputOffset, inputLen, output, 0);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted,
     * depending on how this cipher was initialized.
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, and any input
     * bytes that may have been buffered during a previous
     * <code>update</code> operation, are processed, with padding
     * (if requested) being applied.
     * The result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code> inclusive.
     * <p>
     * If the <code>output</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown. In this case, repeat this
     * call with a larger output buffer. Use 
     * <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
     * the output buffer should be.
     * <p>
     * A call to this method resets this cipher object to the state 
     * it was in when previously initialized via a call to <code>init</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>init</code>) more data.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result is
     * stored
     * @return the number of bytes stored in <code>output</code>
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size
     * @exception ShortBufferException if the given output buffer is too small
     * to hold the result
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     */
    public final int doFinal(
        byte[]      input,
        int         inputOffset,
        int         inputLen,
        byte[]      output,
        int         outputOffset)
    throws IllegalStateException, ShortBufferException,
        IllegalBlockSizeException, BadPaddingException
    {
        if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
        {
            throw new IllegalStateException("Cipher is uninitialised");
        }

        if (input == null)
        {
            throw new IllegalArgumentException("Null input passed");
        }

        if (inputLen < 0 || inputOffset < 0
            || inputLen > (input.length - inputOffset))
        {
            throw new IllegalArgumentException("Bad inputOffset/inputLen");
        }

        if (output == null)
        {
            throw new IllegalArgumentException("Null output passed");
        }

        if (outputOffset < 0 || outputOffset >= output.length)
        {
            throw new IllegalArgumentException("Bad outputOffset");
        }

        return cipherSpi.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    /**
     * Wrap a key.
     *
     * @param key the key to be wrapped.
     * @return the wrapped key.
     * @exception IllegalStateException if this cipher is in a wrong state (e.g., has not
     * been initialized).
     * @exception IllegalBlockSizeException if this cipher is a block cipher, no padding
     * has been requested, and the length of the encoding of the key to be wrapped is not a
     * multiple of the block size.
     * @exception <DD>java.security.InvalidKeyException - if it is impossible or unsafe to
     * wrap the key with this cipher (e.g., a hardware protected key is being passed to a
     * software-only cipher).
     */
    public final byte[] wrap(
        Key   key)
    throws IllegalStateException, IllegalBlockSizeException, InvalidKeyException
    {
        if (mode != WRAP_MODE)
        {
            throw new IllegalStateException("Cipher is not initialised for wrapping");
        }

        if (key == null)
        {
            throw new IllegalArgumentException("Null key passed");
        }

        return cipherSpi.engineWrap(key);
    }

    /**
     * Unwrap a previously wrapped key.
     *
     * @param wrappedKey the key to be unwrapped.
     * @param wrappedKeyAlgorithm the algorithm associated with the wrapped key.
     * @param wrappedKeyType the type of the wrapped key. This must be one of
     * <code>SECRET_KEY</code>, <code>PRIVATE_KEY</code>, or <code>PUBLIC_KEY</code>.
     * @return the unwrapped key.   
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized).
     * @exception InvalidKeyException if <code>wrappedKey</code> does not
     * represent a wrapped key, or if the algorithm associated with the
     * wrapped key is different from <code>wrappedKeyAlgorithm</code> 
     * and/or its key type is different from <code>wrappedKeyType</code>.
     * @exception NoSuchAlgorithmException - if no installed providers
     * can create keys for the <code>wrappedKeyAlgorithm</code>.
     */
    public final Key unwrap(
        byte[]      wrappedKey,
        String      wrappedKeyAlgorithm,
        int         wrappedKeyType)
    throws IllegalStateException, InvalidKeyException, NoSuchAlgorithmException
    {
        if (mode != UNWRAP_MODE)
        {
            throw new IllegalStateException("Cipher is not initialised for unwrapping");
        }

        if (wrappedKeyType != SECRET_KEY && wrappedKeyType != PUBLIC_KEY
            && wrappedKeyType != PRIVATE_KEY)
        {
            throw new IllegalArgumentException("Invalid key type argument");
        }

        if (wrappedKey == null)
        {
            throw new IllegalArgumentException("Null wrappedKey passed");
        }

        if (wrappedKeyAlgorithm == null)
        {
            throw new IllegalArgumentException("Null wrappedKeyAlgorithm string passed");
        }

        return cipherSpi.engineUnwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }
}
