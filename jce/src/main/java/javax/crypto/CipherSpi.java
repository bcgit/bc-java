package javax.crypto;

import java.security.Key;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class defines the <i>Service Provider Interface</i> (<b>SPI</b>)
 * for the <code>Cipher</code> class.
 * All the abstract methods in this class must be implemented by each 
 * cryptographic service provider who wishes to supply the implementation
 * of a particular cipher algorithm.
 * <p>
 * In order to create an instance of <code>Cipher</code>, which
 * encapsulates an instance of this <code>CipherSpi</code> class, an
 * application calls one of the
 * <a href = "Cipher.html#getInstance(java.lang.String)">getInstance</a>
 * factory methods of the
 * <a href = "Cipher.html">Cipher</a> engine class and specifies the requested
 * <i>transformation</i>.
 * Optionally, the application may also specify the name of a provider.
 * <p>
 * A <i>transformation</i> is a string that describes the operation (or
 * set of operations) to be performed on the given input, to produce some
 * output. A transformation always includes the name of a cryptographic
 * algorithm (e.g., <i>DES</i>), and may be followed by a feedback mode and
 * padding scheme.
 * <p>
 * A transformation is of the form:
 * <p>
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
 *
 * <p>A provider may supply a separate class for each combination
 * of <i>algorithm/mode/padding</i>, or may decide to provide more generic
 * classes representing sub-transformations corresponding to
 * <i>algorithm</i> or <i>algorithm/mode</i> or <i>algorithm//padding</i>
 * (note the double slashes),
 * in which case the requested mode and/or padding are set automatically by
 * the <code>getInstance</code> methods of <code>Cipher</code>, which invoke
 * the <a href = "#engineSetMode(java.lang.String)">engineSetMode</a> and
 * <a href = "#engineSetPadding(java.lang.String)">engineSetPadding</a>
 * methods of the provider's subclass of <code>CipherSpi</code>.
 *
 * <p>A <code>Cipher</code> property in a provider master class may have one of
 * the following formats:
 *
 * <ul>
 *
 * <li>
 * <pre>
 *     // provider's subclass of "CipherSpi" implements "algName" with
 *     // pluggable mode and padding
 *     <code>Cipher.</code><i>algName</i>
 * </pre>
 * 
 * <li>
 * <pre>
 *     // provider's subclass of "CipherSpi" implements "algName" in the
 *     // specified "mode", with pluggable padding
 *     <code>Cipher.</code><i>algName/mode</i>
 * </pre>
 * 
 * <li>
 * <pre>
 *    // provider's subclass of "CipherSpi" implements "algName" with the
 *    // specified "padding", with pluggable mode
 *    <code>Cipher.</code><i>algName//padding</i>
 * </pre>
 *
 * <li>
 * <pre>
 *    // provider's subclass of "CipherSpi" implements "algName" with the
 *    // specified "mode" and "padding"
 *    <code>Cipher.</code><i>algName/mode/padding</i>
 * </pre>
 *
 * </ul>
 *
 * <p>For example, a provider may supply a subclass of <code>CipherSpi</code>
 * that implements <i>DES/ECB/PKCS5Padding</i>, one that implements
 * <i>DES/CBC/PKCS5Padding</i>, one that implements
 * <i>DES/CFB/PKCS5Padding</i>, and yet another one that implements
 * <i>DES/OFB/PKCS5Padding</i>. That provider would have the following
 * <code>Cipher</code> properties in its master class:<p>
 *
 * <ul>
 *
 * <li>
 * <pre>
 *    <code>Cipher.</code><i>DES/ECB/PKCS5Padding</i>
 * </pre>
 *
 * <li>
 * <pre>
 *    <code>Cipher.</code><i>DES/CBC/PKCS5Padding</i>
 * </pre>
 *
 * <li>
 * <pre>
 *    <code>Cipher.</code><i>DES/CFB/PKCS5Padding</i>
 * </pre>
 *
 * <li>
 * <pre>
 *    <code>Cipher.</code><i>DES/OFB/PKCS5Padding</i>
 * </pre>
 *
 * </ul>
 *
 * <p>Another provider may implement a class for each of the above modes
 * (i.e., one class for <i>ECB</i>, one for <i>CBC</i>, one for <i>CFB</i>,
 * and one for <i>OFB</i>), one class for <i>PKCS5Padding</i>,
 * and a generic <i>DES</i> class that subclasses from <code>CipherSpi</code>.
 * That provider would have the following
 * <code>Cipher</code> properties in its master class:<p>
 *
 * <ul>
 *
 * <li>
 * <pre>
 *    <code>Cipher.</code><i>DES</i>
 * </pre>
 *
 * </ul>
 *
 * <p>The <code>getInstance</code> factory method of the <code>Cipher</code>
 * engine class follows these rules in order to instantiate a provider's
 * implementation of <code>CipherSpi</code> for a
 * transformation of the form "<i>algorithm</i>":
 *
 * <ol>
 * <li>
 * Check if the provider has registered a subclass of <code>CipherSpi</code>
 * for the specified "<i>algorithm</i>".
 * <p>If the answer is YES, instantiate this
 * class, for whose mode and padding scheme default values (as supplied by
 * the provider) are used.
 * <p>If the answer is NO, throw a <code>NoSuchAlgorithmException</code>
 * exception.
 * </ol>
 *  
 * <p>The <code>getInstance</code> factory method of the <code>Cipher</code>
 * engine class follows these rules in order to instantiate a provider's
 * implementation of <code>CipherSpi</code> for a
 * transformation of the form "<i>algorithm/mode/padding</i>":
 *  
 * <ol>
 * <li>
 * Check if the provider has registered a subclass of <code>CipherSpi</code>
 * for the specified "<i>algorithm/mode/padding</i>" transformation.
 * <p>If the answer is YES, instantiate it.
 * <p>If the answer is NO, go to the next step.<p>
 * <li>
 * Check if the provider has registered a subclass of <code>CipherSpi</code>
 * for the sub-transformation "<i>algorithm/mode</i>".
 * <p>If the answer is YES, instantiate it, and call
 * <code>engineSetPadding(<i>padding</i>)</code> on the new instance.
 * <p>If the answer is NO, go to the next step.<p>
 * <li>
 * Check if the provider has registered a subclass of <code>CipherSpi</code>
 * for the sub-transformation "<i>algorithm//padding</i>" (note the double
 * slashes).
 * <p>If the answer is YES, instantiate it, and call
 * <code>engineSetMode(<i>mode</i>)</code> on the new instance.
 * <p>If the answer is NO, go to the next step.<p>
 * <li>
 * Check if the provider has registered a subclass of <code>CipherSpi</code>
 * for the sub-transformation "<i>algorithm</i>".
 * <p>If the answer is YES, instantiate it, and call
 * <code>engineSetMode(<i>mode</i>)</code> and
 * <code>engineSetPadding(<i>padding</i>)</code> on the new instance.
 * <p>If the answer is NO, throw a <code>NoSuchAlgorithmException</code>
 * exception.
 * </ol>
 * 
 * @see KeyGenerator
 * @see SecretKey
 */
public abstract class CipherSpi
{
    public CipherSpi()
    {
    }

    /**
     * Sets the mode of this cipher.
     *
     * @param mode the cipher mode
     * @exception NoSuchAlgorithmException if the requested cipher mode does not exist
     */
    protected abstract void engineSetMode(
        String  mode)
    throws NoSuchAlgorithmException;

    /**
     * Sets the padding mechanism of this cipher.
     *
     * @param padding the padding mechanism
     * @exception NoSuchPaddingException if the requested padding mechanism does not exist
     */
    protected abstract void engineSetPadding(
        String  padding)
    throws NoSuchPaddingException;

    /**
     * Returns the block size (in bytes).
     *
     * @return the block size (in bytes), or 0 if the underlying algorithm is not a block cipher
     */
    protected abstract int engineGetBlockSize();

    /**
     * Returns the length in bytes that an output buffer would
     * need to be in order to hold the result of the next <code>update</code>
     * or <code>doFinal</code> operation, given the input length
     * <code>inputLen</code> (in bytes).
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
     */
    protected abstract int engineGetOutputSize(
        int  inputLen);

    /**
     * Returns the initialization vector (IV) in a new buffer. 
     * <p>
     * This is useful in the context of password-based encryption or
     * decryption, where the IV is derived from a user-provided passphrase.
     *
     * @return the initialization vector in a new buffer, or null if the
     * underlying algorithm does not use an IV, or if the IV has not yet
     * been set.
     */
    protected abstract byte[] engineGetIV();
    
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
    protected abstract AlgorithmParameters engineGetParameters();

    /**
     * Initializes this cipher with a key and a source
     * of randomness.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
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
     * 
     * <p>Note that when a Cipher object is initialized, it loses all 
     * previously-acquired state. In other words, initializing a Cipher is 
     * equivalent to creating a new instance of that Cipher and initializing 
     * it.
     * @param opmode the operation mode of this cipher (this is one of
     * the following:
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param random the source of randomness
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher, or if this cipher is being initialized for
     * decryption and requires algorithm parameters that cannot be
     * determined from the given key.
     */
    protected abstract void engineInit(
        int             opmode,
        Key             key,
        SecureRandom    random)
    throws InvalidKeyException;

    /**
     * Initializes this cipher with a key, a set of
     * algorithm parameters, and a source of randomness.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     * <p>
     * If this cipher requires any algorithm parameters and
     *  <code>params</code> is null, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidAlgorithmParameterException</code> if it is being
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
     * @param opmode the operation mode of this cipher (this is one of the following: 
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     * @exception InvalidKeyException if the given key is inappropriate for initializing this cipher
     * @exception InvalidAlgorithmParameterException if the given algorithm parameters are inappropriate
     * for this cipher, or if this cipher is being initialized for decryption and requires
     * algorithm parameters and <code>params</code> is null.
     */
    protected abstract void engineInit(
        int                     opmode,
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random)
    throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * Initializes this cipher with a key, a set of
     * algorithm parameters, and a source of randomness.
     * <p>
     * The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     * <p>
     * If this cipher requires any algorithm parameters and
     * <code>params</code> is null, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidAlgorithmParameterException</code> if it is being
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
     * equivalent to creating a new instance of that Cipher and initializing it.
     *
     * @param opmode the operation mode of this cipher (this is one of the following: 
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code>
     * or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     * @exception InvalidKeyException if the given key is inappropriate for initializing this cipher
     * @exception InvalidAlgorithmParameterException if the given algorithm parameters are inappropriate
     * for this cipher, or if this cipher is being initialized for decryption and requires
     * algorithm parameters and <code>params</code> is null.
     */
    protected abstract void engineInit(
        int                 opmode,
        Key                 key,
        AlgorithmParameters params,
        SecureRandom        random)
    throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, are processed,
     * and the result is stored in a new buffer.
     * 
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @return the new buffer with the result, or null if the underlying cipher is a
     * block cipher and the input data is too short to result in a new block.
     */
    protected abstract byte[] engineUpdate(
        byte[]      input,
        int         inputOffset,
        int         inputLen);

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
     * a <code>ShortBufferException</code> is thrown.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result is stored
     * @return the number of bytes stored in <code>output</code>
     * @exception ShortBufferException if the given output buffer is too small to hold the result
     */
    protected abstract int engineUpdate(
        byte[]      input,
        int         inputOffset,
        int         inputLen,
        byte[]      output,
        int         outputOffset)
    throws ShortBufferException;

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
     * The data is encrypted or decrypted, depending on how this cipher was initialized.
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, and any input
     * bytes that may have been buffered during a previous <code>update</code>
     * operation, are processed, with padding (if requested) being applied.
     * The result is stored in a new buffer.
     * <p>
     * A call to this method resets this cipher object to the state 
     * it was in when previously initialized via a call to <code>engineInit</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>engineInit</code>) more data.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @return the new buffer with the result
     * @exception IllegalBlockSizeException if this cipher is a block cipher, no padding has been requested
     * (only in encryption mode), and the total input length of the data processed by this cipher is not a
     * multiple of block size
     * @exception BadPaddingException  if this cipher is in decryption mode, and (un)padding has been requested,
     * but the decrypted data is not bounded by the appropriate padding bytes
     */
    protected abstract byte[] engineDoFinal(
        byte[]      input,
        int         inputOffset,
        int         inputLen)
    throws IllegalBlockSizeException, BadPaddingException;

    /**
     * Encrypts or decrypts data in a single-part operation,
     * or finishes a multiple-part operation.
     * The data is encrypted or decrypted, depending on how this cipher was
     * initialized.
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, and any input
     * bytes that may have been buffered during a previous <code>update</code>
     * operation, are processed, with padding (if requested) being applied.
     * The result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code> inclusive.
     * <p>
     * If the <code>output</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown.
     * <p>
     * A call to this method resets this cipher object to the state 
     * it was in when previously initialized via a call to
     * <code>engineInit</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>engineInit</code>) more data.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result is stored
     * @return the number of bytes stored in <code>output</code>
     * @exception IllegalBlockSizeException if this cipher is a block cipher, no padding has been
     * requested (only in encryption mode), and the total input length of the data processed by this
     * cipher is not a multiple of block size
     * @exception ShortBufferException if the given output buffer is too small to hold the result
     * @exception BadPaddingException if this cipher is in decryption mode, and (un)padding has been requested,
     * but the decrypted data is not bounded by the appropriate padding bytes
     */
    protected abstract int engineDoFinal(
        byte[]      input,
        int         inputOffset,
        int         inputLen,
        byte[]      output,
        int         outputOffset)
    throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;

    /**
     * Wrap a key.
     * <p>
     * This concrete method has been added to this previously-defined
     * abstract class. (For backwards compatibility, it cannot be abstract.)
     * It may be overridden by a provider to wrap a key.
     * Such an override is expected to throw an IllegalBlockSizeException or
     * InvalidKeyException (under the specified circumstances),
     * if the given key cannot be wrapped.
     * If this method is not overridden, it always throws an
     * UnsupportedOperationException.
     *
     * @param key the key to be wrapped.
     * @return the wrapped key.
     * @exception IllegalBlockSizeException if this cipher is a block cipher, no padding has been requested,
     * and the length of the encoding of the key to be wrapped is not a multiple of the block size.
     * @exception InvalidKeyException if it is impossible or unsafe to wrap the key with this cipher (e.g.,
     * a hardware protected key is being passed to a software-only cipher).
     */
    protected byte[] engineWrap(
        Key     key)
    throws IllegalBlockSizeException, InvalidKeyException
    {
        throw new UnsupportedOperationException("Underlying cipher does not support key wrapping");
    }

    /**
     * Unwrap a previously wrapped key.
     *
     * <p>This concrete method has been added to this previously-defined
     * abstract class. (For backwards compatibility, it cannot be abstract.)
     * It may be overridden by a provider to unwrap a previously wrapped key.
     * Such an override is expected to throw an InvalidKeyException if
     * the given wrapped key cannot be unwrapped.
     * If this method is not overridden, it always throws an
     * UnsupportedOperationException.
     *
     * @param wrappedKey the key to be unwrapped.
     * @param wrappedKeyAlgorithm the algorithm associated with the wrapped key.
     * @param wrappedKeyType the type of the wrapped key. This is one of <code>SECRET_KEY</code>,
     * <code>PRIVATE_KEY</code>, or <code>PUBLIC_KEY</code>.
     * @return the unwrapped key.
     * @exception InvalidKeyException if <code>wrappedKey</code> does not represent a wrapped key,
     * or if the algorithm associated with the wrapped key is different from <code>wrappedKeyAlgorithm</code> 
     * and/or its key type is different from <code>wrappedKeyType</code>.
     * @exception NoSuchAlgorithmException - if no installed providers can create keys for the
     * <code>wrappedKeyAlgorithm</code>.
     */
    protected java.security.Key engineUnwrap(
        byte[]  wrappedKey,
        String  wrappedKeyAlgorithm,
        int     wrappedKeyType)
    throws InvalidKeyException, NoSuchAlgorithmException
    {
        throw new UnsupportedOperationException("Underlying cipher does not support key unwrapping");
    }

    /**
     * Returns the key size of the given key object.
     * <p>
     * This concrete method has been added to this previously-defined
     * abstract class. It throws an <code>UnsupportedOperationException</code>
     * if it is not overridden by the provider.
     * 
     * @param key the key object.
     * @return the key size of the given key object.
     * @exception InvalidKeyException if <code>key</code> is invalid.
     */
    protected int engineGetKeySize(
        Key     key)
    throws InvalidKeyException
    {
        throw new UnsupportedOperationException("Key size unavailable");
    }
}
