package javax.crypto;

import java.security.Key;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class defines the <i>Service Provider Interface</i> (<b>SPI</b>)
 * for the <code>KeyAgreement</code> class.
 * All the abstract methods in this class must be implemented by each 
 * cryptographic service provider who wishes to supply the implementation
 * of a particular key agreement algorithm.
 * <p>
 * The keys involved in establishing a shared secret are created by one of the
 * key generators (<code>KeyPairGenerator</code> or <code>KeyGenerator</code>),
 * a <code>KeyFactory</code>, or as a result from an intermediate phase of the key
 * agreement protocol (see <a href = "#engineDoPhase(java.security.Key, boolean)">engineDoPhase</a>).
 * <p>
 * For each of the correspondents in the key exchange, <code>engineDoPhase</code>
 * needs to be called. For example, if the key exchange is with one other
 * party, <code>engineDoPhase</code> needs to be called once, with the
 * <code>lastPhase</code> flag set to <code>true</code>.
 * If the key exchange is with two other parties, <code>engineDoPhase</code> needs to be called twice,
 * the first time setting the <code>lastPhase</code> flag to
 * <code>false</code>, and the second time setting it to <code>true</code>.
 * There may be any number of parties involved in a key exchange.
 *
 * @see KeyGenerator
 * @see SecretKey
 */
public abstract class KeyAgreementSpi
{
    public KeyAgreementSpi()
    {
    }

    /**
     * Initializes this key agreement with the given key and source of
     * randomness. The given key is required to contain all the algorithm
     * parameters required for this key agreement.
     * <p>
     * If the key agreement algorithm requires random bytes, it gets them
     * from the given source of randomness, <code>random</code>.
     * However, if the underlying
     * algorithm implementation does not require any random bytes,
     * <code>random</code> is ignored.
     *
     * @param key the party's private information. For example, in the case
     * of the Diffie-Hellman key agreement, this would be the party's own Diffie-Hellman private key.
     * @param random the source of randomness
     * @exception InvalidKeyException if the given key is inappropriate for this key agreement, e.g., is
     *  of the wrong type or has an incompatible algorithm type.
     */
    protected abstract void engineInit(
        Key             key,
        SecureRandom    random)
    throws InvalidKeyException;

    /**
     * Initializes this key agreement with the given key, set of
     * algorithm parameters, and source of randomness.
     *
     * @param key the party's private information. For example, in the case
     * of the Diffie-Hellman key agreement, this would be the party's own
     * Diffie-Hellman private key.
     * @param params the key agreement parameters
     * @param random the source of randomness
     * @exception InvalidKeyException if the given key is inappropriate for this key agreement, e.g., is of the
     * wrong type or has an incompatible algorithm type.
     * @exception InvalidAlgorithmParameterException if the given parameters are inappropriate for this key
     * agreement.
     */
    protected abstract void engineInit(
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random)
    throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * Executes the next phase of this key agreement with the given
     * key that was received from one of the other parties involved in this key
     * agreement.
     * @param key  the key for this phase. For example, in the case of
     * Diffie-Hellman between 2 parties, this would be the other party's
     * Diffie-Hellman public key.
     * @param lastPhase flag which indicates whether or not this is the last
     * phase of this key agreement.
     * @return the (intermediate) key resulting from this phase, or null if this phase does not yield a key
     * @exception InvalidKeyException if the given key is inappropriate for this phase.
     * @exception IllegalStateException if this key agreement has not been initialized.
     */
    protected abstract Key engineDoPhase(
        Key     key,
        boolean lastPhase)
    throws InvalidKeyException, IllegalStateException;

    /**
     * Generates the shared secret and returns it in a new buffer.
     * <p>
     * This method resets this <code>KeyAgreementSpi</code> object, so that it
     * can be reused for further key agreements. Unless this key agreement is
     * reinitialized with one of the <code>engineInit</code> methods, the same
     * private information and algorithm parameters will be used for
     * subsequent key agreements.
     * @return the new buffer with the shared secret
     * @exception IllegalStateException if this key agreement has not been completed yet
     */
    protected abstract byte[] engineGenerateSecret()
        throws IllegalStateException;

    /**
     * Generates the shared secret, and places it into the buffer
     * <code>sharedSecret</code>, beginning at <code>offset</code> inclusive.
     * <p>
     * If the <code>sharedSecret</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown. In this case, this call should be
     * repeated with a larger output buffer. 
     * <p>
     * This method resets this <code>KeyAgreementSpi</code> object, so that it
     * can be reused for further key agreements. Unless this key agreement is
     * reinitialized with one of the <code>engineInit</code> methods, the same
     * private information and algorithm parameters will be used for subsequent key agreements.
     *
     * @param sharedSecret the buffer for the shared secret
     * @param offset the offset in <code>sharedSecret</code> where the shared secret will be stored
     * @return the number of bytes placed into <code>sharedSecret</code>
     * @exception IllegalStateException if this key agreement has not been completed yet
     * @exception ShortBufferException if the given output buffer is too small to hold the secret
     */
    protected abstract int engineGenerateSecret(
        byte[]      sharedSecret,
        int         offset)
    throws IllegalStateException, ShortBufferException;

    /**
     * Creates the shared secret and returns it as a secret key object
     * of the requested algorithm type.
     * <p>
     * This method resets this <code>KeyAgreementSpi</code> object, so that it
     * can be reused for further key agreements. Unless this key agreement is
     * reinitialized with one of the <code>engineInit</code> methods, the same
     * private information and algorithm parameters will be used for
     * subsequent key agreements.
     *
     * @param algorithm the requested secret key algorithm
     * @return the shared secret key
     * @exception IllegalStateException if this key agreement has not been completed yet
     * @exception NoSuchAlgorithmException if the requested secret key algorithm is not available
     * @exception InvalidKeyException if the shared secret key material cannot be used to generate
     * a secret key of the requested algorithm type (e.g., the key material is too short)
     */
    protected abstract SecretKey engineGenerateSecret(
        String      algorithm)
    throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException;
}
