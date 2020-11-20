package org.bouncycastle.crypto.engines;

/**
 * an implementation of the ARIA Key Wrapper from the NIST Key Wrap
 * Specification.
 * <p>
 * For further details see: <a href="https://csrc.nist.gov/encryption/kms/key-wrap.pdf">https://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
 */
public class ARIAWrapEngine
    extends RFC3394WrapEngine
{
    /**
     * Create a regular AESWrapEngine specifying the encrypt for wrapping, decrypt for unwrapping.
     */
    public ARIAWrapEngine()
    {
        super(new ARIAEngine());
    }

    /**
     * Create an AESWrapEngine where the underlying cipher is set to decrypt for wrapping, encrypt for unwrapping.
     *
     * @param useReverseDirection true if underlying cipher should be used in decryption mode, false otherwise.
     */
    public ARIAWrapEngine(boolean useReverseDirection)
    {
        super(new ARIAEngine(), useReverseDirection);
    }
}
