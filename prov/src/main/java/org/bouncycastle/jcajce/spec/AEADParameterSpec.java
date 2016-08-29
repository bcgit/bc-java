package org.bouncycastle.jcajce.spec;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * ParameterSpec for AEAD modes which allows associated data to be added via an algorithm parameter spec.In normal
 * circumstances you would only want to use this if you had to work with the pre-JDK1.7 Cipher class as associated
 * data is ignored for the purposes of returning a Cipher's parameters.
 */
public class AEADParameterSpec
    extends IvParameterSpec
{
    private final byte[] associatedData;
    private final int macSizeInBits;

    /**
     * Base constructor.
     *
     * @param nonce nonce/iv to be used
     * @param macSizeInBits macSize in bits
     */
    public AEADParameterSpec(byte[] nonce, int macSizeInBits)
    {
        this(nonce, macSizeInBits, null);
    }

    /**
     * Base constructor with prepended associated data.
     *
     * @param nonce nonce/iv to be used
     * @param macSizeInBits macSize in bits
     * @param associatedData associated data to be prepended to the cipher stream.
     */
    public AEADParameterSpec(byte[] nonce, int macSizeInBits, byte[] associatedData)
    {
        super(nonce);

        this.macSizeInBits = macSizeInBits;
        this.associatedData = Arrays.clone(associatedData);
    }

    /**
     * Return the size of the MAC associated with this parameter spec.
     *
     * @return the MAC size in bits.
     */
    public int getMacSizeInBits()
    {
        return macSizeInBits;
    }

    /**
     * Return the associated data associated with this parameter spec.
     *
     * @return the associated data, null if there isn't any.
     */
    public byte[] getAssociatedData()
    {
        return Arrays.clone(associatedData);
    }

    /**
     * Return the nonce (same as IV) associated with this parameter spec.
     *
     * @return the nonce/IV.
     */
    public byte[] getNonce()
    {
        return getIV();
    }
}
