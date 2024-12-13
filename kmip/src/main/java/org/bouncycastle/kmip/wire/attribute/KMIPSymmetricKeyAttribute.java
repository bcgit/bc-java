package org.bouncycastle.kmip.wire.attribute;

import org.bouncycastle.kmip.wire.enumeration.KMIPCryptographicAlgorithm;

public class KMIPSymmetricKeyAttribute
    extends KMIPCryptographicObject
{
    private KMIPCryptographicAlgorithm cryptographicAlgorithm;
    private int cryptographicLength;
    private int cryptographicUsageMask;

    /**
     * Constructor to initialize all fields of SymmetricKeyAttribute.
     *
     * @param cryptographicAlgorithm The cryptographic algorithm used.
     * @param cryptographicLength    The length of the cryptographic key.
     * @param cryptographicUsageMask The cryptographic usage mask.
     */
    public KMIPSymmetricKeyAttribute(KMIPCryptographicAlgorithm cryptographicAlgorithm, int cryptographicLength, int cryptographicUsageMask)
    {
        this.cryptographicAlgorithm = cryptographicAlgorithm;
        this.cryptographicLength = cryptographicLength;
        this.cryptographicUsageMask = cryptographicUsageMask;
    }

    // Getters

    /**
     * Gets the cryptographic algorithm.
     *
     * @return The cryptographic algorithm.
     */
    public KMIPCryptographicAlgorithm getCryptographicAlgorithm()
    {
        return cryptographicAlgorithm;
    }

    /**
     * Gets the cryptographic length.
     *
     * @return The length of the cryptographic key.
     */
    public int getCryptographicLength()
    {
        return cryptographicLength;
    }

    /**
     * Gets the cryptographic usage mask.
     *
     * @return The cryptographic usage mask.
     */
    public int getCryptographicUsageMask()
    {
        return cryptographicUsageMask;
    }

    // Setters

    /**
     * Sets the cryptographic algorithm.
     *
     * @param cryptographicAlgorithm The cryptographic algorithm to set.
     */
    public void setCryptographicAlgorithm(KMIPCryptographicAlgorithm cryptographicAlgorithm)
    {
        this.cryptographicAlgorithm = cryptographicAlgorithm;
    }

    /**
     * Sets the cryptographic length.
     *
     * @param cryptographicLength The length of the cryptographic key to set.
     */
    public void setCryptographicLength(int cryptographicLength)
    {
        this.cryptographicLength = cryptographicLength;
    }

    /**
     * Sets the cryptographic usage mask.
     *
     * @param cryptographicUsageMask The cryptographic usage mask to set.
     */
    public void setCryptographicUsageMask(int cryptographicUsageMask)
    {
        this.cryptographicUsageMask = cryptographicUsageMask;
    }
}
