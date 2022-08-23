package org.bouncycastle.crypto;

public interface EncapsulatedSecretExtractor
{
    /**
     * Generate an exchange pair based on the recipient public key.
     *
     * @param encapsulation the encapsulated secret.
     */
    byte[] extractSecret(byte[] encapsulation);

    /**
     * Return the length in bytes of the encapsulation.
     *
     * @return length in bytes of an encapsulation for this parameter set.
     */
    int getEncapsulationLength();
}
