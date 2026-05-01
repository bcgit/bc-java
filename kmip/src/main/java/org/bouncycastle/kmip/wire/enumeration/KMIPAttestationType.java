package org.bouncycastle.kmip.wire.enumeration;

public enum KMIPAttestationType
    implements KMIPEnumeration
{
    TPMQuote(0x00000001),          // TPM Quote
    TCGIntegrityReport(0x00000002), // TCG Integrity Report
    SAMLAssertion(0x00000003);      // SAML Assertion

    private final int value;

    /**
     * Constructor for AttestationType.
     *
     * @param value The hex value corresponding to the attestation type.
     */
    KMIPAttestationType(int value)
    {
        this.value = value;
    }

    /**
     * Gets the hex value associated with the attestation type.
     *
     * @return The hex value as an int.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves an AttestationType based on the provided value.
     *
     * @param value The hex value of the attestation type.
     * @return The corresponding AttestationType enum.
     * @throws IllegalArgumentException if the value does not match any attestation type.
     */
    public static KMIPAttestationType fromValue(int value)
    {
        for (KMIPAttestationType type : KMIPAttestationType.values())
        {
            if (type.getValue() == value)
            {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown attestation type value: " + value);
    }
}
