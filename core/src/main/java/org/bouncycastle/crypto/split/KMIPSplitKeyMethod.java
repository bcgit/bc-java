package org.bouncycastle.crypto.split;

/**
 * Enumeration for Split Key Methods.
 */
public enum KMIPSplitKeyMethod
{
    XOR(0x00000001),                       // XOR method
    POLYNOMIAL_GF_65536(0x00000002),        // Polynomial Sharing GF (2^16)
    POLYNOMIAL_PRIME_FIELD(0x00000003),   // Polynomial Sharing Prime Field
    POLYNOMIAL_GF_256(0x00000004);         // Polynomial Sharing GF (2^8)

    private final int value;

    KMIPSplitKeyMethod(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    /**
     * Returns the SplitKeyMethod corresponding to the given value.
     *
     * @param value the integer value of the SplitKeyMethod
     * @return the corresponding SplitKeyMethod
     * @throws IllegalArgumentException if the value does not correspond to any SplitKeyMethod
     */
    public static KMIPSplitKeyMethod fromValue(int value)
    {
        for (KMIPSplitKeyMethod method : KMIPSplitKeyMethod.values())
        {
            if (method.getValue() == value)
            {
                return method;
            }
        }
        throw new IllegalArgumentException("No SplitKeyMethod found for value: " + value);
    }

    /**
     * Checks if the given SplitKeyMethod is a polynomial method.
     *
     * @return true if the SplitKeyMethod is either POLYNOMIAL_GF_216,
     * POLYNOMIAL_PRIME_FIELD, or POLYNOMIAL_GF_28; otherwise false.
     */
    public boolean isPolynomial() {
        return this == POLYNOMIAL_GF_65536 ||
            this == POLYNOMIAL_PRIME_FIELD ||
            this == POLYNOMIAL_GF_256;
    }
}
