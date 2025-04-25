package org.bouncycastle.kmip.wire.enumeration;

/**
 * Enum representing the Wrapping Method Enumeration.
 * <p>
 * This enum defines the available methods for wrapping keys
 * in cryptographic operations. Each wrapping method corresponds
 * to a specific value and describes the way in which keys can
 * be wrapped using encryption or MAC/signing techniques.
 * </p>
 */
public enum KMIPWrappingMethod
{
    /**
     * Represents encryption only, using a symmetric key or
     * public key, or authenticated encryption algorithms
     * that use a single key.
     */
    ENCRYPT(1),
    /**
     * Represents MAC/sign only, either MACing the Key Value
     * with a symmetric key or signing the Key Value with a
     * private key.
     */
    MAC_SIGN(2),
    /**
     * Represents the process of applying MAC/sign to the Key
     * Value and then encrypting it.
     */
    ENCRYPT_THEN_MAC_SIGN(3),
    /**
     * Represents the process of applying MAC/sign to the Key
     * Value and then encrypting it.
     */
    MAC_SIGN_THEN_ENCRYPT(4),
    /**
     * Represents TR-31 wrapping method.
     */
    TR31(5);

    private final int value;

    KMIPWrappingMethod(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    public static KMIPWrappingMethod fromValue(int value)
    {
        for (KMIPWrappingMethod method : KMIPWrappingMethod.values())
        {
            if (method.value == value)
            {
                return method;
            }
        }
        throw new IllegalArgumentException("Invalid WrappingMethod value: " + value);
    }

}

