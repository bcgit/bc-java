package org.bouncycastle.crypto.split;

/**
 * Enum representing the Wrapping Method Enumeration.
 * <p>
 * This enum defines the available methods for wrapping keys
 * in cryptographic operations. Each wrapping method corresponds
 * to a specific value and describes the way in which keys can
 * be wrapped using encryption or MAC/signing techniques.
 * </p>
 */
public class KMIPWrappingMethod
{

    /**
     * Represents encryption only, using a symmetric key or
     * public key, or authenticated encryption algorithms
     * that use a single key.
     */
    public static final int ENCRYPT = 0x01;

    /**
     * Represents MAC/sign only, either MACing the Key Value
     * with a symmetric key or signing the Key Value with a
     * private key.
     */
    public static final int MAC_SIGN = 0x02;

    /**
     * Represents the process of encrypting the Key Value
     * and then applying MAC/sign.
     */
    public static final int ENCRYPT_THEN_MAC_SIGN = 0x03;

    /**
     * Represents the process of applying MAC/sign to the Key
     * Value and then encrypting it.
     */
    public static final int MAC_SIGN_THEN_ENCRYPT = 0x04;

    /**
     * Represents TR-31 wrapping method.
     */
    public static final int TR31 = 0x05;
        
    //EXTENSIONS("8XXXXXXX");
}

