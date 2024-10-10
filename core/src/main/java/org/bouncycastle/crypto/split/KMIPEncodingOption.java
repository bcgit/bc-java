package org.bouncycastle.crypto.split;

/**
 * Enum representing the Encoding Option Enumeration.
 * <p>
 * This enum defines the available encoding options for cryptographic key materials.
 * Each option corresponds to a specific value that can be used in the context of
 * key management operations.
 * </p>
 */
public class KMIPEncodingOption
{

    /**
     * Represents no encoding, indicating that the wrapped
     * un-encoded value of the Byte String Key Material field
     * is to be used.
     */
    public static final int NO_ENCODING = 1;

    /**
     * Represents TTLV encoding, indicating that the wrapped
     * TTLV-encoded Key Value structure is to be used.
     */
    public static final int NTTLV_ENCODING = 2;

    //EXTENSIONS("8XXXXXXX");
}

