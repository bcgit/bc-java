package org.bouncycastle.cbor;

/**
 * CBOR major type constants, as defined in Section 3.1 of RFC 8949.
 */
public final class CBORType
{
    /**
     * Major type 0: an unsigned integer in the range 0 to 2^64-1.
     */
    public static final int UNSIGNED_INTEGER = 0;

    /**
     * Major type 1: a negative integer in the range -2^64 to -1.
     */
    public static final int NEGATIVE_INTEGER = 1;

    /**
     * Major type 2: a byte string.
     */
    public static final int BYTE_STRING = 2;

    /**
     * Major type 3: a text string encoded as UTF-8.
     */
    public static final int TEXT_STRING = 3;

    /**
     * Major type 4: an array of data items.
     */
    public static final int ARRAY = 4;

    /**
     * Major type 5: a map of pairs of data items.
     */
    public static final int MAP = 5;

    /**
     * Major type 6: a tagged data item.
     */
    public static final int TAG = 6;

    /**
     * Major type 7: floating-point numbers and simple values (false, true, null, undefined).
     */
    public static final int SIMPLE = 7;

    private CBORType()
    {
    }
}
