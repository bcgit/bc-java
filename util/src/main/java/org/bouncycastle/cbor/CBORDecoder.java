package org.bouncycastle.cbor;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

/**
 * A decoder for Deterministically Encoded CBOR (RFC 8949, Sections 4.2.1 and 4.2.2),
 * restricted to the profile needed by CBOR-based PKI formats such as C509
 * (draft-ietf-cose-cbor-encoded-cert-20).
 * <p>
 * The decoder is deliberately strict: indefinite-length items, non-shortest-form
 * arguments, floating-point values, simple values other than false, true, null and
 * undefined, malformed UTF-8 in text strings, and maps whose keys are not in bytewise
 * lexicographic order are all rejected with an {@link IOException}. Accepting any of
 * these would allow the same data item to have more than one encoding, which for
 * natively signed structures (where the signature is computed over the CBOR bytes)
 * would make signatures malleable.
 * <p>
 * All read methods honour a <code>throws IOException</code> contract for malformed
 * input; no {@link RuntimeException} escapes for any input byte sequence. Declared
 * lengths are validated against the number of bytes actually remaining before any
 * allocation is made, so a short crafted header cannot drive an over-allocation.
 */
public class CBORDecoder
{
    /**
     * Hard cap on the nesting depth of arrays, maps and tags. CBOR items nest, and
     * {@link #readEncodedItem()} descends recursively; without a bound a small input of
     * repeated array headers would drive the recursion into a StackOverflowError. The
     * structures defined for C509 nest only a few levels deep, so 64 is generous.
     */
    private static final int MAX_NESTING_DEPTH = 64;

    private final byte[] data;
    private final int limit;

    private int pos;

    /**
     * Base constructor.
     *
     * @param encoding the encoded CBOR data to read from.
     */
    public CBORDecoder(byte[] encoding)
    {
        this(encoding, 0, encoding.length);
    }

    /**
     * Constructor for reading a slice of a larger array.
     *
     * @param encoding the array containing the encoded CBOR data.
     * @param off the offset of the first byte of CBOR data.
     * @param len the number of bytes of CBOR data.
     */
    public CBORDecoder(byte[] encoding, int off, int len)
    {
        if (encoding == null)
        {
            throw new NullPointerException("'encoding' cannot be null");
        }
        if (off < 0 || len < 0 || off > encoding.length - len)
        {
            throw new IllegalArgumentException("invalid offset and/or length specified");
        }
        this.data = encoding;
        this.pos = off;
        this.limit = off + len;
    }

    /**
     * Return true if at least one more data item (or part of one) is available.
     */
    public boolean hasNext()
    {
        return pos < limit;
    }

    /**
     * Throw an exception unless all input has been consumed.
     */
    public void expectEnd()
        throws IOException
    {
        if (pos != limit)
        {
            throw new IOException("unexpected trailing data after CBOR item");
        }
    }

    /**
     * Return the major type (0 to 7) of the next data item without consuming it.
     */
    public int peekMajorType()
        throws IOException
    {
        if (pos >= limit)
        {
            throw new IOException("unexpected end of CBOR data");
        }
        return (data[pos] >> 5) & 0x07;
    }

    /**
     * Return true if the next data item is the simple value null (0xf6).
     */
    public boolean nextIsNull()
        throws IOException
    {
        if (pos >= limit)
        {
            throw new IOException("unexpected end of CBOR data");
        }
        return (data[pos] & 0xFF) == 0xF6;
    }

    /**
     * Return true if the next data item is the simple value undefined (0xf7).
     */
    public boolean nextIsUndefined()
        throws IOException
    {
        if (pos >= limit)
        {
            throw new IOException("unexpected end of CBOR data");
        }
        return (data[pos] & 0xFF) == 0xF7;
    }

    /**
     * Read an unsigned integer (major type 0) in the range 0 to 2^63-1.
     *
     * @throws IOException if the next item is not an unsigned integer in range.
     */
    public long readUnsignedInteger()
        throws IOException
    {
        long arg = readArgument(CBORType.UNSIGNED_INTEGER);
        if (arg < 0)
        {
            throw new IOException("CBOR unsigned integer outside supported range");
        }
        return arg;
    }

    /**
     * Read an integer (major type 0 or 1) in the range of a Java long.
     *
     * @throws IOException if the next item is not an integer, or is outside the long range.
     */
    public long readInteger()
        throws IOException
    {
        int major = peekMajorType();
        if (major == CBORType.UNSIGNED_INTEGER)
        {
            return readUnsignedInteger();
        }
        if (major == CBORType.NEGATIVE_INTEGER)
        {
            long arg = readArgument(CBORType.NEGATIVE_INTEGER);
            if (arg < 0)
            {
                throw new IOException("CBOR negative integer outside supported range");
            }
            return -1L - arg;
        }
        throw new IOException("CBOR integer expected, found major type " + major);
    }

    /**
     * Read an integer (major type 0 or 1) in the range of a Java int.
     *
     * @throws IOException if the next item is not an integer, or is outside the int range.
     */
    public int readInt()
        throws IOException
    {
        long value = readInteger();
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE)
        {
            throw new IOException("CBOR integer outside supported range");
        }
        return (int)value;
    }

    /**
     * Read an integer (major type 0 or 1) of any magnitude CBOR supports
     * (-2^64 to 2^64-1).
     *
     * @throws IOException if the next item is not an integer.
     */
    public BigInteger readBigInteger()
        throws IOException
    {
        int major = peekMajorType();
        if (major != CBORType.UNSIGNED_INTEGER && major != CBORType.NEGATIVE_INTEGER)
        {
            throw new IOException("CBOR integer expected, found major type " + major);
        }
        long arg = readArgument(major);
        byte[] mag = new byte[8];
        for (int i = 0; i != 8; i++)
        {
            mag[i] = (byte)(arg >>> (56 - 8 * i));
        }
        BigInteger value = new BigInteger(1, mag);
        if (major == CBORType.NEGATIVE_INTEGER)
        {
            value = value.negate().subtract(BigInteger.valueOf(1));
        }
        return value;
    }

    /**
     * Read a byte string (major type 2).
     */
    public byte[] readByteString()
        throws IOException
    {
        long len = readArgument(CBORType.BYTE_STRING);
        int start = checkAvailable(len, "byte string");
        return Arrays.copyOfRange(data, start, pos);
    }

    /**
     * Read a text string (major type 3), validating that it is well-formed UTF-8.
     */
    public String readTextString()
        throws IOException
    {
        long len = readArgument(CBORType.TEXT_STRING);
        int start = checkAvailable(len, "text string");
        try
        {
            return Strings.fromUTF8ByteArray(data, start, pos - start);
        }
        catch (RuntimeException e)
        {
            // Strings.fromUTF8ByteArray signals malformed UTF-8 with an unchecked exception
            throw Exceptions.ioException("CBOR text string is not well-formed UTF-8", e);
        }
    }

    /**
     * Read an array header (major type 4), returning the number of elements that follow.
     * The count is validated against the bytes remaining (every element occupies at
     * least one byte), so a crafted count cannot drive an oversized allocation in the
     * caller.
     */
    public int readArrayHeader()
        throws IOException
    {
        long count = readArgument(CBORType.ARRAY);
        if (count < 0 || count > limit - pos)
        {
            throw new IOException("CBOR array count exceeds remaining data");
        }
        return (int)count;
    }

    /**
     * Read a map header (major type 5), returning the number of key/value pairs that follow.
     */
    public int readMapHeader()
        throws IOException
    {
        long count = readArgument(CBORType.MAP);
        if (count < 0 || count > (limit - pos) / 2)
        {
            throw new IOException("CBOR map count exceeds remaining data");
        }
        return (int)count;
    }

    /**
     * Read a tag (major type 6), returning the tag number. The tag content follows as
     * the next data item.
     */
    public long readTag()
        throws IOException
    {
        long tag = readArgument(CBORType.TAG);
        if (tag < 0)
        {
            throw new IOException("CBOR tag number outside supported range");
        }
        return tag;
    }

    /**
     * Read a boolean simple value (0xf4 or 0xf5).
     */
    public boolean readBoolean()
        throws IOException
    {
        int b = readSimple("boolean");
        if (b == 20)
        {
            return false;
        }
        if (b == 21)
        {
            return true;
        }
        throw new IOException("CBOR boolean expected");
    }

    /**
     * Read the simple value null (0xf6).
     */
    public void readNull()
        throws IOException
    {
        if (readSimple("null") != 22)
        {
            throw new IOException("CBOR null expected");
        }
    }

    /**
     * Read the simple value undefined (0xf7).
     */
    public void readUndefined()
        throws IOException
    {
        if (readSimple("undefined") != 23)
        {
            throw new IOException("CBOR undefined expected");
        }
    }

    /**
     * Read one complete data item, of whatever type, returning its encoding verbatim.
     * The item is fully validated as it is skipped: all nested items must be
     * deterministically encoded, nesting is bounded, and map keys must be sorted in
     * bytewise lexicographic order of their encodings (RFC 8949 Section 4.2.1).
     */
    public byte[] readEncodedItem()
        throws IOException
    {
        int start = pos;
        skipItem(0);
        return Arrays.copyOfRange(data, start, pos);
    }

    private void skipItem(int depth)
        throws IOException
    {
        if (depth > MAX_NESTING_DEPTH)
        {
            throw new IOException("CBOR decoder exceeded maximum nesting depth of " + MAX_NESTING_DEPTH);
        }

        int major = peekMajorType();
        switch (major)
        {
        case CBORType.UNSIGNED_INTEGER:
        case CBORType.NEGATIVE_INTEGER:
            readArgument(major);
            break;
        case CBORType.BYTE_STRING:
        case CBORType.TEXT_STRING:
        {
            long len = readArgument(major);
            int start = checkAvailable(len, major == CBORType.BYTE_STRING ? "byte string" : "text string");
            if (major == CBORType.TEXT_STRING)
            {
                try
                {
                    Strings.fromUTF8ByteArray(data, start, pos - start);
                }
                catch (RuntimeException e)
                {
                    throw Exceptions.ioException("CBOR text string is not well-formed UTF-8", e);
                }
            }
            break;
        }
        case CBORType.ARRAY:
        {
            int count = readArrayHeader();
            for (int i = 0; i != count; i++)
            {
                skipItem(depth + 1);
            }
            break;
        }
        case CBORType.MAP:
        {
            int count = readMapHeader();
            byte[] lastKey = null;
            for (int i = 0; i != count; i++)
            {
                int keyStart = pos;
                skipItem(depth + 1);
                byte[] key = Arrays.copyOfRange(data, keyStart, pos);
                if (lastKey != null && compareEncodings(lastKey, key) >= 0)
                {
                    throw new IOException("CBOR map keys are not in deterministic order");
                }
                lastKey = key;
                skipItem(depth + 1);
            }
            break;
        }
        case CBORType.TAG:
            readTag();
            skipItem(depth + 1);
            break;
        default:
            readSimple("simple value");
            break;
        }
    }

    /**
     * Bytewise lexicographic comparison of two encoded data items, as required for
     * deterministic map key ordering.
     */
    private static int compareEncodings(byte[] a, byte[] b)
    {
        int len = Math.min(a.length, b.length);
        for (int i = 0; i != len; i++)
        {
            int av = a[i] & 0xFF, bv = b[i] & 0xFF;
            if (av != bv)
            {
                return av < bv ? -1 : 1;
            }
        }
        return a.length - b.length;
    }

    /**
     * Read a major type 7 initial byte, returning the simple value (20-23). Floating
     * point values and all other simple values are rejected: they have no use in the
     * supported profile, and accepting them would widen the attack surface for no
     * benefit.
     */
    private int readSimple(String expected)
        throws IOException
    {
        if (pos >= limit)
        {
            throw new IOException("unexpected end of CBOR data");
        }
        int ib = data[pos] & 0xFF;
        int major = ib >> 5;
        int info = ib & 0x1F;
        if (major != CBORType.SIMPLE)
        {
            throw new IOException("CBOR " + expected + " expected, found major type " + major);
        }
        if (info < 20 || info > 23)
        {
            throw new IOException("CBOR simple value " + info + " is not supported");
        }
        pos++;
        return info;
    }

    /**
     * Read the initial byte and argument of a data item of the given major type,
     * enforcing the deterministic encoding requirements: no indefinite lengths, and
     * arguments in their shortest form. The returned long holds the full unsigned
     * 64-bit argument (values above 2^63-1 appear negative).
     */
    private long readArgument(int expectedMajor)
        throws IOException
    {
        if (pos >= limit)
        {
            throw new IOException("unexpected end of CBOR data");
        }
        int ib = data[pos] & 0xFF;
        int major = ib >> 5;
        int info = ib & 0x1F;
        if (major != expectedMajor)
        {
            throw new IOException("CBOR major type " + expectedMajor + " expected, found " + major);
        }
        if (major == CBORType.SIMPLE)
        {
            throw new IOException("CBOR argument read on major type 7");
        }
        pos++;
        if (info < 24)
        {
            return info;
        }
        switch (info)
        {
        case 24:
        {
            long value = readOctets(1);
            if (value < 24)
            {
                throw new IOException("CBOR argument is not in shortest form");
            }
            return value;
        }
        case 25:
        {
            long value = readOctets(2);
            if (value < 0x100)
            {
                throw new IOException("CBOR argument is not in shortest form");
            }
            return value;
        }
        case 26:
        {
            long value = readOctets(4);
            if (value < 0x10000)
            {
                throw new IOException("CBOR argument is not in shortest form");
            }
            return value;
        }
        case 27:
        {
            long value = readOctets(8);
            if (value >= 0 && value < 0x100000000L)
            {
                throw new IOException("CBOR argument is not in shortest form");
            }
            return value;
        }
        case 31:
            throw new IOException("indefinite-length CBOR items are not permitted in deterministic encoding");
        default:
            throw new IOException("CBOR initial byte with reserved additional information " + info);
        }
    }

    private long readOctets(int count)
        throws IOException
    {
        if (count > limit - pos)
        {
            throw new IOException("unexpected end of CBOR data");
        }
        long value = 0;
        for (int i = 0; i != count; i++)
        {
            value = (value << 8) | (data[pos + i] & 0xFF);
        }
        pos += count;
        return value;
    }

    /**
     * Check a declared length against the bytes actually remaining, before anything is
     * allocated from it, and consume it. Returns the start position of the content.
     */
    private int checkAvailable(long declaredLength, String type)
        throws IOException
    {
        if (declaredLength < 0 || declaredLength > limit - pos)
        {
            throw new IOException("CBOR " + type + " length exceeds remaining data");
        }
        int start = pos;
        pos += (int)declaredLength;
        return start;
    }
}
