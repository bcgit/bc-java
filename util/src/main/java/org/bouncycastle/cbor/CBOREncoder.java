package org.bouncycastle.cbor;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.util.Strings;

/**
 * An encoder producing Deterministically Encoded CBOR (RFC 8949, Sections 4.2.1 and
 * 4.2.2). Integer arguments, lengths and tag numbers are always emitted in their
 * shortest form, and only definite-length items can be produced, so any output of this
 * class is deterministically encoded by construction.
 * <p>
 * The encoder does not enforce map key ordering itself - callers writing maps are
 * responsible for presenting keys in bytewise lexicographic order of their encodings.
 * The structures defined for C509 (draft-ietf-cose-cbor-encoded-cert-20) use no maps.
 */
public class CBOREncoder
{
    private final OutputStream out;

    /**
     * Base constructor.
     *
     * @param out the stream the CBOR encoding is written to.
     */
    public CBOREncoder(OutputStream out)
    {
        if (out == null)
        {
            throw new NullPointerException("'out' cannot be null");
        }
        this.out = out;
    }

    /**
     * Write an unsigned integer (major type 0).
     *
     * @param value the value, which must be non-negative.
     */
    public void writeUnsignedInteger(long value)
        throws IOException
    {
        if (value < 0)
        {
            throw new IllegalArgumentException("'value' cannot be negative");
        }
        writeArgument(CBORType.UNSIGNED_INTEGER, value);
    }

    /**
     * Write an integer (major type 0 or 1 according to sign).
     */
    public void writeInteger(long value)
        throws IOException
    {
        if (value < 0)
        {
            writeArgument(CBORType.NEGATIVE_INTEGER, -1L - value);
        }
        else
        {
            writeArgument(CBORType.UNSIGNED_INTEGER, value);
        }
    }

    /**
     * Write an integer (major type 0 or 1 according to sign) of any magnitude CBOR
     * supports (-2^64 to 2^64-1).
     */
    public void writeInteger(BigInteger value)
        throws IOException
    {
        BigInteger arg = value;
        int major = CBORType.UNSIGNED_INTEGER;
        if (value.signum() < 0)
        {
            major = CBORType.NEGATIVE_INTEGER;
            arg = value.negate().subtract(BigInteger.valueOf(1));
        }
        if (arg.bitLength() > 64)
        {
            throw new IllegalArgumentException("'value' outside the range CBOR integers can represent");
        }
        writeArgument(major, arg.longValue());
    }

    /**
     * Write a byte string (major type 2).
     */
    public void writeByteString(byte[] bytes)
        throws IOException
    {
        writeByteString(bytes, 0, bytes.length);
    }

    /**
     * Write a byte string (major type 2) from a slice of an array.
     */
    public void writeByteString(byte[] bytes, int off, int len)
        throws IOException
    {
        if (off < 0 || len < 0 || off > bytes.length - len)
        {
            throw new IllegalArgumentException("invalid offset and/or length specified");
        }
        writeArgument(CBORType.BYTE_STRING, len);
        out.write(bytes, off, len);
    }

    /**
     * Write a text string (major type 3), encoded as UTF-8.
     */
    public void writeTextString(String text)
        throws IOException
    {
        byte[] utf8 = Strings.toUTF8ByteArray(text);
        writeArgument(CBORType.TEXT_STRING, utf8.length);
        out.write(utf8);
    }

    /**
     * Write an array header (major type 4) for an array of the given number of elements.
     * The elements themselves are written by the following calls.
     */
    public void writeArrayHeader(int count)
        throws IOException
    {
        if (count < 0)
        {
            throw new IllegalArgumentException("'count' cannot be negative");
        }
        writeArgument(CBORType.ARRAY, count);
    }

    /**
     * Write a map header (major type 5) for a map of the given number of key/value
     * pairs. The keys and values themselves are written by the following calls, and
     * must be presented in deterministic key order.
     */
    public void writeMapHeader(int count)
        throws IOException
    {
        if (count < 0)
        {
            throw new IllegalArgumentException("'count' cannot be negative");
        }
        writeArgument(CBORType.MAP, count);
    }

    /**
     * Write a tag (major type 6). The tag content is written by the following call.
     */
    public void writeTag(long tagNumber)
        throws IOException
    {
        if (tagNumber < 0)
        {
            throw new IllegalArgumentException("'tagNumber' cannot be negative");
        }
        writeArgument(CBORType.TAG, tagNumber);
    }

    /**
     * Write a boolean simple value (0xf4 or 0xf5).
     */
    public void writeBoolean(boolean value)
        throws IOException
    {
        out.write(value ? 0xF5 : 0xF4);
    }

    /**
     * Write the simple value null (0xf6).
     */
    public void writeNull()
        throws IOException
    {
        out.write(0xF6);
    }

    /**
     * Write the simple value undefined (0xf7).
     */
    public void writeUndefined()
        throws IOException
    {
        out.write(0xF7);
    }

    /**
     * Write a complete data item that has already been encoded. The caller is
     * responsible for the item being deterministically encoded - typically it was
     * produced by this class or validated by {@link CBORDecoder#readEncodedItem()}.
     */
    public void writeEncoded(byte[] encodedItem)
        throws IOException
    {
        out.write(encodedItem);
    }

    private void writeArgument(int major, long value)
        throws IOException
    {
        int mt = major << 5;
        if (value >= 0 && value < 24)
        {
            out.write(mt | (int)value);
        }
        else if (value >= 0 && value < 0x100)
        {
            out.write(mt | 24);
            out.write((int)value);
        }
        else if (value >= 0 && value < 0x10000)
        {
            out.write(mt | 25);
            out.write((int)(value >>> 8));
            out.write((int)value & 0xFF);
        }
        else if (value >= 0 && value < 0x100000000L)
        {
            out.write(mt | 26);
            out.write((int)(value >>> 24));
            out.write((int)(value >>> 16) & 0xFF);
            out.write((int)(value >>> 8) & 0xFF);
            out.write((int)value & 0xFF);
        }
        else
        {
            out.write(mt | 27);
            for (int i = 56; i >= 0; i -= 8)
            {
                out.write((int)(value >>> i) & 0xFF);
            }
        }
    }
}
