package com.github.gv2011.asn1.util.encoders;

import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import java.io.OutputStream;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * Utility class for converting Base64 data to bytes and back again.
 */
public class Base64
{
    private static final Encoder encoder = new Base64Encoder();

    public static String toBase64String(
        final Bytes data)
    {
        return toBase64String(data, 0, data.size());
    }

    public static String toBase64String(
        final Bytes data,
        final int    off,
        final int    length)
    {
        final Bytes encoded = encode(data, off, length);
        return Strings.fromByteArray(encoded);
    }

    /**
     * encode the input data producing a base 64 encoded byte array.
     *
     * @return a byte array containing the base 64 encoded data.
     */
    public static Bytes encode(
        final Bytes    data)
    {
        return encode(data, 0, data.size());
    }

    /**
     * encode the input data producing a base 64 encoded byte array.
     *
     * @return a byte array containing the base 64 encoded data.
     */
    public static Bytes encode(
        final Bytes data,
        final int    off,
        final int    length)
    {
        final int len = (length + 2) / 3 * 4;
        final BytesBuilder bOut = newBytesBuilder(len);

        try
        {
            encoder.encode(data, off, length, bOut);
        }
        catch (final Exception e)
        {
            throw new EncoderException("exception encoding base64 string: " + e.getMessage(), e);
        }

        return bOut.build();
    }

    /**
     * Encode the byte data to base 64 writing it to the given output stream.
     *
     * @return the number of bytes produced.
     */
    public static int encode(
        final Bytes                data,
        final OutputStream    out)
    {
        return encoder.encode(data, 0, data.size(), out);
    }

    /**
     * Encode the byte data to base 64 writing it to the given output stream.
     *
     * @return the number of bytes produced.
     */
    public static int encode(
        final Bytes                data,
        final int                    off,
        final int                    length,
        final OutputStream    out)
    {
        return encoder.encode(data, off, length, out);
    }

    /**
     * decode the base 64 encoded input data. It is assumed the input data is valid.
     *
     * @return a byte array representing the decoded data.
     */
    public static Bytes decode(
        final Bytes    data)
    {
        final int len = data.size() / 4 * 3;
        final BytesBuilder bOut = newBytesBuilder(len);

        try
        {
            encoder.decode(data, 0, data.size(), bOut);
        }
        catch (final Exception e)
        {
            throw new DecoderException("unable to decode base64 data: " + e.getMessage(), e);
        }

        return bOut.build();
    }

    /**
     * decode the base 64 encoded String data - whitespace will be ignored.
     *
     * @return a byte array representing the decoded data.
     */
    public static Bytes decode(
        final String    data)
    {
        final int len = data.length() / 4 * 3;
        final BytesBuilder bOut = newBytesBuilder(len);

        try
        {
            encoder.decode(data, bOut);
        }
        catch (final Exception e)
        {
            throw new DecoderException("unable to decode base64 string: " + e.getMessage(), e);
        }

        return bOut.build();
    }

    /**
     * decode the base 64 encoded String data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public static int decode(
        final String                data,
        final OutputStream    out)
    {
        return encoder.decode(data, out);
    }
}
