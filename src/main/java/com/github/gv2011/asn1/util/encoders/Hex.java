package com.github.gv2011.asn1.util.encoders;

import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import java.io.IOException;
import java.io.OutputStream;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * Utility class for converting hex data to bytes and back again.
 */
public class Hex
{
    private static final Encoder encoder = new HexEncoder();

    public static String toHexString(
        final Bytes data)
    {
        return toHexString(data, 0, data.size());
    }

    public static String toHexString(
        final Bytes  data,
        final int    off,
        final int    length)
    {
        final Bytes encoded = encode(data, off, length);
        return Strings.fromByteArray(encoded);
    }

    /**
     * encode the input data producing a Hex encoded byte array.
     *
     * @return a byte array containing the Hex encoded data.
     */
    public static Bytes encode(
        final Bytes    data)
    {
        return encode(data, 0, data.size());
    }

    /**
     * encode the input data producing a Hex encoded byte array.
     *
     * @return a byte array containing the Hex encoded data.
     */
    public static Bytes encode(
        final Bytes    data,
        final int       off,
        final int       length)
    {
        final BytesBuilder    bOut = newBytesBuilder();

        try
        {
            encoder.encode(data, off, length, bOut);
        }
        catch (final Exception e)
        {
            throw new EncoderException("exception encoding Hex string: " + e.getMessage(), e);
        }

        return bOut.build();
    }

    /**
     * Hex encode the byte data writing it to the given output stream.
     *
     * @return the number of bytes produced.
     */
    public static int encode(final Bytes data, final OutputStream out)
    {
        return encoder.encode(data, 0, data.size(), out);
    }

    /**
     * Hex encode the byte data writing it to the given output stream.
     *
     * @return the number of bytes produced.
     */
    public static int encode(
        final Bytes          data,
        final int            off,
        final int            length,
        final OutputStream   out)
        throws IOException
    {
        return encoder.encode(data, off, length, out);
    }

    /**
     * decode the Hex encoded input data. It is assumed the input data is valid.
     *
     * @return a byte array representing the decoded data.
     */
    public static Bytes decode(
        final Bytes    data)
    {
        final BytesBuilder    bOut = newBytesBuilder();

        try
        {
            encoder.decode(data, 0, data.size(), bOut);
        }
        catch (final Exception e)
        {
            throw new DecoderException("exception decoding Hex data: " + e.getMessage(), e);
        }

        return bOut.build();
    }

    /**
     * decode the Hex encoded String data - whitespace will be ignored.
     *
     * @return a byte array representing the decoded data.
     */
    public static Bytes decode(
        final String    data)
    {
      final BytesBuilder    bOut = newBytesBuilder();

        try
        {
            encoder.decode(data, bOut);
        }
        catch (final Exception e)
        {
            throw new DecoderException("exception decoding Hex string: " + e.getMessage(), e);
        }

        return bOut.build();
    }

    /**
     * decode the Hex encoded String data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public static int decode(
        final String          data,
        final OutputStream    out)
    {
        return encoder.decode(data, out);
    }
}
