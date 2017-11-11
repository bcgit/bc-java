package com.github.gv2011.asn1.util.encoders;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import java.io.OutputStream;

import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * Convert binary data to and from UrlBase64 encoding.  This is identical to
 * Base64 encoding, except that the padding character is "." and the other
 * non-alphanumeric characters are "-" and "_" instead of "+" and "/".
 * <p>
 * The purpose of UrlBase64 encoding is to provide a compact encoding of binary
 * data that is safe for use as an URL parameter. Base64 encoding does not
 * produce encoded values that are safe for use in URLs, since "/" can be
 * interpreted as a path delimiter; "+" is the encoded form of a space; and
 * "=" is used to separate a name from the corresponding value in an URL
 * parameter.
 */
public class UrlBase64
{
    private static final Encoder encoder = new UrlBase64Encoder();

    /**
     * Encode the input data producing a URL safe base 64 encoded byte array.
     *
     * @return a byte array containing the URL safe base 64 encoded data.
     */
    public static Bytes encode(
        final Bytes    data)
    {
      final BytesBuilder bOut = newBytesBuilder();

        try
        {
            encoder.encode(data, 0, data.size(), bOut);
        }
        catch (final Exception e)
        {
            throw new EncoderException("exception encoding URL safe base64 data: " + e.getMessage(), e);
        }

        return bOut.build();
    }

    /**
     * Encode the byte data writing it to the given output stream.
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
     * Decode the URL safe base 64 encoded input data - white space will be ignored.
     *
     * @return a byte array representing the decoded data.
     */
    public static Bytes decode(
        final Bytes    data)
    {
      final BytesBuilder bOut = newBytesBuilder();

        try
        {
            encoder.decode(data, 0, data.size(), bOut);
        }
        catch (final Exception e)
        {
            throw new DecoderException("exception decoding URL safe base64 string: " + e.getMessage(), e);
        }

        return bOut.build();
    }

    /**
     * decode the URL safe base 64 encoded byte data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public static int decode(
        final Bytes               data,
        final OutputStream    out)
    {
        return encoder.decode(data, 0, data.size(), out);
    }

    /**
     * decode the URL safe base 64 encoded String data - whitespace will be ignored.
     *
     * @return a byte array representing the decoded data.
     */
    public static Bytes decode(
        final String    data)
    {
      final BytesBuilder bOut = newBytesBuilder();

        try
        {
            encoder.decode(data, bOut);
        }
        catch (final Exception e)
        {
            throw new DecoderException("exception decoding URL safe base64 string: " + e.getMessage(), e);
        }

        return bOut.build();
    }

    /**
     * Decode the URL safe base 64 encoded String data writing it to the given output stream,
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
