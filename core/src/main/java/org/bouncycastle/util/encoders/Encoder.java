package org.bouncycastle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Encode and decode byte arrays (typically from binary to 7-bit ASCII 
 * encodings).
 */
public interface Encoder
{
    /**
     * Return the expected output length of the encoding.
     *
     * @param inputLength the input length of the data.
     * @return the output length of an encoding.
     */
    int getEncodedLength(int inputLength);

    /**
     * Return the maximum expected output length of a decoding. If padding
     * is present the value returned will be greater than the decoded data length.
     *
     * @param inputLength the input length of the encoded data.
     * @return the upper bound of the output length of a decoding.
     */
    int getMaxDecodedLength(int inputLength);

    int encode(byte[] data, int off, int length, OutputStream out) throws IOException;
    
    int decode(byte[] data, int off, int length, OutputStream out) throws IOException;

    int decode(String data, OutputStream out) throws IOException;
}
