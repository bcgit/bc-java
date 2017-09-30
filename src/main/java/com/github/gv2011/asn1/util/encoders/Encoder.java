package com.github.gv2011.asn1.util.encoders;

import java.io.OutputStream;

import com.github.gv2011.util.bytes.Bytes;

/**
 * Encode and decode byte arrays (typically from binary to 7-bit ASCII
 * encodings).
 */
public interface Encoder
{
    int encode(Bytes data, int off, int length, OutputStream out);

    int decode(Bytes data, int off, int length, OutputStream out);

    int decode(String data, OutputStream out);
}
