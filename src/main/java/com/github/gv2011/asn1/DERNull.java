package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.emptyBytes;

import com.github.gv2011.util.bytes.Bytes;

/**
 * A NULL object.
 */
public class DERNull
    extends ASN1Null
{
    public static final DERNull INSTANCE = new DERNull();

    private static final Bytes  zeroBytes = emptyBytes();

    @Deprecated
    private DERNull(){}

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 2;
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.NULL, zeroBytes);
    }
}
