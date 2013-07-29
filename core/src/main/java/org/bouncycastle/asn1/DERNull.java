package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * An ASN.1 DER NULL object.
 * <p>
 * Preferably use:  DERNull.INSTANCE
 */
public class DERNull
    extends ASN1Null
{
    /**
     * Preferred public instance of the DER NULL.
     */
    public static final DERNull INSTANCE = new DERNull();

    private static final byte[]  zeroBytes = new byte[0];

    /**
     * @deprecated use DERNull.INSTANCE
     */
    public DERNull()
    {
    }

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
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.NULL, zeroBytes);
    }
}
