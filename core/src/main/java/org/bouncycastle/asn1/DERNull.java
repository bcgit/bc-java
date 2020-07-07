package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * An ASN.1 DER NULL object.
 * <p>
 * Preferably use the constant:  DERNull.INSTANCE.
 */
public class DERNull
    extends ASN1Null
{
    public static final DERNull INSTANCE = new DERNull();

    private static final byte[]  zeroBytes = new byte[0];

    private DERNull()
    {
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 2;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncoded(withTag, BERTags.NULL, zeroBytes);
    }
}
