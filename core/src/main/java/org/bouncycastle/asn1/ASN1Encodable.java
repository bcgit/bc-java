package org.bouncycastle.asn1;

/**
 * Everybody implementing this has toASN1Primitive() producing {@link ASN1Primitive}.
 */

public interface ASN1Encodable
{
    /**
     * Supply serializers with {@link ASN1Primitive} form of data.
     */
    ASN1Primitive toASN1Primitive();
}
