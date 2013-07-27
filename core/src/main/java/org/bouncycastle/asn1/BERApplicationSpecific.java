package org.bouncycastle.asn1;

/**
 * ASN.1 APPLICATION type data with indefinite form length/sequence/set encodings.
 */
public class BERApplicationSpecific
    extends DERApplicationSpecific
{
    public BERApplicationSpecific(int tagNo, ASN1EncodableVector vec)
    {
        super(tagNo, vec);
    }
}
