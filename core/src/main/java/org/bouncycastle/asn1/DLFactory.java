package org.bouncycastle.asn1;

class DLFactory
{
    static final ASN1Sequence EMPTY_SEQUENCE = new DLSequence();
    static final ASN1Set EMPTY_SET = new DLSet();

    static ASN1Sequence createSequence(ASN1EncodableVector v)
    {
        if (v.size() < 1)
        {
            return EMPTY_SEQUENCE;
        }

        return new DLSequence(v);
    }

    static ASN1Set createSet(ASN1EncodableVector v)
    {
        if (v.size() < 1)
        {
            return EMPTY_SET;
        }

        return new DLSet(v);
    }
}
