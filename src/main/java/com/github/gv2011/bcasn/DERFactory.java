package com.github.gv2011.bcasn;

class DERFactory
{
    static final ASN1Sequence EMPTY_SEQUENCE = new DERSequence();
    static final ASN1Set EMPTY_SET = new DERSet();

    static ASN1Sequence createSequence(ASN1EncodableVector v)
    {
        return v.size() < 1 ? EMPTY_SEQUENCE : new DLSequence(v);
    }

    static ASN1Set createSet(ASN1EncodableVector v)
    {
        return v.size() < 1 ? EMPTY_SET : new DLSet(v);
    }
}
