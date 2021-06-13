package org.bouncycastle.asn1;

class DERFactory
{
    static final DERSequence EMPTY_SEQUENCE = new DERSequence();
    static final DERSet EMPTY_SET = new DERSet();

    static DERSequence createSequence(ASN1EncodableVector v)
    {
        if (v.size() < 1)
        {
            return EMPTY_SEQUENCE;
        }

        return new DERSequence(v);
    }

    static DERSet createSet(ASN1EncodableVector v)
    {
        if (v.size() < 1)
        {
            return EMPTY_SET;
        }

        return new DERSet(v);
    }
}
