package org.bouncycastle.asn1;

class DLFactory
{
    static final DLSequence EMPTY_SEQUENCE = new DLSequence();
    static final DLSet EMPTY_SET = new DLSet();

    static DLSequence createSequence(ASN1EncodableVector v)
    {
        if (v.size() < 1)
        {
            return EMPTY_SEQUENCE;
        }

        return new DLSequence(v);
    }

    static DLSet createSet(ASN1EncodableVector v)
    {
        if (v.size() < 1)
        {
            return EMPTY_SET;
        }

        return new DLSet(v);
    }
}
