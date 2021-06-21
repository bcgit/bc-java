package org.bouncycastle.asn1;

final class ASN1UniversalTypes
{
    private ASN1UniversalTypes()
    {
    }

    static ASN1UniversalType get(int tagNumber)
    {
        if (tagNumber < 1 || tagNumber > 30)
        {
            throw new IllegalArgumentException("unsupported tag number: " + tagNumber);
        }

        switch (tagNumber)
        {
        case BERTags.BOOLEAN:
            return ASN1Boolean.TYPE;
        case BERTags.INTEGER:
            return ASN1Integer.TYPE;
        case BERTags.OCTET_STRING:
            return ASN1OctetString.TYPE;
        case BERTags.SEQUENCE:
            return ASN1Sequence.TYPE;
        case BERTags.SET:
            return ASN1Set.TYPE;

        // TODO Handle all valid tags, then change to throw 
        default:
//            throw new IllegalArgumentException("unsupported tag number: " + tagNumber);
            return null;
        }
    }
}
