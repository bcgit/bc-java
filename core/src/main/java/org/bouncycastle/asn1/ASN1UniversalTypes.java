package org.bouncycastle.asn1;

final class ASN1UniversalTypes
{
    private ASN1UniversalTypes()
    {
    }

    static ASN1UniversalType get(int tagNumber)
    {
        switch (tagNumber)
        {
        case BERTags.BOOLEAN:
            return ASN1Boolean.TYPE;
        case BERTags.INTEGER:
            return ASN1Integer.TYPE;
        case BERTags.OCTET_STRING:
            return ASN1OctetString.TYPE;
        case BERTags.NULL:
            return ASN1Null.TYPE;
        case BERTags.OBJECT_IDENTIFIER:
            return ASN1ObjectIdentifier.TYPE;
        case BERTags.ENUMERATED:
            return ASN1Enumerated.TYPE;
        case BERTags.SEQUENCE:
            return ASN1Sequence.TYPE;
        case BERTags.SET:
            return ASN1Set.TYPE;

        // TODO Handle remaining valid tags 
        case BERTags.BIT_STRING:
        case BERTags.EXTERNAL:
        case BERTags.UTF8_STRING:
        case BERTags.NUMERIC_STRING:
        case BERTags.PRINTABLE_STRING:
        case BERTags.T61_STRING:
        case BERTags.VIDEOTEX_STRING:
        case BERTags.IA5_STRING:
        case BERTags.UTC_TIME:
        case BERTags.GENERALIZED_TIME:
        case BERTags.GRAPHIC_STRING:
        case BERTags.VISIBLE_STRING:
        case BERTags.GENERAL_STRING:
        case BERTags.UNIVERSAL_STRING:
        case BERTags.BMP_STRING:
            return null;

        case BERTags.OBJECT_DESCRIPTOR:
        case BERTags.REAL:
        case BERTags.EMBEDDED_PDV:
        case BERTags.RELATIVE_OID:
        case BERTags.UNRESTRICTED_STRING:
        default:
            throw new IllegalArgumentException("unsupported tag number: " + tagNumber);
        }
    }
}
