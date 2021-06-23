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
        case BERTags.OBJECT_DESCRIPTOR:         // [UNIVERSAL 7] IMPLICIT GraphicString
            return ASN1ObjectDescriptor.TYPE;
        case BERTags.ENUMERATED:
            return ASN1Enumerated.TYPE;
        case BERTags.SEQUENCE:
            return ASN1Sequence.TYPE;
        case BERTags.SET:
            return ASN1Set.TYPE;
        case BERTags.GRAPHIC_STRING:            // [UNIVERSAL 25] IMPLICIT OCTET STRING (encode as if)
            return ASN1GraphicString.TYPE;

        // TODO Handle remaining valid tags 
        case BERTags.BIT_STRING:
        case BERTags.EXTERNAL:
        case BERTags.UTF8_STRING:               // [UNIVERSAL 12] IMPLICIT OCTET STRING (encode as if)
        case BERTags.NUMERIC_STRING:            // [UNIVERSAL 18] IMPLICIT OCTET STRING (encode as if)
        case BERTags.PRINTABLE_STRING:          // [UNIVERSAL 19] IMPLICIT OCTET STRING (encode as if)
        case BERTags.T61_STRING:                // [UNIVERSAL 20] IMPLICIT OCTET STRING (encode as if)
        case BERTags.VIDEOTEX_STRING:           // [UNIVERSAL 21] IMPLICIT OCTET STRING (encode as if)
        case BERTags.IA5_STRING:                // [UNIVERSAL 22] IMPLICIT OCTET STRING (encode as if)
        case BERTags.UTC_TIME:                  // [UNIVERSAL 23] IMPLICIT VisibleString (restricted values)
        case BERTags.GENERALIZED_TIME:          // [UNIVERSAL 24] IMPLICIT VisibleString (restricted values)
        case BERTags.VISIBLE_STRING:            // [UNIVERSAL 26] IMPLICIT OCTET STRING (encode as if)
        case BERTags.GENERAL_STRING:            // [UNIVERSAL 27] IMPLICIT OCTET STRING (encode as if)
        case BERTags.UNIVERSAL_STRING:          // [UNIVERSAL 28] IMPLICIT OCTET STRING (encode as if)
        case BERTags.BMP_STRING:                // [UNIVERSAL 30] IMPLICIT OCTET STRING (encode as if)
            return null;

        case BERTags.REAL:
        case BERTags.EMBEDDED_PDV:
        case BERTags.RELATIVE_OID:
        case BERTags.UNRESTRICTED_STRING:
        default:
            throw new IllegalArgumentException("unsupported tag number: " + tagNumber);
        }
    }
}
