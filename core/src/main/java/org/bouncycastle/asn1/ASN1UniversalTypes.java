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
        case BERTags.BIT_STRING:
            return ASN1BitString.TYPE;
        case BERTags.OCTET_STRING:
            return ASN1OctetString.TYPE;
        case BERTags.NULL:
            return ASN1Null.TYPE;
        case BERTags.OBJECT_IDENTIFIER:
            return ASN1ObjectIdentifier.TYPE;
        case BERTags.OBJECT_DESCRIPTOR:         // [UNIVERSAL 7] IMPLICIT GraphicString
            return ASN1ObjectDescriptor.TYPE;
        case BERTags.EXTERNAL:
            return ASN1External.TYPE;
        case BERTags.ENUMERATED:
            return ASN1Enumerated.TYPE;
        case BERTags.UTF8_STRING:               // [UNIVERSAL 12] IMPLICIT OCTET STRING (encode as if)
            return ASN1UTF8String.TYPE;
        case BERTags.RELATIVE_OID:
            return ASN1RelativeOID.TYPE;
        case BERTags.SEQUENCE:
            return ASN1Sequence.TYPE;
        case BERTags.SET:
            return ASN1Set.TYPE;
        case BERTags.NUMERIC_STRING:            // [UNIVERSAL 18] IMPLICIT OCTET STRING (encode as if)
            return ASN1NumericString.TYPE;
        case BERTags.PRINTABLE_STRING:          // [UNIVERSAL 19] IMPLICIT OCTET STRING (encode as if)
            return ASN1PrintableString.TYPE;
        case BERTags.T61_STRING:                // [UNIVERSAL 20] IMPLICIT OCTET STRING (encode as if)
            return ASN1T61String.TYPE;
        case BERTags.VIDEOTEX_STRING:           // [UNIVERSAL 21] IMPLICIT OCTET STRING (encode as if)
            return ASN1VideotexString.TYPE;
        case BERTags.IA5_STRING:                // [UNIVERSAL 22] IMPLICIT OCTET STRING (encode as if)
            return ASN1IA5String.TYPE;
        case BERTags.UTC_TIME:                  // [UNIVERSAL 23] IMPLICIT VisibleString (restricted values)
            return ASN1UTCTime.TYPE;
        case BERTags.GENERALIZED_TIME:          // [UNIVERSAL 24] IMPLICIT VisibleString (restricted values)
            return ASN1GeneralizedTime.TYPE;
        case BERTags.GRAPHIC_STRING:            // [UNIVERSAL 25] IMPLICIT OCTET STRING (encode as if)
            return ASN1GraphicString.TYPE;
        case BERTags.VISIBLE_STRING:            // [UNIVERSAL 26] IMPLICIT OCTET STRING (encode as if)
            return ASN1VisibleString.TYPE;
        case BERTags.GENERAL_STRING:            // [UNIVERSAL 27] IMPLICIT OCTET STRING (encode as if)
            return ASN1GeneralString.TYPE;
        case BERTags.UNIVERSAL_STRING:          // [UNIVERSAL 28] IMPLICIT OCTET STRING (encode as if)
            return ASN1UniversalString.TYPE;
        case BERTags.BMP_STRING:                // [UNIVERSAL 30] IMPLICIT OCTET STRING (encode as if)
            return ASN1BMPString.TYPE;

        case BERTags.REAL:
        case BERTags.EMBEDDED_PDV:
        case BERTags.UNRESTRICTED_STRING:
        default:
            return null;
        }
    }
}
