package org.bouncycastle.asn1;

import java.io.IOException;

public abstract class ASN1Util
{
//    public static ASN1Encodable parseBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo,
//        boolean declaredExplicit, int baseTagClass, int baseTagNo, boolean baseDeclaredExplicit) throws IOException
//    {
//        if (!taggedObjectParser.hasTag(tagClass, tagNo))
//        {
//            String requested = getTagText(tagClass, tagNo);
//            String found = getTagText(taggedObjectParser.getTagClass(), taggedObjectParser.getTagNo());
//            throw new ASN1Exception("Requested " + requested + " tag but found " + found);
//        }
//
//        return taggedObjectParser.parseBaseObject(declaredExplicit, baseTagClass, baseTagNo, baseDeclaredExplicit);
//    }

    public static ASN1Encodable parseBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagClass,
        int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException
    {
        if (!taggedObjectParser.hasTag(tagClass, tagNo))
        {
            String requested = getTagText(tagClass, tagNo);
            String found = getTagText(taggedObjectParser.getTagClass(), taggedObjectParser.getTagNo());
            throw new ASN1Exception("Requested " + requested + " tag but found " + found);
        }

        return taggedObjectParser.parseBaseUniversal(declaredExplicit, baseTagNo);
    }

//    public static ASN1Encodable parseContextBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagNo,
//        boolean declaredExplicit, int baseTagClass, int baseTagNo, boolean baseDeclaredExplicit) throws IOException
//    {
//        return parseBaseObject(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagClass,
//            baseTagNo, baseDeclaredExplicit);
//    }

    public static ASN1Encodable parseContextBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagNo,
        boolean declaredExplicit, int baseTagNo) throws IOException
    {
        return parseBaseUniversal(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagNo);
    }

//    public static ASN1Encodable tryParseBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo,
//        boolean declaredExplicit, int baseTagClass, int baseTagNo, boolean baseDeclaredExplicit) throws IOException
//    {
//        if (!taggedObjectParser.hasTag(tagClass, tagNo))
//        {
//            return null;
//        }
//
//        return taggedObjectParser.parseBaseObject(declaredExplicit, baseTagClass, baseTagNo, baseDeclaredExplicit);
//    }

    public static ASN1Encodable tryParseBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagClass,
        int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException
    {
        if (!taggedObjectParser.hasTag(tagClass, tagNo))
        {
            return null;
        }

        return taggedObjectParser.parseBaseUniversal(declaredExplicit, baseTagNo);
    }

//    public static ASN1Encodable tryParseContextBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagNo,
//        boolean declaredExplicit, int baseTagClass, int baseTagNo, boolean baseDeclaredExplicit) throws IOException
//    {
//        return tryParseBaseObject(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagClass,
//            baseTagNo, baseDeclaredExplicit);
//    }

    public static ASN1Encodable tryParseContextBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagNo,
        boolean declaredExplicit, int baseTagNo) throws IOException
    {
        return tryParseBaseUniversal(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagNo);
    }

    static String getTagText(int tagClass, int tagNo)
    {
        switch (tagClass)
        {
        case BERTags.APPLICATION:
            return "[APPLICATION " + tagNo + "]";
        case BERTags.CONTEXT_SPECIFIC:
            return "[" + tagNo + "]";
        case BERTags.PRIVATE:
            return "[PRIVATE " + tagNo + "]";
        default:
            return "U" + Integer.toString(tagNo);
        }
    }
}
