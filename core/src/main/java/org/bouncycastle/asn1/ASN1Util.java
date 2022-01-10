package org.bouncycastle.asn1;

import java.io.IOException;

public abstract class ASN1Util
{
    static ASN1TaggedObject checkTag(ASN1TaggedObject taggedObject, int tagClass, int tagNo)
    {
        if (!taggedObject.hasTag(tagClass, tagNo))
        {
            String expected = getTagText(tagClass, tagNo);
            String found = getTagText(taggedObject);
            throw new IllegalStateException("Expected " + expected + " tag but found " + found);
        }
        return taggedObject;
    }

    static ASN1TaggedObjectParser checkTag(ASN1TaggedObjectParser taggedObjectParser, int tagClass, int tagNo)
    {
        if (!taggedObjectParser.hasTag(tagClass, tagNo))
        {
            String expected = getTagText(tagClass, tagNo);
            String found = getTagText(taggedObjectParser);
            throw new IllegalStateException("Expected " + expected + " tag but found " + found);
        }
        return taggedObjectParser;
    }


    /*
     * Tag text methods
     */

    static String getTagText(ASN1Tag tag)
    {
        return getTagText(tag.getTagClass(), tag.getTagNumber());
    }

    public static String getTagText(ASN1TaggedObject taggedObject)
    {
        return getTagText(taggedObject.getTagClass(), taggedObject.getTagNo());
    }

    public static String getTagText(ASN1TaggedObjectParser taggedObjectParser)
    {
        return getTagText(taggedObjectParser.getTagClass(), taggedObjectParser.getTagNo());
    }

    public static String getTagText(int tagClass, int tagNo)
    {
        switch (tagClass)
        {
        case BERTags.APPLICATION:
            return "[APPLICATION " + tagNo + "]";
        case BERTags.CONTEXT_SPECIFIC:
            return "[CONTEXT " + tagNo + "]";
        case BERTags.PRIVATE:
            return "[PRIVATE " + tagNo + "]";
        default:
            return "[UNIVERSAL " + tagNo + "]";
        }
    }


    /*
     * Wrappers for ASN1TaggedObject#getExplicitBaseObject
     */

    public static ASN1Object getExplicitBaseObject(ASN1TaggedObject taggedObject, int tagClass, int tagNo)
    {
        return checkTag(taggedObject, tagClass, tagNo).getExplicitBaseObject();
    }

    public static ASN1Object getExplicitContextBaseObject(ASN1TaggedObject taggedObject, int tagNo)
    {
        return getExplicitBaseObject(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo);
    }

    public static ASN1Object tryGetExplicitBaseObject(ASN1TaggedObject taggedObject, int tagClass, int tagNo)
    {
        if (!taggedObject.hasTag(tagClass, tagNo))
        {
            return null;
        }

        return taggedObject.getExplicitBaseObject();
    }

    public static ASN1Object tryGetExplicitContextBaseObject(ASN1TaggedObject taggedObject, int tagNo)
    {
        return tryGetExplicitBaseObject(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo);
    }


    /*
     * Wrappers for ASN1TaggedObject#getExplicitBaseTagged
     */

    public static ASN1TaggedObject getExplicitBaseTagged(ASN1TaggedObject taggedObject, int tagClass, int tagNo)
    {
        return checkTag(taggedObject, tagClass, tagNo).getExplicitBaseTagged();
    }

    public static ASN1TaggedObject getExplicitContextBaseTagged(ASN1TaggedObject taggedObject, int tagNo)
    {
        return getExplicitBaseTagged(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo);
    }

    public static ASN1TaggedObject tryGetExplicitBaseTagged(ASN1TaggedObject taggedObject, int tagClass, int tagNo)
    {
        if (!taggedObject.hasTag(tagClass, tagNo))
        {
            return null;
        }

        return taggedObject.getExplicitBaseTagged();
    }

    public static ASN1TaggedObject tryGetExplicitContextBaseTagged(ASN1TaggedObject taggedObject, int tagNo)
    {
        return tryGetExplicitBaseTagged(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo);
    }


    /*
     * Wrappers for ASN1TaggedObject#getImplicitBaseTagged
     */

    public static ASN1TaggedObject getImplicitBaseTagged(ASN1TaggedObject taggedObject, int tagClass, int tagNo,
        int baseTagClass, int baseTagNo)
    {
        return checkTag(taggedObject, tagClass, tagNo).getImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObject getImplicitContextBaseTagged(ASN1TaggedObject taggedObject, int tagNo,
        int baseTagClass, int baseTagNo)
    {
        return getImplicitBaseTagged(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo, baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObject tryGetImplicitBaseTagged(ASN1TaggedObject taggedObject, int tagClass, int tagNo,
        int baseTagClass, int baseTagNo)
    {
        if (!taggedObject.hasTag(tagClass, tagNo))
        {
            return null;
        }

        return taggedObject.getImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObject tryGetImplicitContextBaseTagged(ASN1TaggedObject taggedObject, int tagNo,
        int baseTagClass, int baseTagNo)
    {
        return tryGetImplicitBaseTagged(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo, baseTagClass, baseTagNo);
    }


    /*
     * Wrappers for ASN1TaggedObject#getBaseUniversal
     */

    public static ASN1Primitive getBaseUniversal(ASN1TaggedObject taggedObject, int tagClass, int tagNo,
        boolean declaredExplicit, int baseTagNo)
    {
        return checkTag(taggedObject, tagClass, tagNo).getBaseUniversal(declaredExplicit, baseTagNo);  
    }

    public static ASN1Primitive getContextBaseUniversal(ASN1TaggedObject taggedObject, int tagNo,
        boolean declaredExplicit, int baseTagNo)
    {
        return getBaseUniversal(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagNo);
    }

    public static ASN1Primitive tryGetBaseUniversal(ASN1TaggedObject taggedObject, int tagClass, int tagNo,
        boolean declaredExplicit, int baseTagNo)
    {
        if (!taggedObject.hasTag(tagClass, tagNo))
        {
            return null;
        }

        return taggedObject.getBaseUniversal(declaredExplicit, baseTagNo);  
    }

    public static ASN1Primitive tryGetContextBaseUniversal(ASN1TaggedObject taggedObject, int tagNo,
        boolean declaredExplicit, int baseTagNo)
    {
        return tryGetBaseUniversal(taggedObject, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagNo);
    }


    /*
     * Wrappers for ASN1TaggedObjectParser#parseExplicitBaseTagged
     */

    public static ASN1TaggedObjectParser parseExplicitBaseTagged(ASN1TaggedObjectParser taggedObjectParser,
        int tagClass, int tagNo) throws IOException
    {
        return checkTag(taggedObjectParser, tagClass, tagNo).parseExplicitBaseTagged();
    }

    public static ASN1TaggedObjectParser parseExplicitContextBaseTagged(ASN1TaggedObjectParser taggedObjectParser,
        int tagNo) throws IOException
    {
        return parseExplicitBaseTagged(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo);
    }

    public static ASN1TaggedObjectParser tryParseExplicitBaseTagged(ASN1TaggedObjectParser taggedObjectParser,
        int tagClass, int tagNo) throws IOException
    {
        if (!taggedObjectParser.hasTag(tagClass, tagNo))
        {
            return null;
        }

        return taggedObjectParser.parseExplicitBaseTagged();
    }

    public static ASN1TaggedObjectParser tryParseExplicitContextBaseTagged(ASN1TaggedObjectParser taggedObjectParser,
        int tagNo) throws IOException
    {
        return tryParseExplicitBaseTagged(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo);
    }


    /*
     * Wrappers for ASN1TaggedObjectParser#parseImplicitBaseTagged
     */

    public static ASN1TaggedObjectParser parseImplicitBaseTagged(ASN1TaggedObjectParser taggedObjectParser,
        int tagClass, int tagNo, int baseTagClass, int baseTagNo) throws IOException
    {
        return checkTag(taggedObjectParser, tagClass, tagNo).parseImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObjectParser parseImplicitContextBaseTagged(ASN1TaggedObjectParser taggedObjectParser,
        int tagNo, int baseTagClass, int baseTagNo) throws IOException
    {
        return parseImplicitBaseTagged(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObjectParser tryParseImplicitBaseTagged(ASN1TaggedObjectParser taggedObjectParser,
        int tagClass, int tagNo, int baseTagClass, int baseTagNo) throws IOException
    {
        if (!taggedObjectParser.hasTag(tagClass, tagNo))
        {
            return null;
        }

        return taggedObjectParser.parseImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public static ASN1TaggedObjectParser tryParseImplicitContextBaseTagged(ASN1TaggedObjectParser taggedObjectParser,
        int tagNo, int baseTagClass, int baseTagNo) throws IOException
    {
        return tryParseImplicitBaseTagged(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, baseTagClass, baseTagNo);
    }


    /*
     * Wrappers for ASN1TaggedObjectParser#parseBaseUniversal
     */

    public static ASN1Encodable parseBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagClass,
        int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException
    {
        return checkTag(taggedObjectParser, tagClass, tagNo).parseBaseUniversal(declaredExplicit, baseTagNo);
    }

    public static ASN1Encodable parseContextBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagNo,
        boolean declaredExplicit, int baseTagNo) throws IOException
    {
        return parseBaseUniversal(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagNo);
    }

    public static ASN1Encodable tryParseBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagClass,
        int tagNo, boolean declaredExplicit, int baseTagNo) throws IOException
    {
        if (!taggedObjectParser.hasTag(tagClass, tagNo))
        {
            return null;
        }

        return taggedObjectParser.parseBaseUniversal(declaredExplicit, baseTagNo);
    }

    public static ASN1Encodable tryParseContextBaseUniversal(ASN1TaggedObjectParser taggedObjectParser, int tagNo,
        boolean declaredExplicit, int baseTagNo) throws IOException
    {
        return tryParseBaseUniversal(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo, declaredExplicit, baseTagNo);
    }


    /*
     * Wrappers for ASN1TaggedObjectParser#parseExplicitBaseObject
     */

    public static ASN1Encodable parseExplicitBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagClass,
        int tagNo) throws IOException
    {
        return checkTag(taggedObjectParser, tagClass, tagNo).parseExplicitBaseObject();
    }

    public static ASN1Encodable parseExplicitContextBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagNo)
        throws IOException
    {
        return parseExplicitBaseObject(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo);
    }

    public static ASN1Encodable tryParseExplicitBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagClass,
        int tagNo) throws IOException
    {
        if (!taggedObjectParser.hasTag(tagClass, tagNo))
        {
            return null;
        }

        return taggedObjectParser.parseExplicitBaseObject();
    }

    public static ASN1Encodable tryParseExplicitContextBaseObject(ASN1TaggedObjectParser taggedObjectParser, int tagNo)
        throws IOException
    {
        return tryParseExplicitBaseObject(taggedObjectParser, BERTags.CONTEXT_SPECIFIC, tagNo);
    }
}
