package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Interface for the parsing of a generic tagged ASN.1 object.
 */
public interface ASN1TaggedObjectParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Return the tag class associated with this object.
     *
     * @return the tag class.
     */
    int getTagClass();

    /**
     * Return the tag number associated with this object.
     *
     * @return the tag number.
     */
    int getTagNo();

    boolean hasContextTag(int tagNo);

    boolean hasTag(int tagClass, int tagNo);

    /**
     * 
     * Return a parser for the actual object tagged.
     *
     * @param tag        the primitive tag value for the object tagged originally.
     * @param isExplicit true if the tagging was done explicitly.
     * @return a parser for the tagged object.
     * @throws IOException if a parser cannot be constructed.
     * 
     * @deprecated This parser now includes the {@link #getTagClass() tag class}.
     *             This method will raise an exception if it is not
     *             {@link BERTags#CONTEXT_SPECIFIC}. Use
     *             {@link ASN1Util#parseContextBaseUniversal(ASN1TaggedObjectParser, int, int, boolean, int)}
     *             as a direct replacement, or use
     *             {@link #parseBaseUniversal(boolean, int)} only after confirming
     *             the expected tag class (e.g.
     *             {@link ASN1Util#tryParseContextBaseUniversal(ASN1TaggedObjectParser, int, boolean, int)}.
     */
    ASN1Encodable getObjectParser(int tag, boolean isExplicit)
        throws IOException;

    ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException;

    /**
     * Needed for open types, until we have better type-guided parsing support. Use sparingly for other
     * purposes, and prefer {@link #parseExplicitBaseTagged()} or {@link #parseBaseUniversal(boolean, int)}
     * where possible. Before using, check for matching tag {@link #getTagClass() class} and
     * {@link #getTagNo() number}.
     */
    ASN1Encodable parseExplicitBaseObject() throws IOException;

    ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException;

    ASN1TaggedObjectParser parseImplicitBaseTagged(int baseTagClass, int baseTagNo) throws IOException;
}
