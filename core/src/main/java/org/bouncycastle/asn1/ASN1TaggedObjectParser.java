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

    boolean hasContextTag();

    boolean hasContextTag(int tagNo);

    boolean hasTag(int tagClass, int tagNo);

    boolean hasTagClass(int tagClass);

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
