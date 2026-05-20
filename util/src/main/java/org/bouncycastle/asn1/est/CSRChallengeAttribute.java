package org.bouncycastle.asn1.est;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * Common base for the three EST CSR-challenge attribute value types defined by
 * <a href="https://tools.ietf.org/html/rfc7894">RFC 7894</a>: {@link OtpChallenge},
 * {@link RevocationChallenge} and {@link EstIdentityLinking}.
 * <p>
 * Each is a {@code DirectoryString (SIZE (1..255))}. RFC 7894 §3 says values SHOULD
 * use the PrintableString encoding where possible and the UTF8String encoding
 * otherwise; this base class picks PrintableString when {@link String}-input is in
 * the printable subset and falls back to UTF8String otherwise.
 */
abstract class CSRChallengeAttribute
    extends ASN1Object
{
    private static final int MAX_LENGTH = 255;

    private final DirectoryString value;

    CSRChallengeAttribute(String value)
    {
        if (value == null)
        {
            throw new NullPointerException("value cannot be null");
        }
        checkLength(value.length());
        this.value = chooseEncoding(value);
    }

    CSRChallengeAttribute(DirectoryString value)
    {
        if (value == null)
        {
            throw new NullPointerException("value cannot be null");
        }
        checkLength(value.getString().length());
        this.value = value;
    }

    private static void checkLength(int len)
    {
        if (len < 1 || len > MAX_LENGTH)
        {
            throw new IllegalArgumentException("length must be in 1.." + MAX_LENGTH + ", got " + len);
        }
    }

    private static DirectoryString chooseEncoding(String s)
    {
        if (ASN1PrintableString.isPrintableString(s))
        {
            return DirectoryString.getInstance(new DERPrintableString(s));
        }
        return new DirectoryString(s);
    }

    /**
     * Return the value as a {@link DirectoryString}.
     */
    public DirectoryString getValue()
    {
        return value;
    }

    /**
     * Return the value as a Java {@link String}, decoded from whichever
     * underlying {@code DirectoryString} encoding was used.
     */
    public String getString()
    {
        return value.getString();
    }

    /**
     * The attribute-type OID for this RFC 7894 attribute. Used by
     * {@link #toAttribute()} to wrap the value in a PKCS#9 {@link Attribute}.
     */
    protected abstract ASN1ObjectIdentifier getAttrType();

    /**
     * Wrap this value in a PKCS#9 {@link Attribute} carrying the RFC 7894 OID,
     * ready for inclusion in a {@code CertificationRequest}'s
     * {@code attributes} set (or in a CSR-Attributes response).
     *
     * @return an {@code Attribute} of the form {@code (oid, {value})}.
     */
    public Attribute toAttribute()
    {
        return new Attribute(getAttrType(), new DERSet(value));
    }

    /**
     * Helper for parsing: given an {@link Attribute} whose {@code attrType}
     * matches the supplied OID, return its single value as an
     * {@link ASN1Encodable} suitable for {@code getInstance}.
     *
     * @throws IllegalArgumentException if the attribute type does not match
     *         the expected OID, or the attribute does not carry exactly one value.
     */
    static ASN1Encodable extractValue(Attribute attribute, ASN1ObjectIdentifier expected)
    {
        if (!expected.equals(attribute.getAttrType()))
        {
            throw new IllegalArgumentException("attribute is not " + expected + ", got " + attribute.getAttrType());
        }
        if (attribute.getAttrValues().size() != 1)
        {
            throw new IllegalArgumentException("RFC 7894 attribute must have exactly one value, got " + attribute.getAttrValues().size());
        }
        return attribute.getAttrValues().getObjectAt(0);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return value.toASN1Primitive();
    }
}
