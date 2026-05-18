package org.bouncycastle.asn1.est;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * <a href="https://tools.ietf.org/html/rfc7894#section-3.3">RFC 7894 §3.3</a>
 * {@code estIdentityLinking} attribute: an unambiguous replacement for the
 * overloaded PKCS#9 {@code challengePassword} attribute when used to convey
 * the {@code tls-unique} value linking the certificate request to the
 * authenticated TLS session per
 * <a href="https://tools.ietf.org/html/rfc7030#section-3.5">RFC 7030 §3.5</a>.
 * <pre>
 * estIdentityLinking ATTRIBUTE ::= {
 *     WITH SYNTAX DirectoryString {ub-aa-est-identity-linking}
 *     EQUALITY MATCHING RULE caseExactMatch
 *     SINGLE VALUE TRUE
 *     ID id-aa-estIdentityLinking
 * }
 * ub-aa-est-identity-linking INTEGER ::= 255
 * </pre>
 * Identified by {@link PKCSObjectIdentifiers#id_aa_estIdentityLinking}.
 */
public class EstIdentityLinking
    extends CSRChallengeAttribute
{
    public EstIdentityLinking(String value)
    {
        super(value);
    }

    public EstIdentityLinking(DirectoryString value)
    {
        super(value);
    }

    public static EstIdentityLinking getInstance(Object obj)
    {
        if (obj == null || obj instanceof EstIdentityLinking)
        {
            return (EstIdentityLinking)obj;
        }
        return new EstIdentityLinking(DirectoryString.getInstance(obj));
    }

    /**
     * Extract the {@code estIdentityLinking} value carried by a PKCS#9 {@link Attribute}.
     *
     * @throws IllegalArgumentException if the attribute is not
     *         {@link PKCSObjectIdentifiers#id_aa_estIdentityLinking} or does not
     *         carry exactly one value.
     */
    public static EstIdentityLinking fromAttribute(Attribute attribute)
    {
        return getInstance(extractValue(attribute, PKCSObjectIdentifiers.id_aa_estIdentityLinking));
    }

    protected ASN1ObjectIdentifier getAttrType()
    {
        return PKCSObjectIdentifiers.id_aa_estIdentityLinking;
    }
}
