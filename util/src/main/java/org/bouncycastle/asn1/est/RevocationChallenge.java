package org.bouncycastle.asn1.est;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * <a href="https://tools.ietf.org/html/rfc7894#section-3.2">RFC 7894 §3.2</a>
 * {@code revocationChallenge} attribute: an unambiguous replacement for the
 * overloaded PKCS#9 {@code challengePassword} attribute when its semantic is
 * the original RFC 2985 certificate-revocation password.
 * <pre>
 * revocationChallenge ATTRIBUTE ::= {
 *     WITH SYNTAX DirectoryString {ub-aa-revocationChallenge}
 *     EQUALITY MATCHING RULE caseExactMatch
 *     SINGLE VALUE TRUE
 *     ID id-aa-revocationChallenge
 * }
 * ub-aa-revocationChallenge INTEGER ::= 255
 * </pre>
 * Identified by {@link PKCSObjectIdentifiers#id_aa_revocationChallenge}.
 */
public class RevocationChallenge
    extends CSRChallengeAttribute
{
    public RevocationChallenge(String value)
    {
        super(value);
    }

    public RevocationChallenge(DirectoryString value)
    {
        super(value);
    }

    public static RevocationChallenge getInstance(Object obj)
    {
        if (obj == null || obj instanceof RevocationChallenge)
        {
            return (RevocationChallenge)obj;
        }
        return new RevocationChallenge(DirectoryString.getInstance(obj));
    }

    /**
     * Extract the {@code revocationChallenge} value carried by a PKCS#9 {@link Attribute}.
     *
     * @throws IllegalArgumentException if the attribute is not
     *         {@link PKCSObjectIdentifiers#id_aa_revocationChallenge} or does not
     *         carry exactly one value.
     */
    public static RevocationChallenge fromAttribute(Attribute attribute)
    {
        return getInstance(extractValue(attribute, PKCSObjectIdentifiers.id_aa_revocationChallenge));
    }

    protected ASN1ObjectIdentifier getAttrType()
    {
        return PKCSObjectIdentifiers.id_aa_revocationChallenge;
    }
}
