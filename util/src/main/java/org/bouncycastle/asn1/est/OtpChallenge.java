package org.bouncycastle.asn1.est;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * <a href="https://tools.ietf.org/html/rfc7894#section-3.1">RFC 7894 §3.1</a>
 * {@code otpChallenge} attribute: a one-time password value conveyed as part of
 * a CSR request. The companion OTP generation and verification mechanisms (e.g.
 * RFC 4226 HOTP, RFC 6238 TOTP) are out of scope.
 * <pre>
 * otpChallenge ATTRIBUTE ::= {
 *     WITH SYNTAX DirectoryString {ub-aa-otpChallenge}
 *     EQUALITY MATCHING RULE caseExactMatch
 *     SINGLE VALUE TRUE
 *     ID id-aa-otpChallenge
 * }
 * ub-aa-otpChallenge INTEGER ::= 255
 * </pre>
 * Identified by {@link PKCSObjectIdentifiers#id_aa_otpChallenge}.
 */
public class OtpChallenge
    extends CSRChallengeAttribute
{
    public OtpChallenge(String value)
    {
        super(value);
    }

    public OtpChallenge(DirectoryString value)
    {
        super(value);
    }

    public static OtpChallenge getInstance(Object obj)
    {
        if (obj == null || obj instanceof OtpChallenge)
        {
            return (OtpChallenge)obj;
        }
        return new OtpChallenge(DirectoryString.getInstance(obj));
    }

    /**
     * Extract the {@code otpChallenge} value carried by a PKCS#9 {@link Attribute}.
     *
     * @throws IllegalArgumentException if the attribute is not
     *         {@link PKCSObjectIdentifiers#id_aa_otpChallenge} or does not carry
     *         exactly one value.
     */
    public static OtpChallenge fromAttribute(Attribute attribute)
    {
        return getInstance(extractValue(attribute, PKCSObjectIdentifiers.id_aa_otpChallenge));
    }

    protected ASN1ObjectIdentifier getAttrType()
    {
        return PKCSObjectIdentifiers.id_aa_otpChallenge;
    }
}
