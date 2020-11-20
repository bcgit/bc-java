package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;


/**
 * <a href="https://tools.ietf.org/html/rfc5652">RFC 5652</a> CMS attribute OID constants.
 * and <a href="https://tools.ietf.org/html/rfc6211">RFC 6211</a> Algorithm Identifier Protection Attribute.
 * <pre>
 * contentType      ::= 1.2.840.113549.1.9.3
 * messageDigest    ::= 1.2.840.113549.1.9.4
 * signingTime      ::= 1.2.840.113549.1.9.5
 * counterSignature ::= 1.2.840.113549.1.9.6
 *
 * contentHint      ::= 1.2.840.113549.1.9.16.2.4
 * cmsAlgorithmProtect := 1.2.840.113549.1.9.52
 * </pre>
 */

public interface CMSAttributes
{
    /** PKCS#9: 1.2.840.113549.1.9.3 */
    ASN1ObjectIdentifier  contentType = PKCSObjectIdentifiers.pkcs_9_at_contentType;
    /** PKCS#9: 1.2.840.113549.1.9.4 */
    ASN1ObjectIdentifier  messageDigest = PKCSObjectIdentifiers.pkcs_9_at_messageDigest;
    /** PKCS#9: 1.2.840.113549.1.9.5 */
    ASN1ObjectIdentifier  signingTime = PKCSObjectIdentifiers.pkcs_9_at_signingTime;
    /** PKCS#9: 1.2.840.113549.1.9.6 */
    ASN1ObjectIdentifier  counterSignature = PKCSObjectIdentifiers.pkcs_9_at_counterSignature;
    /** PKCS#9: 1.2.840.113549.1.9.16.6.2.4 - See <a href="https://tools.ietf.org/html/rfc2634">RFC 2634</a> */
    ASN1ObjectIdentifier  contentHint = PKCSObjectIdentifiers.id_aa_contentHint;

    ASN1ObjectIdentifier  cmsAlgorithmProtect = PKCSObjectIdentifiers.id_aa_cmsAlgorithmProtect;

}
