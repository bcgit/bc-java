package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     ToBeSignedCertificate ::= SEQUENCE {
 *         id CertificateId,
 *         cracaId HashedId3,
 *         crlSeries CrlSeries,
 *         validityPeriod ValidityPeriod,
 *         region GeographicRegion OPTIONAL,
 *         assuranceLevel SubjectAssurance OPTIONAL,
 *         appPermissions SequenceOfPsidSep OPTIONAL,
 *         certIssuePermissions SequenceOfPsidGroupPermissions OPTIONAL,
 *         certRequestPermissions NULL OPTIONAL,
 *         encryptionKey PublicEncryptionKey OPTIONAL,
 *         verifyKeyIndicator VerificationKeyIndicator,
 *         ...
 *     }
 * </pre>
 */
public class ToBeSignedCertificate
    extends ASN1Object
{
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
