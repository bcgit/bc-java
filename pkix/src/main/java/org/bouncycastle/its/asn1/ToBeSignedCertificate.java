package org.bouncycastle.its.asn1;

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
{
}
