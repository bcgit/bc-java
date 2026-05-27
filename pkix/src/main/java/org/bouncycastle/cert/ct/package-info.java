/**
 * Decoders for the embedded Signed Certificate Timestamp extensions defined by
 * RFC 6962 (Certificate Transparency v1) and RFC 9162 (CT v2).
 * <p>
 * For v1, {@link org.bouncycastle.cert.ct.SignedCertificateTimestampList} parses the
 * TLS-encoded list of {@link org.bouncycastle.cert.ct.SignedCertificateTimestamp} entries
 * carried inside the {@code 1.3.6.1.4.1.11129.2.4.2} extension. For v2,
 * {@link org.bouncycastle.cert.ct.TransItemList} parses the TLS-encoded list of
 * {@link org.bouncycastle.cert.ct.TransItem} entries carried inside the
 * {@code 1.3.101.75} extension; SCT-typed items expose their payload via
 * {@link org.bouncycastle.cert.ct.SignedCertificateTimestampDataV2}.
 * <p>
 * This is a decode-only API: verifying an SCT against a log's STH (fetching the
 * inclusion proof and checking the log's public-key signature) is intentionally not
 * provided here.
 */
package org.bouncycastle.cert.ct;
