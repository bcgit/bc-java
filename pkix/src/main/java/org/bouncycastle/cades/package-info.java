/**
 * High-level CAdES (CMS Advanced Electronic Signatures) builders.
 * <p>
 * This package wraps the existing {@code cms} / {@code tsp} primitives with
 * profile-aware builders for the four CAdES baseline levels of
 * <a href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/">ETSI
 * EN&nbsp;319&nbsp;122-1</a> (and the older
 * <a href="https://www.rfc-editor.org/rfc/rfc5126">RFC&nbsp;5126</a> profile
 * names):
 * <ul>
 *   <li><b>B-B</b> (BES) &mdash;
 *       {@link org.bouncycastle.cades.CAdESSignerInfoGeneratorBuilder} +
 *       {@link org.bouncycastle.cades.CAdESSignedDataGenerator}: a CMS
 *       SignedData carrying the mandatory ESS signing-certificate(-v2)
 *       reference plus optional commitment-type, signature-policy,
 *       signer-location and content-hints signed attributes.</li>
 *   <li><b>B-T</b> (T) &mdash;
 *       {@link org.bouncycastle.cades.CAdESSignatureTimestampUtil}: attaches
 *       an id-aa-signatureTimeStampToken unsigned attribute over the
 *       SignerInfo signature value.</li>
 *   <li><b>B-LT</b> (C-X-L) &mdash;
 *       {@link org.bouncycastle.cades.CAdESLongTermValuesUtil}: attaches the
 *       four long-term validation-data unsigned attributes
 *       (id-aa-ets-certificateRefs / certValues / revocationRefs /
 *       revocationValues) for offline validation.</li>
 *   <li><b>B-LTA</b> (A) &mdash;
 *       {@link org.bouncycastle.cades.CAdESArchiveTimestampUtil}: attaches an
 *       id-aa-ets-archiveTimestampV2 (ETSI TS 101 733 v1.7.4) unsigned
 *       attribute over a canonical concatenation of the SignedData, with
 *       existing archive-timestamps stripped so chains are renewable.</li>
 * </ul>
 * <p>
 * {@link org.bouncycastle.cades.CAdESLevelDetector} inspects a
 * {@link org.bouncycastle.cms.SignerInformation} and reports the attained
 * baseline level. None of these classes embed an HTTP / OCSP transport &mdash;
 * callers fetch timestamps, CRLs and OCSP responses out-of-band and pass them
 * in. The low-level ASN.1 types for all CAdES attributes live in
 * {@code org.bouncycastle.asn1.esf} and {@code org.bouncycastle.asn1.ess};
 * callers needing fine-grained control over a signature&apos;s shape can
 * build those directly and feed them to a standard
 * {@link org.bouncycastle.cms.CMSSignedDataGenerator}.
 */
package org.bouncycastle.cades;
