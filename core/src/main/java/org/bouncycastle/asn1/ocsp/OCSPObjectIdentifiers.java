package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * OIDs for <a href="https://tools.ietf.org/html/rfc2560">RFC 2560</a> and <a href="https://tools.ietf.org/html/rfc6960">RFC 6960</a>
 * Online Certificate Status Protocol - OCSP.
 */
public interface OCSPObjectIdentifiers
{
    /** OID: 1.3.6.1.5.5.7.48.1 */
    ASN1ObjectIdentifier id_pkix_ocsp = X509ObjectIdentifiers.id_ad_ocsp;

    /** OID: 1.3.6.1.5.5.7.48.1.1 */
    ASN1ObjectIdentifier id_pkix_ocsp_basic = id_pkix_ocsp.branch("1");
    /** OID: 1.3.6.1.5.5.7.48.1.2 */
    ASN1ObjectIdentifier id_pkix_ocsp_nonce = id_pkix_ocsp.branch("2");
    /** OID: 1.3.6.1.5.5.7.48.1.3 */
    ASN1ObjectIdentifier id_pkix_ocsp_crl = id_pkix_ocsp.branch("3");
    /** OID: 1.3.6.1.5.5.7.48.1.4 */
    ASN1ObjectIdentifier id_pkix_ocsp_response = id_pkix_ocsp.branch("4");
    /** OID: 1.3.6.1.5.5.7.48.1.5 */
    ASN1ObjectIdentifier id_pkix_ocsp_nocheck = id_pkix_ocsp.branch("5");
    /** OID: 1.3.6.1.5.5.7.48.1.6 */
    ASN1ObjectIdentifier id_pkix_ocsp_archive_cutoff = id_pkix_ocsp.branch("6");
    /** OID: 1.3.6.1.5.5.7.48.1.7 */
    ASN1ObjectIdentifier id_pkix_ocsp_service_locator = id_pkix_ocsp.branch("7");
    /** OID: 1.3.6.1.5.5.7.48.1.8 */
    ASN1ObjectIdentifier id_pkix_ocsp_pref_sig_algs = id_pkix_ocsp.branch("8");
    /** OID: 1.3.6.1.5.5.7.48.1.9 */
    ASN1ObjectIdentifier id_pkix_ocsp_extended_revoke = id_pkix_ocsp.branch("9");
}
