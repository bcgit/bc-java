package com.github.gv2011.bcasn.asn1.ocsp;

import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;

/**
 * OIDs for <a href="http://tools.ietf.org/html/rfc2560">RFC 2560</a> and <a href="http://tools.ietf.org/html/rfc6960">RFC 6960</a>
 * Online Certificate Status Protocol - OCSP.
 */
public interface OCSPObjectIdentifiers
{
    /** OID: 1.3.6.1.5.5.7.48.1 */
    static final ASN1ObjectIdentifier id_pkix_ocsp       = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1");
    /** OID: 1.3.6.1.5.5.7.48.1.1 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_basic = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.1");
    
    /** OID: 1.3.6.1.5.5.7.48.1.2 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_nonce = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2");
    /** OID: 1.3.6.1.5.5.7.48.1.3 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_crl   = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.3");
    
    /** OID: 1.3.6.1.5.5.7.48.1.4 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_response        = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.4");
    /** OID: 1.3.6.1.5.5.7.48.1.5 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_nocheck         = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5");
    /** OID: 1.3.6.1.5.5.7.48.1.6 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_archive_cutoff  = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.6");
    /** OID: 1.3.6.1.5.5.7.48.1.7 */
    static final ASN1ObjectIdentifier id_pkix_ocsp_service_locator = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.7");


    static final ASN1ObjectIdentifier id_pkix_ocsp_pref_sig_algs = id_pkix_ocsp.branch("8");

    static final ASN1ObjectIdentifier id_pkix_ocsp_extended_revoke = id_pkix_ocsp.branch("9");
}
