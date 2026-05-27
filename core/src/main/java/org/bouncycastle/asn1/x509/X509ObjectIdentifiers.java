package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;

public interface X509ObjectIdentifiers
{
    static final ASN1ObjectIdentifier attributeType = new ASN1ObjectIdentifier("2.5.4").intern();

    /** Subject RDN components: commonName = 2.5.4.3 */
    static final ASN1ObjectIdentifier    commonName              = attributeType.branch("3").intern();
    /** Subject RDN components: countryName = 2.5.4.6 */
    static final ASN1ObjectIdentifier    countryName             = attributeType.branch("6").intern();
    /** Subject RDN components: localityName = 2.5.4.7 */
    static final ASN1ObjectIdentifier    localityName            = attributeType.branch("7").intern();
    /** Subject RDN components: stateOrProvinceName = 2.5.4.8 */
    static final ASN1ObjectIdentifier    stateOrProvinceName     = attributeType.branch("8").intern();
    /** Subject RDN components: organization = 2.5.4.10 */
    static final ASN1ObjectIdentifier    organization            = attributeType.branch("10").intern();
    /** Subject RDN components: organizationalUnitName = 2.5.4.11 */
    static final ASN1ObjectIdentifier    organizationalUnitName  = attributeType.branch("11").intern();

    /** Subject RDN components: telephone_number = 2.5.4.20 */
    static final ASN1ObjectIdentifier    id_at_telephoneNumber   = attributeType.branch("20").intern();
    /** Subject RDN components: name = 2.5.4.41 */
    static final ASN1ObjectIdentifier    id_at_name              = attributeType.branch("41").intern();
    /** Subject RDN components: organizationIdentifier = 2.5.4.97 */
    static final ASN1ObjectIdentifier    id_at_organizationIdentifier = attributeType.branch("97").intern();

    /**
     * id-SHA1 OBJECT IDENTIFIER ::=    
     *   {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }
     * <p>
     * OID: 1.3.14.3.2.26
     */
    static final ASN1ObjectIdentifier    id_SHA1                 = new ASN1ObjectIdentifier("1.3.14.3.2.26").intern();

    /**
     * ripemd160 OBJECT IDENTIFIER ::=
     *      {iso(1) identified-organization(3) TeleTrust(36) algorithm(3) hashAlgorithm(2) RIPEMD-160(1)}
     * <p>
     * OID: 1.3.36.3.2.1
     */
    static final ASN1ObjectIdentifier    ripemd160               = new ASN1ObjectIdentifier("1.3.36.3.2.1").intern();

    /**
     * ripemd160WithRSAEncryption OBJECT IDENTIFIER ::=
     *      {iso(1) identified-organization(3) TeleTrust(36) algorithm(3) signatureAlgorithm(3) rsaSignature(1) rsaSignatureWithripemd160(2) }
     * <p>
     * OID: 1.3.36.3.3.1.2
     */
    static final ASN1ObjectIdentifier    ripemd160WithRSAEncryption = new ASN1ObjectIdentifier("1.3.36.3.3.1.2").intern();


    /** OID: 2.5.8.1.1  */
    static final ASN1ObjectIdentifier    id_ea_rsa = new ASN1ObjectIdentifier("2.5.8.1.1").intern();
    
    /** id-pkix OID: 1.3.6.1.5.5.7
     */
    static final ASN1ObjectIdentifier  id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");

    /**
     * private internet extensions; OID = 1.3.6.1.5.5.7.1
     */
    static final ASN1ObjectIdentifier  id_pe   = id_pkix.branch("1");

    /**
     * id-pe-relatedCert OBJECT IDENTIFIER ::= { iso(1)
     *        identified-organization(3) dod(6) internet(1)
     *        security(5) mechanisms(5) pkix(7) pe(1) 36 }
     * <p>
     * Per RFC 9763 sec. 3, the {@code RelatedCertificate} certificate
     * extension. The extension MUST
     * appear in an end-entity certificate only, SHOULD NOT be marked critical,
     * and carries a digest of one previously-issued certificate (the "related
     * certificate") that the CA is asserting belongs to the same end entity —
     * the mechanism that lets a verifier link a classical and a post-quantum
     * certificate during hybrid PQ migration without requiring composite
     * signature algorithms.
     */
    ASN1ObjectIdentifier id_pe_relatedCert = id_pe.branch("36");

    /** 1.3.6.1.5.5.7.6 */
    static final ASN1ObjectIdentifier pkix_algorithms = id_pkix.branch("6");

    /**
     *    id-RSASSA-PSS-SHAKE128  OBJECT IDENTIFIER  ::=  { iso(1)
     *             identified-organization(3) dod(6) internet(1)
     *             security(5) mechanisms(5) pkix(7) algorithms(6) 30 }
     */
    static final ASN1ObjectIdentifier id_rsassa_pss_shake128 = pkix_algorithms.branch("30");

    /**
     *    id-RSASSA-PSS-SHAKE256  OBJECT IDENTIFIER  ::=  { iso(1)
     *             identified-organization(3) dod(6) internet(1)
     *             security(5) mechanisms(5) pkix(7) algorithms(6) 31 }
     */
    static final ASN1ObjectIdentifier id_rsassa_pss_shake256 = pkix_algorithms.branch("31");

    /**
     * id-ecdsa-with-shake128 OBJECT IDENTIFIER  ::=  { iso(1)
     *        identified-organization(3) dod(6) internet(1)
     *        security(5) mechanisms(5) pkix(7) algorithms(6) 32 }
     */
    static final ASN1ObjectIdentifier id_ecdsa_with_shake128 = pkix_algorithms.branch("32");

    /**
     * id-ecdsa-with-shake256 OBJECT IDENTIFIER  ::=  { iso(1)
     *         identified-organization(3) dod(6) internet(1)
     *         security(5) mechanisms(5) pkix(7) algorithms(6) 33 }
     */
    static final ASN1ObjectIdentifier id_ecdsa_with_shake256 = pkix_algorithms.branch("33");

    /**
     * id-alg-noSignature OBJECT IDENTIFIER ::= {id-pkix id-alg(6) 2}
     */
    ASN1ObjectIdentifier id_alg_noSignature = pkix_algorithms.branch("2");

    /**
     * id-alg-unsigned OBJECT IDENTIFIER ::= {id-pkix id-alg(6) 36}
     */
    ASN1ObjectIdentifier id_alg_unsigned = pkix_algorithms.branch("36");
    
    /** 1.3.6.1.5.5.7.9 */
    static final ASN1ObjectIdentifier id_pda = id_pkix.branch("9");

    /** id-pkix OID:         1.3.6.1.5.5.7.48  */
    static final ASN1ObjectIdentifier  id_ad           = id_pkix.branch("48");
    /** id-ad-caIssuers OID: 1.3.6.1.5.5.7.48.2  */
    static final ASN1ObjectIdentifier  id_ad_caIssuers = id_ad.branch("2").intern();
    /** id-ad-ocsp OID:      1.3.6.1.5.5.7.48.1  */
    static final ASN1ObjectIdentifier  id_ad_ocsp      = id_ad.branch("1").intern();

    /** OID for ocsp uri in AuthorityInformationAccess extension */
    static final ASN1ObjectIdentifier ocspAccessMethod = id_ad_ocsp;
    /** OID for crl uri in AuthorityInformationAccess extension */
    static final ASN1ObjectIdentifier crlAccessMethod  = id_ad_caIssuers;

    /**
     * ISO ARC for standard certificate and CRL extensions
     * <p>
     * OID: 2.5.29
     */
    static final ASN1ObjectIdentifier id_ce = new ASN1ObjectIdentifier("2.5.29");

    /**
     * Google's Certificate Transparency arc, the parent of the OIDs defined
     * by RFC 6962. Not under the standard PKIX id-pe / id-ce trees because
     * the values predate RFC 6962's transition to IETF process.
     * <p>
     * OID: 1.3.6.1.4.1.11129.2.4
     */
    static final ASN1ObjectIdentifier id_ct = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4");

    /**
     * RFC 6962 sec. 3.3 / RFC 9162 sec. 4.1 — certificate extension carrying
     * the TLS-encoded {@code SignedCertificateTimestampList} for a server
     * certificate.
     * <p>
     * OID: 1.3.6.1.4.1.11129.2.4.2
     */
    static final ASN1ObjectIdentifier id_ce_ct_embeddedSCTList = id_ct.branch("2");

    /**
     * RFC 6962 sec. 3.1 / RFC 9162 sec. 4.2 — the precertificate-poison
     * critical extension that marks a CMS as a precertificate (i.e. not a
     * valid TLS certificate, used only for CT log submission).
     * <p>
     * OID: 1.3.6.1.4.1.11129.2.4.3
     */
    static final ASN1ObjectIdentifier id_ce_ct_precertPoison = id_ct.branch("3");

    /**
     * RFC 6962 sec. 3.1 — Extended Key Usage identifier for an intermediate
     * CA delegated to sign precertificates.
     * <p>
     * OID: 1.3.6.1.4.1.11129.2.4.4
     */
    static final ASN1ObjectIdentifier id_kp_ct_precertSigning = id_ct.branch("4");

    /**
     * RFC 6962 sec. 3.3 — OCSP response extension carrying a TLS-encoded
     * {@code SignedCertificateTimestampList} when SCTs are delivered through
     * an OCSP stapling response rather than embedded in the certificate.
     * <p>
     * OID: 1.3.6.1.4.1.11129.2.4.5
     */
    static final ASN1ObjectIdentifier id_ocsp_ct_sctList = id_ct.branch("5");

    /**
     * RFC 9162 sec. 7.1 — the Transparency Information X.509v3 extension,
     * the CT v2 replacement for {@link #id_ce_ct_embeddedSCTList}. Carries a
     * TLS-encoded {@code TransItemList} whose entries are typed under the
     * {@code VersionedTransType} registry. RFC 9162 deliberately drops the
     * poison extension and precertificate-signing EKU concepts from v1;
     * those constants ({@link #id_ce_ct_precertPoison} and
     * {@link #id_kp_ct_precertSigning}) have no v2 counterpart.
     * <p>
     * OID: 1.3.101.75
     */
    static final ASN1ObjectIdentifier id_ce_ct_transparencyInformation
        = new ASN1ObjectIdentifier("1.3.101.75").intern();

    /**
     * RFC 9162 sec. 3.2 — the CMS {@code eContentType} for a CT v2
     * precertificate. The v2 precertificate is wrapped as a CMS SignedData
     * object whose encapContentInfo carries this content type, replacing
     * the v1 approach of issuing a separate precertificate with a critical
     * poison extension.
     * <p>
     * OID: 1.3.101.78
     */
    static final ASN1ObjectIdentifier id_ct_precertificate
        = new ASN1ObjectIdentifier("1.3.101.78").intern();

    /**
     *  id-PasswordBasedMac OBJECT IDENTIFIER ::= { iso(1) member-body(2)
     *          us(840) nt(113533) nsn(7) algorithms(66) 13 }
     *  @deprecated Use CRMFObjectIdentifiers.passwordBasedMac instead 
     */
    static final ASN1ObjectIdentifier id_PasswordBasedMac = MiscObjectIdentifiers.entrust.branch("66.13");
}
