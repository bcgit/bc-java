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
     * OID: 1.3.14.3.2.27
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
     *  id-PasswordBasedMac OBJECT IDENTIFIER ::= { iso(1) member-body(2)
     *          us(840) nt(113533) nsn(7) algorithms(66) 13 }
     *  @deprecated Use CRMFObjectIdentifiers.passwordBasedMac instead 
     */
    static final ASN1ObjectIdentifier id_PasswordBasedMac = MiscObjectIdentifiers.entrust.branch("66.13");
}
