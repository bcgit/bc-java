package org.bouncycastle.asn1.misc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface MiscObjectIdentifiers
{
    //
    // Netscape
    //       iso/itu(2) joint-assign(16) us(840) uscompany(1) netscape(113730) cert-extensions(1) }
    //
    /**
     * Netscape cert extensions OID base: 2.16.840.1.113730.1
     */
    ASN1ObjectIdentifier netscape = new ASN1ObjectIdentifier("2.16.840.1.113730.1");
    /**
     * Netscape cert CertType OID: 2.16.840.1.113730.1.1
     */
    ASN1ObjectIdentifier netscapeCertType = netscape.branch("1");
    /**
     * Netscape cert BaseURL OID: 2.16.840.1.113730.1.2
     */
    ASN1ObjectIdentifier netscapeBaseURL = netscape.branch("2");
    /**
     * Netscape cert RevocationURL OID: 2.16.840.1.113730.1.3
     */
    ASN1ObjectIdentifier netscapeRevocationURL = netscape.branch("3");
    /**
     * Netscape cert CARevocationURL OID: 2.16.840.1.113730.1.4
     */
    ASN1ObjectIdentifier netscapeCARevocationURL = netscape.branch("4");
    /**
     * Netscape cert RenewalURL OID: 2.16.840.1.113730.1.7
     */
    ASN1ObjectIdentifier netscapeRenewalURL = netscape.branch("7");
    /**
     * Netscape cert CApolicyURL OID: 2.16.840.1.113730.1.8
     */
    ASN1ObjectIdentifier netscapeCApolicyURL = netscape.branch("8");
    /**
     * Netscape cert SSLServerName OID: 2.16.840.1.113730.1.12
     */
    ASN1ObjectIdentifier netscapeSSLServerName = netscape.branch("12");
    /**
     * Netscape cert CertComment OID: 2.16.840.1.113730.1.13
     */
    ASN1ObjectIdentifier netscapeCertComment = netscape.branch("13");

    //
    // Verisign
    //       iso/itu(2) joint-assign(16) us(840) uscompany(1) verisign(113733) cert-extensions(1) }
    //
    /**
     * Verisign OID base: 2.16.840.1.113733.1
     */
    ASN1ObjectIdentifier verisign = new ASN1ObjectIdentifier("2.16.840.1.113733.1");

    /**
     * Verisign CZAG (Country,Zip,Age,Gender) Extension OID: 2.16.840.1.113733.1.6.3
     */
    ASN1ObjectIdentifier verisignCzagExtension = verisign.branch("6.3");

    ASN1ObjectIdentifier verisignPrivate_6_9 = verisign.branch("6.9");
    ASN1ObjectIdentifier verisignOnSiteJurisdictionHash = verisign.branch("6.11");
    ASN1ObjectIdentifier verisignBitString_6_13 = verisign.branch("6.13");

    /**
     * Verisign D&amp;B D-U-N-S number Extension OID: 2.16.840.1.113733.1.6.15
     */
    ASN1ObjectIdentifier verisignDnbDunsNumber = verisign.branch("6.15");

    ASN1ObjectIdentifier verisignIssStrongCrypto = verisign.branch("8.1");

    //
    // Novell
    //       iso/itu(2) country(16) us(840) organization(1) novell(113719)
    //
    /**
     * Novell OID base: 2.16.840.1.113719
     */
    ASN1ObjectIdentifier novell = new ASN1ObjectIdentifier("2.16.840.1.113719");
    /**
     * Novell SecurityAttribs OID: 2.16.840.1.113719.1.9.4.1
     */
    ASN1ObjectIdentifier novellSecurityAttribs = novell.branch("1.9.4.1");

    //
    // Entrust
    //       iso(1) member-body(16) us(840) nortelnetworks(113533) entrust(7)
    //
    /**
     * NortelNetworks Entrust OID base: 1.2.840.113533.7
     */
    ASN1ObjectIdentifier entrust = new ASN1ObjectIdentifier("1.2.840.113533.7");
    /**
     * NortelNetworks Entrust VersionExtension OID: 1.2.840.113533.7.65.0
     */
    ASN1ObjectIdentifier entrustVersionExtension = entrust.branch("65.0");

    /**
     * cast5CBC OBJECT IDENTIFIER ::= {iso(1) member-body(2) us(840) nt(113533) nsn(7) algorithms(66) 10} SEE RFC 2984
     */
    ASN1ObjectIdentifier cast5CBC = entrust.branch("66.10");

    //
    // HMAC-SHA1       hMAC-SHA1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
    //       dod(6) internet(1) security(5) mechanisms(5) 8 1 2 }
    //
    ASN1ObjectIdentifier hMAC_SHA1 = new ASN1ObjectIdentifier("1.3.6.1.5.5.8.1.2");

    //
    // Ascom
    //
    ASN1ObjectIdentifier as_sys_sec_alg_ideaCBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.188.7.1.1.2");

    //
    // Peter Gutmann's Cryptlib
    //
    ASN1ObjectIdentifier cryptlib = new ASN1ObjectIdentifier("1.3.6.1.4.1.3029");

    ASN1ObjectIdentifier cryptlib_algorithm = cryptlib.branch("1");
    ASN1ObjectIdentifier cryptlib_algorithm_blowfish_ECB = cryptlib_algorithm.branch("1.1");
    ASN1ObjectIdentifier cryptlib_algorithm_blowfish_CBC = cryptlib_algorithm.branch("1.2");
    ASN1ObjectIdentifier cryptlib_algorithm_blowfish_CFB = cryptlib_algorithm.branch("1.3");
    ASN1ObjectIdentifier cryptlib_algorithm_blowfish_OFB = cryptlib_algorithm.branch("1.4");

    //
    // Blake2b
    //
    ASN1ObjectIdentifier blake2 = new ASN1ObjectIdentifier("1.3.6.1.4.1.1722.12.2");

    ASN1ObjectIdentifier id_blake2b160 = blake2.branch("1.5");
    ASN1ObjectIdentifier id_blake2b256 = blake2.branch("1.8");
    ASN1ObjectIdentifier id_blake2b384 = blake2.branch("1.12");
    ASN1ObjectIdentifier id_blake2b512 = blake2.branch("1.16");

    ASN1ObjectIdentifier id_blake2s128 = blake2.branch("2.4");
    ASN1ObjectIdentifier id_blake2s160 = blake2.branch("2.5");
    ASN1ObjectIdentifier id_blake2s224 = blake2.branch("2.7");
    ASN1ObjectIdentifier id_blake2s256 = blake2.branch("2.8");

    //
    // Scrypt
    ASN1ObjectIdentifier id_scrypt = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.4.11");

    // Composite key/signature oid - prototyping
    //
    //    id-alg-composite OBJECT IDENTIFIER ::= {
    //        iso(1)  identified-organization(3) dod(6) internet(1) private(4)
    //        enterprise(1) OpenCA(18227) Algorithms(2) id-alg-composite(1) }
    ASN1ObjectIdentifier id_alg_composite = new ASN1ObjectIdentifier("1.3.6.1.4.1.18227.2.1");
}
