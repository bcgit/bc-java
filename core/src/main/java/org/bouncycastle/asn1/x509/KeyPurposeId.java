package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;

/**
 * The KeyPurposeId object.
 * <pre>
 *     KeyPurposeId ::= OBJECT IDENTIFIER
 *
 *     id-kp ::= OBJECT IDENTIFIER { iso(1) identified-organization(3)
 *          dod(6) internet(1) security(5) mechanisms(5) pkix(7) 3}
 *
 * </pre>
 * To create a new KeyPurposeId where none of the below suit, use
 * <pre>
 *     ASN1ObjectIdentifier newKeyPurposeIdOID = new ASN1ObjectIdentifier("1.3.6.1...");
 *
 *     KeyPurposeId newKeyPurposeId = KeyPurposeId.getInstance(newKeyPurposeIdOID);
 * </pre>
 */
public class KeyPurposeId
    extends ASN1Object
{
    private static final ASN1ObjectIdentifier id_kp = X509ObjectIdentifiers.id_pkix.branch("3");

    /**
     * { 2 5 29 37 0 }
     */
    public static final KeyPurposeId anyExtendedKeyUsage = new KeyPurposeId(Extension.extendedKeyUsage.branch("0"));

    /**
     * { id-kp 1 }
     */
    public static final KeyPurposeId id_kp_serverAuth = new KeyPurposeId(id_kp.branch("1"));
    /**
     * { id-kp 2 }
     */
    public static final KeyPurposeId id_kp_clientAuth = new KeyPurposeId(id_kp.branch("2"));
    /**
     * { id-kp 3 }
     */
    public static final KeyPurposeId id_kp_codeSigning = new KeyPurposeId(id_kp.branch("3"));
    /**
     * { id-kp 4 }
     */
    public static final KeyPurposeId id_kp_emailProtection = new KeyPurposeId(id_kp.branch("4"));
    /**
     * Usage deprecated by RFC4945 - was { id-kp 5 }
     */
    public static final KeyPurposeId id_kp_ipsecEndSystem = new KeyPurposeId(id_kp.branch("5"));
    /**
     * Usage deprecated by RFC4945 - was { id-kp 6 }
     */
    public static final KeyPurposeId id_kp_ipsecTunnel = new KeyPurposeId(id_kp.branch("6"));
    /**
     * Usage deprecated by RFC4945 - was { idkp 7 }
     */
    public static final KeyPurposeId id_kp_ipsecUser = new KeyPurposeId(id_kp.branch("7"));
    /**
     * { id-kp 8 }
     */
    public static final KeyPurposeId id_kp_timeStamping = new KeyPurposeId(id_kp.branch("8"));
    /**
     * { id-kp 9 }
     */
    public static final KeyPurposeId id_kp_OCSPSigning = new KeyPurposeId(id_kp.branch("9"));
    /**
     * { id-kp 10 }
     */
    public static final KeyPurposeId id_kp_dvcs = new KeyPurposeId(id_kp.branch("10"));
    /**
     * { id-kp 11 }
     */
    public static final KeyPurposeId id_kp_sbgpCertAAServerAuth = new KeyPurposeId(id_kp.branch("11"));
    /**
     * { id-kp 12 }
     */
    public static final KeyPurposeId id_kp_scvp_responder = new KeyPurposeId(id_kp.branch("12"));
    /**
     * { id-kp 13 }
     */
    public static final KeyPurposeId id_kp_eapOverPPP = new KeyPurposeId(id_kp.branch("13"));
    /**
     * { id-kp 14 }
     */
    public static final KeyPurposeId id_kp_eapOverLAN = new KeyPurposeId(id_kp.branch("14"));
    /**
     * { id-kp 15 }
     */
    public static final KeyPurposeId id_kp_scvpServer = new KeyPurposeId(id_kp.branch("15"));
    /**
     * { id-kp 16 }
     */
    public static final KeyPurposeId id_kp_scvpClient = new KeyPurposeId(id_kp.branch("16"));
    /**
     * { id-kp 17 }
     */
    public static final KeyPurposeId id_kp_ipsecIKE = new KeyPurposeId(id_kp.branch("17"));
    /**
     * RFC 6187 sec. 2.2.2 - authenticating an SSH client.
     * <p>
     * id-kp-secureShellClient OBJECT IDENTIFIER ::= { id-kp 21 }
     */
    public static final KeyPurposeId id_kp_secureShellClient = new KeyPurposeId(id_kp.branch("21"));
    /**
     * RFC 6187 sec. 2.2.2 - authenticating an SSH server.
     * <p>
     * id-kp-secureShellServer OBJECT IDENTIFIER ::= { id-kp 22 }
     */
    public static final KeyPurposeId id_kp_secureShellServer = new KeyPurposeId(id_kp.branch("22"));
    /**
     * { id-kp 18 }
     */
    public static final KeyPurposeId id_kp_capwapAC = new KeyPurposeId(id_kp.branch("18"));
    /**
     * { id-kp 19 }
     */
    public static final KeyPurposeId id_kp_capwapWTP = new KeyPurposeId(id_kp.branch("19"));


    /**
     * id-kp-cmcCA OBJECT IDENTIFIER ::= {
     *          iso(1) identified-organization(3) dod(6) internet(1)
     *          security(5) mechanisms(5) pkix(7) kp(3) 27 }
     */
    public static final KeyPurposeId id_kp_cmcCA = new KeyPurposeId(id_kp.branch("27"));

    /**
     * id-kp-cmcRA OBJECT IDENTIFIER ::= {
     *          iso(1) identified-organization(3) dod(6) internet(1)
     *          security(5) mechanisms(5) pkix(7) kp(3) 28 }
     */
    public static final KeyPurposeId id_kp_cmcRA = new KeyPurposeId(id_kp.branch("28"));
    /**
     * RFC 6402 sec. 2.10 - a CMC key archival server.
     * <p>
     * id-kp-cmcArchive OBJECT IDENTIFIER ::= {
     *          iso(1) identified-organization(3) dod(6) internet(1)
     *          security(5) mechanisms(5) pkix(7) kp(3) 29 }
     */
    public static final KeyPurposeId id_kp_cmcArchive = new KeyPurposeId(id_kp.branch("29"));

    /**
     * id-kp-cmKGA OBJECT IDENTIFIER ::= {
     *          iso(1) identified-organization(3) dod(6) internet(1)
     *          security(5) mechanisms(5) pkix(7) kp(3) 32 }
     */
    public static final KeyPurposeId id_kp_cmKGA = new KeyPurposeId(id_kp.branch("32"));

    /**
     * RFC 9174 sec. 4.4.1 - Delay-Tolerant Networking bundle security (TCPCLv4).
     * <p>
     * id-kp-bundleSecurity OBJECT IDENTIFIER ::= { id-kp 35 }
     */
    public static final KeyPurposeId id_kp_bundleSecurity = new KeyPurposeId(id_kp.branch("35"));
    /**
     * RFC 9336 sec. 3.1 - signing documents (e.g. PDF, XML, JSON) for human consumption.
     * <p>
     * id-kp-documentSigning OBJECT IDENTIFIER ::= { id-kp 36 }
     */
    public static final KeyPurposeId id_kp_documentSigning = new KeyPurposeId(id_kp.branch("36"));

    /**
     * RFC 9509 sec. 3 - signing the JWT Claims Set of a Client Credentials Assertion (CCA)
     * using JWS, for 5G Network Function service consumers.
     * <p>
     * id-kp-jwt OBJECT IDENTIFIER ::= { id-kp 37 }
     */
    public static final KeyPurposeId id_kp_jwt = new KeyPurposeId(id_kp.branch("37"));

    /**
     * RFC 9509 sec. 3 - encrypting JSON objects in HTTP messages between 5G Security Edge
     * Protection Proxies (SEPPs) using JWE.
     * <p>
     * id-kp-httpContentEncrypt OBJECT IDENTIFIER ::= { id-kp 38 }
     */
    public static final KeyPurposeId id_kp_httpContentEncrypt = new KeyPurposeId(id_kp.branch("38"));

    /**
     * RFC 9509 sec. 3 - signing OAuth 2.0 access tokens for service authorization using JWS,
     * as issued by a 5G Network Repository Function (NRF).
     * <p>
     * id-kp-oauthAccessTokenSigning OBJECT IDENTIFIER ::= { id-kp 39 }
     */
    public static final KeyPurposeId id_kp_oauthAccessTokenSigning = new KeyPurposeId(id_kp.branch("39"));

    /**
     * RFC 9734 sec. 3 - proving the identity of an Instant Messaging (IM) client,
     * whose IM URI (RFC 3860) or XMPP URI (RFC 6121) appears in the subjectAltName.
     * <p>
     * id-kp-imUri OBJECT IDENTIFIER ::= { id-kp 40 }
     */
    public static final KeyPurposeId id_kp_imUri = new KeyPurposeId(id_kp.branch("40"));

    /**
     * RFC 9809 sec. 3 - signing general-purpose configuration files.
     * <p>
     * id-kp-configSigning OBJECT IDENTIFIER ::= { id-kp 41 }
     */
    public static final KeyPurposeId id_kp_configSigning = new KeyPurposeId(id_kp.branch("41"));

    /**
     * RFC 9809 sec. 3 - signing trust anchor configuration files.
     * <p>
     * id-kp-trustAnchorConfigSigning OBJECT IDENTIFIER ::= { id-kp 42 }
     */
    public static final KeyPurposeId id_kp_trustAnchorConfigSigning = new KeyPurposeId(id_kp.branch("42"));

    /**
     * RFC 9809 sec. 3 - signing software or firmware update packages.
     * <p>
     * id-kp-updatePackageSigning OBJECT IDENTIFIER ::= { id-kp 43 }
     */
    public static final KeyPurposeId id_kp_updatePackageSigning = new KeyPurposeId(id_kp.branch("43"));

    /**
     * RFC 9809 sec. 3 - authenticating communication peers for safety-critical communication.
     * <p>
     * id-kp-safetyCommunication OBJECT IDENTIFIER ::= { id-kp 44 }
     */
    public static final KeyPurposeId id_kp_safetyCommunication = new KeyPurposeId(id_kp.branch("44"));



    //
    // microsoft key purpose ids
    //
    /**
     * { 1 3 6 1 4 1 311 20 2 2 }
     */
    public static final KeyPurposeId id_kp_smartcardlogon = new KeyPurposeId(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"));


    /**
     *
     */
    public static final KeyPurposeId id_kp_macAddress = new KeyPurposeId(new ASN1ObjectIdentifier("1.3.6.1.1.1.1.22"));


    /**
     * Microsoft Server Gated Crypto (msSGC) see https://www.alvestrand.no/objectid/1.3.6.1.4.1.311.10.3.3.html
     */
    public static final KeyPurposeId id_kp_msSGC = new KeyPurposeId(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.3.3"));

    /**
     * Netscape Server Gated Crypto (nsSGC) see https://www.alvestrand.no/objectid/2.16.840.1.113730.4.1.html
     */
    public static final KeyPurposeId id_kp_nsSGC = new KeyPurposeId(new ASN1ObjectIdentifier("2.16.840.1.113730.4.1"));



    //
    // kerberos PKINIT key purpose ids
    //
    /**
     * RFC 4556 sec. 3.2.2 - the extended key usage a KDC may require in a client's
     * certificate for PKINIT.
     * <pre>
     * id-pkinit-KPClientAuth OBJECT IDENTIFIER ::=
     *     { iso(1) org(3) dod(6) internet(1) security(5) kerberosv5(2)
     *       pkinit(3) keyPurposeClientAuth(4) }
     * </pre>
     */
    public static final KeyPurposeId id_kp_pkinitClientAuth = new KeyPurposeId(IANAObjectIdentifiers.id_pkinit.branch("4"));

    /**
     * RFC 4556 sec. 3.2.4 - the extended key usage a client requires in the KDC's
     * certificate for PKINIT.
     * <pre>
     * id-pkinit-KPKdc OBJECT IDENTIFIER ::=
     *     { iso(1) org(3) dod(6) internet(1) security(5) kerberosv5(2)
     *       pkinit(3) keyPurposeKdc(5) }
     * </pre>
     */
    public static final KeyPurposeId id_kp_pkinitKdc = new KeyPurposeId(IANAObjectIdentifiers.id_pkinit.branch("5"));


    private ASN1ObjectIdentifier id;

    private KeyPurposeId(ASN1ObjectIdentifier id)
    {
        this.id = id;
    }

    public static KeyPurposeId getInstance(Object o)
    {
        if (o instanceof KeyPurposeId)
        {
            return (KeyPurposeId)o;
        }
        else if (o != null)
        {
            return new KeyPurposeId(ASN1ObjectIdentifier.getInstance(o));
        }

        return null;
    }

    public ASN1ObjectIdentifier toOID()
    {
        return id;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return id;
    }

    public String getId()
    {
        return id.getId();
    }

    public String toString()
    {
        return id.toString();
    }
}
