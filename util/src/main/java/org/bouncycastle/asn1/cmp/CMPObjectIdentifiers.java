package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;


public interface CMPObjectIdentifiers
{
    // RFC 4210

    /**
     * id-PasswordBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 13}
     */
    ASN1ObjectIdentifier passwordBasedMac = new ASN1ObjectIdentifier("1.2.840.113533.7.66.13");

    /**
     * id-DHBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 30}
     */
    ASN1ObjectIdentifier dhBasedMac = new ASN1ObjectIdentifier("1.2.840.113533.7.66.30");

    // Example InfoTypeAndValue contents include, but are not limited
    // to, the following (un-comment in this ASN.1 module and use as
    // appropriate for a given environment):
    //
    //   id-it-caProtEncCert    OBJECT IDENTIFIER ::= {id-it 1}
    //      CAProtEncCertValue      ::= CMPCertificate
    //   id-it-signKeyPairTypes OBJECT IDENTIFIER ::= {id-it 2}
    //      SignKeyPairTypesValue   ::= SEQUENCE OF AlgorithmIdentifier
    //   id-it-encKeyPairTypes  OBJECT IDENTIFIER ::= {id-it 3}
    //      EncKeyPairTypesValue    ::= SEQUENCE OF AlgorithmIdentifier
    //   id-it-preferredSymmAlg OBJECT IDENTIFIER ::= {id-it 4}
    //      PreferredSymmAlgValue   ::= AlgorithmIdentifier
    //   id-it-caKeyUpdateInfo  OBJECT IDENTIFIER ::= {id-it 5}
    //      CAKeyUpdateInfoValue    ::= CAKeyUpdAnnContent
    //   id-it-currentCRL       OBJECT IDENTIFIER ::= {id-it 6}
    //      CurrentCRLValue         ::= CertificateList
    //   id-it-unsupportedOIDs  OBJECT IDENTIFIER ::= {id-it 7}
    //      UnsupportedOIDsValue    ::= SEQUENCE OF OBJECT IDENTIFIER
    //   id-it-keyPairParamReq  OBJECT IDENTIFIER ::= {id-it 10}
    //      KeyPairParamReqValue    ::= OBJECT IDENTIFIER
    //   id-it-keyPairParamRep  OBJECT IDENTIFIER ::= {id-it 11}
    //      KeyPairParamRepValue    ::= AlgorithmIdentifer
    //   id-it-revPassphrase    OBJECT IDENTIFIER ::= {id-it 12}
    //      RevPassphraseValue      ::= EncryptedValue
    //   id-it-implicitConfirm  OBJECT IDENTIFIER ::= {id-it 13}
    //      ImplicitConfirmValue    ::= NULL
    //   id-it-confirmWaitTime  OBJECT IDENTIFIER ::= {id-it 14}
    //      ConfirmWaitTimeValue    ::= GeneralizedTime
    //   id-it-origPKIMessage   OBJECT IDENTIFIER ::= {id-it 15}
    //      OrigPKIMessageValue     ::= PKIMessages
    //   id-it-suppLangTags     OBJECT IDENTIFIER ::= {id-it 16}
    //      SuppLangTagsValue       ::= SEQUENCE OF UTF8String
    //   id-it-certProfile  OBJECT IDENTIFIER ::= {id-it 21}
    //      CertProfileValue ::= SEQUENCE SIZE (1..MAX) OF UTF8String
    // where
    //
    //   id-pkix OBJECT IDENTIFIER ::= {
    //      iso(1) identified-organization(3)
    //      dod(6) internet(1) security(5) mechanisms(5) pkix(7)}
    // and
    //   id-it   OBJECT IDENTIFIER ::= {id-pkix 4}

    /** RFC 4120: it-id: PKIX.4 = 1.3.6.1.5.5.7.4 */


    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.1
     */
    ASN1ObjectIdentifier it_caProtEncCert = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.1");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.2
     */
    ASN1ObjectIdentifier it_signKeyPairTypes = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.2");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.3
     */
    ASN1ObjectIdentifier it_encKeyPairTypes = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.3");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.4
     */
    ASN1ObjectIdentifier it_preferredSymAlg = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.4");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.5
     */
    ASN1ObjectIdentifier it_caKeyUpdateInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.5");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.6
     */
    ASN1ObjectIdentifier it_currentCRL = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.6");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.7
     */
    ASN1ObjectIdentifier it_unsupportedOIDs = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.7");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.10
     */
    ASN1ObjectIdentifier it_keyPairParamReq = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.10");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.11
     */
    ASN1ObjectIdentifier it_keyPairParamRep = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.11");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.12
     */
    ASN1ObjectIdentifier it_revPassphrase = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.12");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.13
     */
    ASN1ObjectIdentifier it_implicitConfirm = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.13");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.14
     */
    ASN1ObjectIdentifier it_confirmWaitTime = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.14");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.15
     */
    ASN1ObjectIdentifier it_origPKIMessage = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.15");
    /**
     * RFC 4120: 1.3.6.1.5.5.7.4.16
     */
    ASN1ObjectIdentifier it_suppLangTags = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.16");

    /**
     * Update 16, RFC 4210
     * {id-it 17}
     */
    ASN1ObjectIdentifier id_it_caCerts = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.17");


    /**
     * Update 16, RFC 4210
     * GenRep:    {id-it 18}, RootCaKeyUpdateContent
     */
    ASN1ObjectIdentifier id_it_rootCaKeyUpdate = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.18");


    /**
     * Update 16, RFC 4210
     * {id-it 19}
     */
    ASN1ObjectIdentifier id_it_certReqTemplate = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.19");


    /**
     * Update 16, RFC 4210
     * GenMsg:    {id-it 20}, RootCaCertValue
     */
    ASN1ObjectIdentifier id_it_rootCaCert = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.20");

    /**
     * Update-16 to RFC 4210
     * id-it-certProfile  OBJECT IDENTIFIER ::= {id-it 21}
     */
    ASN1ObjectIdentifier id_it_certProfile = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.21");

    ASN1ObjectIdentifier id_it_crlStatusList = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.22");

    ASN1ObjectIdentifier id_it_crls = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.23");

    // Not yet formally defined.

    // ASN1ObjectIdentifier id_it_crlStatusList = null;
    // ASN1ObjectIdentifier id_it_crls = null;


    // RFC 4211

    // id-pkix  OBJECT IDENTIFIER  ::= { iso(1) identified-organization(3)
    //     dod(6) internet(1) security(5) mechanisms(5) pkix(7) }
    //
    // arc for Internet X.509 PKI protocols and their components
    // id-pkip  OBJECT IDENTIFIER :: { id-pkix pkip(5) }
    //
    // arc for Registration Controls in CRMF
    // id-regCtrl  OBJECT IDENTIFIER ::= { id-pkip regCtrl(1) }
    //
    // arc for Registration Info in CRMF
    // id-regInfo       OBJECT IDENTIFIER ::= { id-pkip id-regInfo(2) }

    /**
     * RFC 4211: it-pkip: PKIX.5 = 1.3.6.1.5.5.7.5
     */
    ASN1ObjectIdentifier id_pkip = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5");

    /**
     * RFC 4211: it-regCtrl: 1.3.6.1.5.5.7.5.1
     */
    ASN1ObjectIdentifier id_regCtrl = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1");
    /**
     * RFC 4211: it-regInfo: 1.3.6.1.5.5.7.5.2
     */
    ASN1ObjectIdentifier id_regInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.2");


    /**
     * 1.3.6.1.5.5.7.5.1.1
     */
    ASN1ObjectIdentifier regCtrl_regToken = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.1");
    /**
     * 1.3.6.1.5.5.7.5.1.2
     */
    ASN1ObjectIdentifier regCtrl_authenticator = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.2");
    /**
     * 1.3.6.1.5.5.7.5.1.3
     */
    ASN1ObjectIdentifier regCtrl_pkiPublicationInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.3");
    /**
     * 1.3.6.1.5.5.7.5.1.4
     */
    ASN1ObjectIdentifier regCtrl_pkiArchiveOptions = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.4");
    /**
     * 1.3.6.1.5.5.7.5.1.5
     */
    ASN1ObjectIdentifier regCtrl_oldCertID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.5");
    /**
     * 1.3.6.1.5.5.7.5.1.6
     */
    ASN1ObjectIdentifier regCtrl_protocolEncrKey = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.6");

    /**
     * From RFC4210:
     * id-regCtrl-altCertTemplate OBJECT IDENTIFIER ::= {id-regCtrl 7}; 1.3.6.1.5.5.7.1.7
     */
    ASN1ObjectIdentifier regCtrl_altCertTemplate = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.7");

    /**
     * RFC 4211: it-regInfo-utf8Pairs: 1.3.6.1.5.5.7.5.2.1
     */
    ASN1ObjectIdentifier regInfo_utf8Pairs = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.2.1");
    /**
     * RFC 4211: it-regInfo-certReq: 1.3.6.1.5.5.7.5.2.1
     */
    ASN1ObjectIdentifier regInfo_certReq = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.2.2");

    /**
     * 1.2.840.113549.1.9.16.1.21
     * <p>
     * id-ct   OBJECT IDENTIFIER ::= { id-smime  1 }  -- content types
     * <p>
     * id-ct-encKeyWithID OBJECT IDENTIFIER ::= {id-ct 21}
     */
    ASN1ObjectIdentifier ct_encKeyWithID = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.21");


    /**
     * id-regCtrl-algId OBJECT IDENTIFIER ::= { iso(1)
     * identified-organization(3) dod(6) internet(1) security(5)
     * mechanisms(5) pkix(7) pkip(5) regCtrl(1) 11 }
     */
    ASN1ObjectIdentifier id_regCtrl_algId = id_pkip.branch("1.11");

    /**
     * id-regCtrl-rsaKeyLen OBJECT IDENTIFIER ::= { iso(1)
     * identified-organization(3) dod(6) internet(1) security(5)
     * mechanisms(5) pkix(7) pkip(5) regCtrl(1) 12 }
     */
    ASN1ObjectIdentifier id_regCtrl_rsaKeyLen = id_pkip.branch("1.12");


}
