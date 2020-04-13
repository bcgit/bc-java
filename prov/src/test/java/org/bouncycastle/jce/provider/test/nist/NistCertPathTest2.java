package org.bouncycastle.jce.provider.test.nist;

import java.security.Security;

import junit.framework.TestCase;

// tests based on https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf
//
public class NistCertPathTest2
    extends TestCase
{

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * 4.1.1 Valid Signatures Test1
     * <p>
     * The purpose of this test is to verify an application's ability to name chain, signature chain, and
     * check validity dates, on certificates in a certification path. It also tests processing of the basic
     * constraints and key usage extensions in intermediate certificates.
     */
    public void test4_1_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Certificate Path Test1 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();
    }

    /**
     * 4.1.2 Invalid CA Signature Test2
     * <p>
     * The purpose of this test is to verify an application's ability to recognize an invalid signature on an
     * intermediate certificate in a certification path.
     */
    public void test4_1_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid CA Signature Test2 EE")
            .withCrls("Bad Signed CA CRL")
            .withCACert("Bad Signed CA Cert")
            .doExceptionTest(1, "TrustAnchor found but certificate validation failed.");
    }

    /**
     * 4.1.3 Invalid EE Signature Test3
     * <p>
     * The purpose of this test is to verify an application's ability to recognize an invalid signature on an
     * end entity certificate in a certification path.
     */
    public void test4_1_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid EE Signature Test3 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(0, "Could not validate certificate signature.");
    }

    /**
     * 4.1.4 Valid DSA Signatures Test4
     * <p>
     * The purpose of this test is to verify an application's ability to validate certificate in which DSA
     * signatures are used. The intermediate CA and the end entity have DSA key pairs.
     */
    public void test4_1_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DSA Signatures Test4 EE")
            .withCrls("DSA CA CRL")
            .withCACert("DSA CA Cert")
            .doTest();
    }

    /**
     * 4.1.5 Valid DSA Parameter Inheritance Test5
     * <p>
     * The purpose of this test is to verify an application's ability to validate DSA signatures when the
     * DSA parameters are not included in a certificate and need to be inherited from a previous
     * certificate in the path. The intermediate CAs and the end entity have DSA key pairs.
     */
    public void test4_1_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DSA Parameter Inheritance Test5 EE")
            .withCrls("DSA Parameters Inherited CA CRL")
            .withCACert("DSA Parameters Inherited CA Cert")
            .withCrls("DSA CA CRL")
            .withCACert("DSA CA Cert")
            .doTest();
    }

    /**
     * 4.1.6 Invalid DSA Signature Test6
     * <p>
     * The purpose of this test is to verify an application's ability to determine when a DSA signature is
     * invalid. The intermediate CA and the end entity have DSA key pairs.
     */
    public void test4_1_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DSA Signature Test6 EE")
            .withCrls("DSA CA CRL")
            .withCACert("DSA CA Cert")
            .doExceptionTest(0, "Could not validate certificate signature.");
    }

    /**
     * 4.2.1 Invalid CA notBefore Date Test1
     * <p>
     * In this test, the intermediate certificate's notBefore date is after the current date.
     */
    public void test4_2_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid CA notBefore Date Test1 EE")
            .withCrls("Bad notBefore Date CA CRL")
            .withCACert("Bad notBefore Date CA Cert")
            .doExceptionTest(1, "Could not validate certificate: certificate not valid till 20470101120100GMT+00:00");
    }

    /**
     * 4.2.2 Invalid EE notBefore Date Test2
     * <p>
     * In this test, the end entity certificate's notBefore date is after the current date.
     */
    public void test4_2_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid EE notBefore Date Test2 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(0, "Could not validate certificate: certificate not valid till 20470101120100GMT+00:00");

    }

    /**
     * 4.2.3 Valid pre2000 UTC notBefore Date Test3
     * <p>
     * In this test, the end entity certificate's notBefore date is set to 1950 and is encoded in UTCTime.
     */
    public void test4_2_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid pre2000 UTC notBefore Date Test3 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();
    }

    /**
     * 4.2.4 Valid GeneralizedTime notBefore Date Test4
     * <p>
     * In this test, the end entity certificate's notBefore date is specified in GeneralizedTime.
     */
    public void test4_2_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid GeneralizedTime notBefore Date Test4 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();
    }

    /**
     * 4.2.5 Invalid CA notAfter Date Test5
     * <p>
     * In this test, the intermediate certificate's notAfter date is before the current date.
     * 9
     */
    public void test4_2_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid CA notAfter Date Test5 EE")
            .withCrls("Bad notAfter Date CA CRL")
            .withCACert("Bad notAfter Date CA Cert")
            .doExceptionTest(1, "Could not validate certificate: certificate expired on 20020101120100GMT+00:00");
    }

    /**
     * 4.2.6 Invalid EE notAfter Date Test6
     * <p>
     * In this test, the end entity certificate's notAfter date is before the current date.
     */
    public void test4_2_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid EE notAfter Date Test6 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(0, "Could not validate certificate: certificate expired on 20020101120100GMT+00:00");
    }

    /**
     * 4.2.7 Invalid pre2000 UTC EE notAfter Date Test7
     * <p>
     * In this test, the end entity certificate's notAfter date is 1999 and is encoded in UTCTime.
     */
    public void test4_2_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid pre2000 UTC EE notAfter Date Test7 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(0, "Could not validate certificate: certificate expired on 19990101120100GMT+00:00");
    }

    /**
     * 4.2.8 Valid GeneralizedTime notAfter Date Test8
     * <p>
     * In this test, the end entity certificate's notAfter date is 2050 and is encoded in GeneralizedTime.
     */
    public void test4_2_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid GeneralizedTime notAfter Date Test8 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();
    }

    /**
     * 4.3.1 Invalid Name Chaining EE Test1
     * <p>
     * In this test, the common name (cn=) portion of the issuer's name in the end entity certificate does
     * not match the common name portion of the subject's name in the preceding intermediate certificate.
     */
    public void test4_3_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Name Chaining Test1 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"cn=Good CA Root,o=Test Certificates,c=US\"");
    }

    /**
     * 4.3.2 Invalid Name Chaining Order Test2
     * <p>
     * In this test, the issuer's name in the end entity certificate and the subject's name in the preceding
     * intermediate certificate contain the same relative distinguished names (RDNs), but their ordering is
     * different.
     */
    public void test4_3_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Name Chaining Order Test2 EE")
            .withCrls("Name Order CA CRL")
            .withCACert("Name Ordering CA Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"cn=Name Ordering CA,ou=Organizational Unit Name 1,ou=Organizational Unit Name 2,o=Test Certificates,c=US\"");
    }

    /**
     * 4.3.3 Valid Name Chaining Whitespace Test3
     * <p>
     * In this test, the issuer's name in the end entity certificate and the subject's name in the preceding
     * intermediate certificate differ in internal whitespace, but match once the internal whitespace is
     * compressed.
     */
    public void test4_3_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Name Chaining Whitespace Test3 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();
    }

    /**
     * 4.3.4 Valid Name Chaining Whitespace Test4
     * <p>
     * In this test, the issuer's name in the end entity certificate and the subject's name in the preceding
     * intermediate certificate differ in leading and trailing whitespace, but match once all leading and
     * trailing whitespace is removed.
     */
    public void test4_3_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Name Chaining Whitespace Test4 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();
    }

    /**
     * 4.3.5 Valid Name Chaining Capitalization Test5
     * <p>
     * In this test, the issuer's name in the end entity certificate and the subject's name in the preceding
     * intermediate certificate differ in capitalization, but match when a case insensitive match is
     * performed.
     */
    public void test4_3_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Name Chaining Capitalization Test5 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();
    }

    /**
     * 4.3.6 Valid Name Chaining UIDs Test6
     * <p>
     * In this test, the intermediate certificate includes a subjectUniqueID and the end entity certificate
     * includes a matching issuerUniqueID.
     * 12
     */
    public void test4_3_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Name UIDs Test6 EE")
            .withCrls("UID CA CRL")
            .withCACert("UID CA Cert")
            .doTest();
    }

    /**
     * 4.3.7 Valid RFC3280 Mandatory Attribute Types Test7
     * <p>
     * In this test, this intermediate certificate includes a subject name that includes the attribute types
     * distinguished name qualifier, state or province name, serial number, domain component,
     * organization, and country.
     */
    public void test4_3_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid RFC3280 Mandatory Attribute Types Test7 EE")
            .withCrls("RFC3280 Mandatory AttributeTypes CA CRL")
            .withCACert("RFC3280 Mandatory Attribute Types CA Cert")
            .doTest();
    }

    /**
     * 4.3.8 Valid RFC3280 Optional Attribute Types Test8
     * <p>
     * In this test, this intermediate certificate includes a subject name that includes the attribute types
     * locality, title, surname, given name, initials, pseudonym, generation qualifier, organization, and
     * country.
     */
    public void test4_3_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid RFC3280 Optional Attribute Types Test8 EE")
            .withCrls("RFC3280 Optional AttributeTypes CA CRL")
            .withCACert("RFC3280 Optional Attribute Types CA Cert")
            .doTest();
    }

    /**
     * 4.3.9 Valid UTF8String Encoded Names Test9
     * <p>
     * In this test, the attribute values for the common name and organization attribute types in the
     * subject fields of the intermediate and end certificates and the issuer fields of the end certificate
     * and the intermediate certificate's CRL are encoded in UTF8String.
     * 13
     */
    public void test4_3_9()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid UTF8String Encoded Names Test9 EE")
            .withCrls("UTF8String Encoded Names CA CRL")
            .withCACert("UTF8String Encoded Names CA Cert")
            .doTest();
    }

    /**
     * 4.3.10 Valid Rollover from PrintableString to UTF8String Test10
     * <p>
     * In this test, the attribute values for the common name and organization attribute types in the issuer
     * and subject fields of the end certificate and the issuer field of the intermediate certificate's CRL
     * are encoded in UTF8String. However, these attribute types are encoded in PrintableString in the
     * subject field of the intermediate certificate.
     */
    public void test4_3_10()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Rollover from PrintableString to UTF8String Test10 EE")
            .withCrls("Rollover fromPrintableString to UTF8String CA CRL")
            .withCACert("Rollover from PrintableString to UTF8String CA Cert")
            .doTest();
    }

    /**
     * 4.3.11 Valid UTF8String Case Insensitive Match Test11
     * <p>
     * In this test, the attribute values for the common name and organization attribute types in the
     * subject fields of the intermediate and end certificates and the issuer fields of the end certificate
     * and the intermediate certificate's CRL are encoded in UTF8String. The subject of the
     * intermediate certificate and the issuer of the end certificate differ in capitalization and whitespace,
     * but match when a case insensitive match is performed.
     */
    public void test4_3_11()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid UTF8String Case Insensitive Match Test11 EE")
            .withCrls("UTF8String Case InsensitiveMatch CA CRL")
            .withCACert("UTF8String Case Insensitive Match CA Cert")
            .doTest();
    }

    /**
     * 4.4.1 Missing CRL Test1
     * <p>
     * In this test, there is no revocation information available from the intermediate CA, making it
     * impossible to determine the status of the end certificate.
     */
    public void test4_4_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Missing CRL Test1 EE")
            .withCACert("No CRL CA Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"cn=No CRL CA,o=Test Certificates,c=US\"");
    }

    /**
     * 4.4.2 Invalid Revoked CA Test2
     * <p>
     * In this test, the CRL issued by the first intermediate CA indicates that the second intermediate
     * certificate in the path has been revoked.
     */
    public void test4_4_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Revoked CA Test2 EE")
            .withCrls("Revoked subCA CRL")
            .withCACert("Revoked subCA Cert")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(1, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.4.3 Invalid Revoked EE Test3
     * <p>
     * In this test, the CRL issued by the intermediate CA indicates that the end entity certificate has been
     * revoked.
     */
    public void test4_4_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Revoked EE Test3 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.4.4 Invalid Bad CRL Signature Test4
     * <p>
     * In this test, the signature on the CRL issued by the intermediate CA is invalid.
     */
    public void test4_4_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Bad CRL Signature Test4 EE")
            .withCrls("Bad CRL Signature CA CRL")
            .withCACert("Bad CRL Signature CA Cert")
            .doExceptionTest(0, "Cannot verify CRL.");
    }

    /**
     * 4.4.5 Invalid Bad CRL Issuer Name Test5
     * <p>
     * In this test, the issuer name in the CRL signed by the intermediate CA does not match the issuer
     * name in the end entity's certificate.
     */
    public void test4_4_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Bad CRL Issuer Name Test5 EE")
            .withCrls("Bad CRL Issuer Name CA CRL")
            .withCACert("Bad CRL Issuer Name CA Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"cn=Bad CRL Issuer Name CA,o=Test Certificates,c=US\"");
    }

    /**
     * 4.4.6 Invalid Wrong CRL Test6
     * <p>
     * In this test, the wrong CRL is in the intermediate certificate's directory entry. There is no CRL
     * available from the intermediate CA making it impossible to determine the status of the end entity's
     * certificate.
     */
    public void test4_4_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Wrong CRL Test6 EE")
            .withCrls("Wrong CRL CA CRL")
            .withCACert("Wrong CRL CA Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"cn=Wrong CRL CA,o=Test Certificates,c=US\"");
    }

    /**
     * 4.4.7 Valid Two CRLs Test7
     * <p>
     * In this test, there are two CRLs in the intermediate CAs directory entry, one that is correct and one
     * that contains the wrong issuer name. The correct CRL does not list any certificates as revoked.
     * The incorrect CRL includes the serial number of the end entity's certificate on its list of revoked
     * certificates.
     */
    public void test4_4_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Two CRLs Test7 EE")
            .withCrls("Two CRLs CA Bad CRL")
            .withCrls("Two CRLs CA Good CRL")
            .withCACert("Two CRLs CA Cert")
            .doTest();
    }

    /**
     * 4.4.8 Invalid Unknown CRL Entry Extension Test8
     * <p>
     * In this test, the end entity's certificate has been revoked. In the intermediate CA's CRL, there is a
     * made up critical crlEntryExtension associated with the end entity certificate's serial number.
     * [X.509 7.3] When an implementation processing a CRL encounters the serial number of the
     * certificate of interest in a CRL entry, but does not recognize a critical extension in the
     * crlEntryExtensions field from that CRL entry, that CRL cannot be used to determine the status of
     * the certificate.
     */
    public void test4_4_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Unknown CRL Entry Extension Test8 EE")
            .withCrls("Unknown CRL Entry Extension CACRL")
            .withCACert("Unknown CRL Entry Extension CA Cert")
            .doExceptionTest(0, "CRL entry has unsupported critical extensions.");
    }

    /**
     * 4.4.9 Invalid Unknown CRL Extension Test9
     * <p>
     * In this test, the end entity's certificate has been revoked. In the intermediate CA's CRL, there is a
     * made up critical extension in the crlExtensions field.
     * [X.509 7.3] When an implementation does not recognize a critical extension in the crlExtensions
     * field, that CRL cannot be used to determine the status of the certificate, regardless of whether the
     * serial number of the certificate of interest appears in that CRL or not.
     */
    public void test4_4_9()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Unknown CRL Extension Test9 EE")
            .withCrls("Unknown CRL Extension CA CRL")
            .withCACert("Unknown CRL Extension CA Cert")
            .doExceptionTest(0, "CRL contains unsupported critical extensions.");
    }

    /**
     * 4.4.10 Invalid Unknown CRL Extension Test10
     * <p>
     * In this test the intermediate CA's CRL contains a made up critical extension in the crlExtensions
     * field. The end entity certificate's serial number is not listed on the CRL, however, due to the
     * presence of an unknown critical CRL extension, the relying party can not be sure that the list of
     * serial numbers on the revokedCertificates list includes all certificates that have been revoked by
     * the intermediate CA. As a result, the relying party can not verify that the end entity's certificate
     * has not been revoked.
     * 18
     */
    public void test4_4_10()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Unknown CRL Extension Test10 EE")
            .withCrls("Unknown CRL Extension CA CRL")
            .withCACert("Unknown CRL Extension CA Cert")
            .doExceptionTest(0, "CRL contains unsupported critical extensions.");
    }

    /**
     * 4.4.11 Invalid Old CRL nextUpdate Test11
     * <p>
     * In this test the intermediate CA's CRL has a nextUpdate time that is far in the past (January
     * 2010), indicating that the CA has already issued updated revocation information. Since the
     * information in the CRL is out-of-date and a more up-to-date CRL (that should have already been
     * issued) can not be obtained, the certification path should be treated as if the status of the end entity
     * certificate can not be determined.3
     */
    public void test4_4_11()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Old CRL nextUpdate Test11 EE")
            .withCrls("Old CRL nextUpdate CA CRL")
            .withCACert("Old CRL nextUpdate CA Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"cn=Old CRL nextUpdate CA,o=Test Certificates,c=US\"");
    }

    /**
     * 4.4.12 Invalid pre2000 CRL nextUpdate Test12
     * <p>
     * In this test the intermediate CA's CRL has a nextUpdate time that is in 1999 indicating that the
     * CA has already issued updated revocation information. Since the information in the CRL is outof-date and a more up-to-date CRL (that should have already been issued) can not be obtained, the
     * certification path should be treated as if the status of the end entity certificate can not be
     * determined.
     */
    public void test4_4_12()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid pre2000 CRL nextUpdate Test12 EE")
            .withCrls("pre2000 CRL nextUpdate CA CRL")
            .withCACert("pre2000 CRL nextUpdate CA Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"cn=pre2000 CRL nextUpdate CA,o=Test Certificates,c=US\"");
    }

    /**
     * 4.4.13 Valid GeneralizedTime CRL nextUpdate Test13
     * <p>
     * In this test the intermediate CA's CRL has a nextUpdate time that is in 2050. Since the
     * nextUpdate time is in the future, this CRL may contain the most up-to-date certificate status
     * information that is available from the intermediate CA and so the relying party may use this CRL
     * to determine the status of the end entity certificate.
     */
    public void test4_4_13()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid GeneralizedTime CRL nextUpdate Test13 EE")
            .withCrls("GeneralizedTime CRL nextUpdateCA CRL")
            .withCACert("GeneralizedTime CRL nextUpdate CA Cert")
            .doTest();
    }

    /**
     * 4.4.14 Valid Negative Serial Number Test14
     * <p>
     * RFC 3280 mandates that certificate serial numbers be positive integers, but states that relying
     * parties should be prepared to gracefully handle certificates with serial numbers that are negative,
     * or zero. In this test, the end entity's certificate has a serial number of 255 (DER encoded as "00
     * FF") and the corresponding CRL lists the certificate with serial number -1 (DER encoded as "FF")
     * as revoked.
     */
    public void test4_4_14()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Negative Serial Number Test14 EE")
            .withCrls("Negative Serial Number CA CRL")
            .withCACert("Negative Serial Number CA Cert")
            .doTest();
    }

    /**
     * 4.4.15 Invalid Negative Serial Number Test15
     * <p>
     * RFC 3280 mandates that certificate serial numbers be positive integers, but states that relying
     * parties should be prepared to gracefully handle certificates with serial numbers that are negative,
     * or zero. In this test, the end entity's certificate has a serial number of -1 (DER encoded as "FF")
     * and the corresponding CRL lists this certificate as revoked.
     */
    public void test4_4_15()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Negative Serial Number Test15 EE")
            .withCrls("Negative Serial Number CA CRL")
            .withCACert("Negative Serial Number CA Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.4.16 Valid Long Serial Number Test16
     * <p>
     * RFC 3280 mandates that certificate users be able to handle serial number values up to 20 octets
     * long. In this test, the end entity's certificate has a 20 octet serial number that is not listed on the
     * corresponding CRL, but the serial number matches the serial number listed on the CRL in all but
     * the least significant octet.
     */
    public void test4_4_16()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Long Serial Number Test16 EE")
            .withCrls("Long Serial Number CA CRL")
            .withCACert("Long Serial Number CA Cert")
            .doTest();
    }

    /**
     * 4.4.17 Valid Long Serial Number Test17
     * <p>
     * RFC 3280 mandates that certificate users be able to handle serial number values up to 20 octets
     * long. In this test, the end entity's certificate has a 20 octet serial number that is not listed on the
     * corresponding CRL, but the serial number matches the serial number listed on the CRL in all but
     * the most significant octet.
     */
    public void test4_4_17()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Long Serial Number Test17 EE")
            .withCrls("Long Serial Number CA CRL")
            .withCACert("Long Serial Number CA Cert")
            .doTest();
    }

    /**
     * 4.4.18 Invalid Long Serial Number Test18
     * <p>
     * RFC 3280 mandates that certificate users be able to handle serial number values up to 20 octets
     * long. In this test, the end entity's certificate has a 20 octet serial number and the certificate's serial
     * number is listed on the corresponding CRL.
     */
    public void test4_4_18()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Long Serial Number Test18 EE")
            .withCrls("Long Serial Number CA CRL")
            .withCACert("Long Serial Number CA Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.4.19 Valid Separate Certificate and CRL Keys Test19
     * <p>
     * In this test, the intermediate CA uses different keys to sign certificates and CRLs. The Trust
     * Anchor CA has issued two certificates to the intermediate CA, one for each key. The end entity's
     * certificate was signed using the intermediate CA's certificate signing key.
     */
    // CHECK -- "Trust anchor for certification path not found."
    public void xtest4_4_19()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Separate Certificate and CRL Keys Test19 EE")
            .withCrls("Separate Certificate and CRLKeys CRL")
            .withCACert("SeparateCertificate and CRL Keys CRL Signing Cert")
            .withCACert("Separate Certificate and CRL Keys Certificate Signing CA Cert")
            .doTest();
    }

    /**
     * 4.4.20 Invalid Separate Certificate and CRL Keys Test20
     * <p>
     * In this test, the intermediate CA uses different keys to sign certificates and CRLs. The Trust
     * Anchor CA has issued two certificates to the intermediate CA, one for each key. The end entity's
     * certificate was signed using the intermediate CA's certificate signing key. The CRL issued by the
     * intermediate CA lists the end entity's certificate as revoked.
     */
    // CHECK getting "Trust anchor for certification path not found."
    public void xtest4_4_20()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Separate Certificate and CRL Keys Test20 EE")
            .withCrls("Separate Certificate and CRLKeys CRL")
            .withCACert("SeparateCertificate and CRL Keys CRL Signing Cert")
            .withCACert("Separate Certificate and CRL Keys Certificate Signing CA Cert")
            .doExceptionTest(1, "--");
    }

    /**
     * 4.4.21 Invalid Separate Certificate and CRL Keys Test21
     * <p>
     * In this test, the intermediate CA uses different keys to sign certificates and CRLs. The Trust
     * Anchor CA has issued two certificates to the intermediate CA, one for each key. The certificate
     * issued to the intermediate CA's CRL verification key has been revoked. The end entity's certificate
     * was signed using the intermediate CA's certificate signing key.
     */
    // CHECK -- Got: Trust anchor for certification path not found.
    public void xtest4_4_21()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Separate Certificate and CRL Keys Test21 EE")
            .withCrls("Separate Certificate and CRLKeys CA2 CRL")
            .withCACert("SeparateCertificate and CRL Keys CA2 CRL Signing Cert")
            .withCACert("Separate Certificate and CRL Keys CA2 Certificate Signing CA Cert")
            .doExceptionTest(1, "--");
    }

    /**
     * 4.5.1 Valid Basic Self-Issued Old With New Test1
     * <p>
     * In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
     * intermediate CA's new public key. The end entity's certificate was signed using the intermediate
     * CA's old private key, requiring the relying party to use the CA's old-signed-with-new self-issued
     * certificate in order to validate the end entity's certificate. The intermediate CA issues one CRL,
     * signed with its new private key, that covers all of the unexpired certificates that it has issued.
     */
    public void test4_5_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Basic SelfIssued Old With New Test1 EE")
            .withCACert("Basic SelfIssued New Key OldWithNew CA Cert")
            .withCrls("Basic SelfIssued New Key CA CRL")
            .withCACert("Basic SelfIssued New Key CA Cert")
            .doTest();
    }

    /**
     * 4.5.2 Invalid Basic Self-Issued Old With New Test2
     * <p>
     * In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
     * intermediate CA's new public key. The end entity's certificate was signed using the intermediate
     * CA's old private key, requiring the relying party to use the CA's old-signed-with-new self-issued
     * certificate in order to validate the end entity's certificate. The intermediate CA issues one CRL,
     * signed with its new private key, that covers all of the unexpired certificates that it has issued. This
     * CRL indicates that the end entity's certificate has been revoked.
     */
    public void test4_5_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Basic SelfIssued Old With New Test2 EE")
            .withCACert("Basic SelfIssued New Key OldWithNew CA Cert")
            .withCrls("Basic SelfIssued New Key CA CRL")
            .withCACert("Basic SelfIssued New Key CA Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.5.3 Valid Basic Self-Issued New With Old Test3
     * <p>
     * In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
     * intermediate CA's old public key. The end entity's certificate and a CRL covering all certificates
     * issued by the intermediate CA was signed using the intermediate CA's new private key, requiring
     * the relying party to use the CA's new-signed-with-old self-issued certificate in order to validate
     * both the end entity's certificate and the intermediate CA's CRL. There is a second CRL, signed
     * using the intermediate CA's old private key that only covers the new-signed-with-old self-issued
     * certificate.
     */
    public void test4_5_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Basic SelfIssued New With Old Test3 EE")
            .withCrls("Basic SelfIssued Old Key CACRL")
            .withCACert("Basic SelfIssued Old Key NewWithOld CA Cert")
            .withCrls("Basic SelfIssued Old Key SelfIssued CertCRL")
            .withCACert("Basic SelfIssued Old Key CA Cert")
            .doTest();
    }

    /**
     * 4.5.4 Valid Basic Self-Issued New With Old Test4
     * <p>
     * In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
     * intermediate CA's old public key. The end entity's certificate was signed using the intermediate
     * CA's old private key, so there is no need to use a self-issued certificate to create a certification path
     * from the Trust Anchor to the end entity. However, the CRL covering all certificates issued by the
     * intermediate CA was signed using the intermediate CA's new private key, requiring the relying
     * party to use the CA's new-signed-with-old self-issued certificate in order to validate the
     * intermediate CA's CRL. This CRL must be validated in order to determine the status of the end
     * entity's certificate. There is a second CRL, signed using the intermediate CA's old private key that
     * only covers the new-signed-with-old self-issued certificate.
     */
    // CHECK I think it is not using the new-signed-with-old
    public void xtest4_5_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Basic SelfIssued New With Old Test4 EE")
            .withCrls("Basic SelfIssued Old Key CACRL")
            .withCACert("Basic SelfIssued Old Key NewWithOld CA Cert")
            .withCrls("Basic SelfIssued Old Key SelfIssued CertCRL")
            .withCACert("Basic SelfIssued Old Key CA Cert")
            .doTest();
    }

    /**
     * 4.5.5 Invalid Basic Self-Issued New With Old Test5
     * <p>
     * In this test, the Trust Anchor CA has issued a certificate to the intermediate CA that contains the
     * intermediate CA's old public key. The end entity's certificate was signed using the intermediate
     * CA's old private key, so there is no need to use a self-issued certificate to create a certification path
     * from the Trust Anchor to the end entity. However, the CRL covering all certificates issued by the
     * intermediate CA was signed using the intermediate CA's new private key, requiring the relying
     * party to use the CA's new-signed-with-old self-issued certificate in order to validate the
     * intermediate CA's CRL. This CRL must be validated in order to determine the status of the end
     * entity's certificate. There is a second CRL, signed using the intermediate CA's old private key that
     * only covers the new-signed-with-old self-issued certificate. The end entity's certificate has been
     * revoked.
     */
    // CHECK I think it is not using the new-signed-with-old
    public void xtest4_5_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Basic SelfIssued New With Old Test5 EE")
            .withCrls("Basic SelfIssued Old Key CACRL")
            .withCACert("Basic SelfIssued Old Key NewWithOld CA Cert")
            .withCrls("Basic SelfIssued Old Key SelfIssued CertCRL")
            .withCACert("Basic SelfIssued Old Key CA Cert")
            .doExceptionTest(0, "--");
    }

    /**
     * 4.5.6 Valid Basic Self-Issued CRL Signing Key Test6
     * <p>
     * In this test, the intermediate CA maintains two key pairs, one for signing certificates and the other
     * for signing CRLs. The Trust Anchor CA has issued a certificate to the intermediate CA that
     * contains the intermediate CA's certificate verification public key, and the intermediate CA has
     * issued a self-issued certificate that contains its CRL verification key. The intermediate CA's
     * certificate signing private key has been used to sign a CRL that only covers the self-issued
     * certificate.
     */
    // CHECK we may be too strict here, "Intermediate certificate lacks BasicConstraints"
    public void xtest4_5_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Basic SelfIssued CRL Signing Key Test6 EE")
            .withCrls("Basic SelfIssued CRL SigningKey CA CRL")
            .withCACert("Basic SelfIssued CRL Signing Key CRL Cert")
            .withCrls("Basic SelfIssued CRL SigningKey CRL Cert CRL")
            .withCACert("Basic SelfIssued CRL Signing Key CA Cert")
            .doTest();
    }

    /**
     * 4.5.7 Invalid Basic Self-Issued CRL Signing Key Test7
     * <p>
     * In this test, the intermediate CA maintains two key pairs, one for signing certificates and the other
     * for signing CRLs. The Trust Anchor CA has issued a certificate to the intermediate CA that
     * contains the intermediate CA's certificate verification public key, and the intermediate CA has
     * issued a self-issued certificate that contains its CRL verification key. The intermediate CA's
     * certificate signing private key has been used to sign a CRL that only covers the self-issued
     * certificate. The end entity's certificate has been revoked.
     */
    // CHECK we may be too strict here, "Intermediate certificate lacks BasicConstraints"
    public void xtest4_5_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Basic SelfIssued CRL Signing Key Test7 EE")
            .withCrls("Basic SelfIssued CRL SigningKey CA CRL")
            .withCACert("Basic SelfIssued CRL Signing Key CRL Cert")
            .withCrls("Basic SelfIssued CRL SigningKey CRL Cert CRL")
            .withCACert("Basic SelfIssued CRL Signing Key CA Cert")
            .doExceptionTest(1, "--");
    }

    /**
     * 4.5.8 Invalid Basic Self-Issued CRL Signing Key Test8
     * <p>
     * In this test, the intermediate CA maintains two key pairs, one for signing certificates and the other
     * for signing CRLs. The Trust Anchor CA has issued a certificate to the intermediate CA that
     * contains the intermediate CA's certificate verification public key, and the intermediate CA has
     * issued a self-issued certificate that contains its CRL verification key. The intermediate CA's
     * certificate signing private key has been used to sign a CRL that only covers the self-issued
     * certificate. The end entity's certificate was signed using the CRL signing key.
     */
    public void test4_5_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Basic SelfIssued CRL Signing Key Test8 EE")
            .withCrls("Basic SelfIssued CRL SigningKey CA CRL")
            .withCACert("Basic SelfIssued CRL Signing Key CRL Cert")
            .withCrls("Basic SelfIssued CRL SigningKey CRL Cert CRL")
            .withCACert("Basic SelfIssued CRL Signing Key CA Cert")
            .doExceptionTest(1, "Intermediate certificate lacks BasicConstraints");
    }

    /**
     * 4.6.1 Invalid Missing basicConstraints Test1
     * <p>
     * In this test, the intermediate certificate does not have a basicConstraints extension.
     */
    public void test4_6_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Missing basicConstraints Test1 EE")
            .withCrls("Missing basicConstraints CA CRL")
            .withCACert("Missing basicConstraints CA Cert")
            .doExceptionTest(1, "Intermediate certificate lacks BasicConstraints");
    }

    /**
     * 4.6.2 Invalid cA False Test2
     * <p>
     * In this test, the basicConstraints extension is present in the intermediate certificate and is marked
     * critical, but the cA component is false, indicating that the subject public key may not be used to
     * verify signatures on certificates.
     */
    public void test4_6_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid cA False Test2 EE")
            .withCrls("basicConstraints Critical cA FalseCA CRL")
            .withCACert("basicConstraints Critical cA False CA Cert")
            .doExceptionTest(1, "Not a CA certificate");
    }

    /**
     * 4.6.3 Invalid cA False Test3
     * <p>
     * In this test, the basicConstraints extension is present in the intermediate certificate and is marked
     * not critical, but the cA component is false, indicating that the subject public key may not be used to
     * verify signatures on certificates. As specified in section 8.4.2.1 of X.509, the application must
     * reject the path either because the application does not recognize the basicConstraints extension or
     * because cA is set to false.
     */
    public void test4_6_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid cA False Test3 EE")
            .withCrls("basicConstraints Not CriticalcA False CA CRL")
            .withCACert("basicConstraints Not Critical cA False CA Cert")
            .doExceptionTest(1, "Not a CA certificate");
    }

    /**
     * 4.6.4 Valid basicConstraints Not Critical Test4
     * <p>
     * In this test, the basicConstraints extension is present in the intermediate certificate and the cA
     * component is true, but the extension is marked not critical.
     */
    public void test4_6_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid basicConstraints Not Critical Test4 EE")
            .withCrls("basicConstraints Not Critical CA CRL")
            .withCACert("basicConstraints Not Critical CA Cert")
            .doTest();
    }

    /**
     * 4.6.5 Invalid pathLenConstraint Test5
     * <p>
     * In this test, the first certificate in the path includes a basicConstraints extension with a
     * pathLenConstraint of 0 (allowing 0 additional intermediate certificates in the path). This is
     * followed by a second intermediate certificate and a end entity certificate.
     */
    public void test4_6_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid pathLenConstraint Test5 EE")
            .withCrls("pathLenConstraint0 subCA CRL")
            .withCACert("pathLenConstraint0 subCA Cert")
            .withCrls("pathLenConstraint0 CA CRL")
            .withCACert("pathLenConstraint0 CA Cert")
            .doExceptionTest(1, "Max path length not greater than zero");
    }

    /**
     * 4.6.6 Invalid pathLenConstraint Test6
     * <p>
     * In this test, the first certificate in the path includes a basicConstraints extension with a
     * pathLenConstraint of 0 (allowing 0 additional intermediate certificates in the path). This is
     * followed by two more CA certificates, the second of which is the end certificate in the path.
     */
    public void test4_6_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid pathLenConstraint Test6 EE")
            .withCrls("pathLenConstraint0 subCA CRL")
            .withCACert("pathLenConstraint0 subCA Cert")
            .withCrls("pathLenConstraint0 CA CRL")
            .withCACert("pathLenConstraint0 CA Cert")
            .doExceptionTest(1, "Max path length not greater than zero");
    }

    /**
     * 4.6.7 Valid pathLenConstraint Test7
     * <p>
     * In this test, the first certificate in the path includes a basicConstraints extension with a
     * pathLenConstraint of 0 (allowing 0 additional intermediate certificates in the path). This is
     * followed by the end entity certificate.
     */
    public void test4_6_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid pathLenConstraint Test7 EE")
            .withCrls("pathLenConstraint0 CA CRL")
            .withCACert("pathLenConstraint0 CA Cert")
            .doTest();
    }

    /**
     * 4.6.8 Valid pathLenConstraint Test8
     * <p>
     * In this test, the first certificate in the path includes a basicConstraints extension with a
     * pathLenConstraint of 0 (allowing 0 additional intermediate certificates in the path). This is
     * followed by the end entity certificate, which is a CA certificate.
     */
    public void test4_6_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid pathLenConstraint Test8 EE")
            .withCrls("pathLenConstraint0 CA CRL")
            .withCACert("pathLenConstraint0 CA Cert")
            .doTest();
    }

    /**
     * 4.6.9 Invalid pathLenConstraint Test9
     * <p>
     * This test consists of a certification path of length 4. The first certificate in the path includes a
     * pathLenConstraint of 6, the second a pathLenConstraint of 0, and the third a
     * pathLenConstraint of 0. The fourth certificate is an end entity certificate.
     */
    public void test4_6_9()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid pathLenConstraint Test9 EE")
            .withCrls("pathLenConstraint6 subsubCA00 CRL")
            .withCACert("pathLenConstraint6 subsubCA00 Cert")
            .withCrls("pathLenConstraint6 subCA0 CRL")
            .withCACert("pathLenConstraint6 subCA0 Cert")
            .withCrls("pathLenConstraint6 CA CRL")
            .withCACert("pathLenConstraint6 CA Cert")
            .doExceptionTest(1, "Max path length not greater than zero");
    }

    /**
     * 4.6.10 Invalid pathLenConstraint Test10
     * <p>
     * This test consists of a certification path of length 4. The first certificate in the path includes a
     * pathLenConstraint of 6, the second a pathLenConstraint of 0, and the third a
     * pathLenConstraint of 0. The end entity certificate is a CA certificate.
     */
    public void test4_6_10()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid pathLenConstraint Test10 EE")
            .withCrls("pathLenConstraint6 subsubCA00 CRL")
            .withCACert("pathLenConstraint6 subsubCA00 Cert")
            .withCrls("pathLenConstraint6 subCA0 CRL")
            .withCACert("pathLenConstraint6 subCA0 Cert")
            .withCrls("pathLenConstraint6 CA CRL")
            .withCACert("pathLenConstraint6 CA Cert")
            .doExceptionTest(1, "Max path length not greater than zero");
    }

    /**
     * 4.6.11 Invalid pathLenConstraint Test11
     * <p>
     * This test consists of a certification path of length 5. The first certificate in the path includes a
     * pathLenConstraint of 6, the second a pathLenConstraint of 1, and the third a
     * pathLenConstraint of 1. The fourth certificate does not include a pathLenConstraint. The fifth
     * certificate is an end entity certificate.
     */
    public void test4_6_11()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid pathLenConstraint Test11 EE")
            .withCrls("pathLenConstraint6subsubsubCA11X CRL")
            .withCACert("pathLenConstraint6 subsubsubCA11X Cert")
            .withCrls("pathLenConstraint6 subsubCA11 CRL")
            .withCACert("pathLenConstraint6 subsubCA11 Cert")
            .withCrls("pathLenConstraint6 subCA1 CRL")
            .withCACert("pathLenConstraint6 subCA1 Cert")
            .withCrls("pathLenConstraint6 CA CRL")
            .withCACert("pathLenConstraint6 CA Cert")
            .doExceptionTest(1, "Max path length not greater than zero");
    }

    /**
     * 4.6.12 Invalid pathLenConstraint Test12
     * <p>
     * This test consists of a certification path of length 5. The first certificate in the path includes a
     * pathLenConstraint of 6, the second a pathLenConstraint of 1, and the third a
     * pathLenConstraint of 1. The fourth certificate does not include a pathLenConstraint. The end
     * entity certificate is a CA certificate.
     */
    public void test4_6_12()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid pathLenConstraint Test12 EE")
            .withCrls("pathLenConstraint6subsubsubCA11X CRL")
            .withCACert("pathLenConstraint6 subsubsubCA11X Cert")
            .withCrls("pathLenConstraint6 subsubCA11 CRL")
            .withCACert("pathLenConstraint6 subsubCA11 Cert")
            .withCrls("pathLenConstraint6 subCA1 CRL")
            .withCACert("pathLenConstraint6 subCA1 Cert")
            .withCrls("pathLenConstraint6 CA CRL")
            .withCACert("pathLenConstraint6 CA Cert")
            .doExceptionTest(1, "Max path length not greater than zero");
    }

    /**
     * 4.6.13 Valid pathLenConstraint Test13
     * <p>
     * This test consists of a certification path of length 5. The first certificate in the path includes a
     * pathLenConstraint of 6, the second a pathLenConstraint of 4, and the third a
     * pathLenConstraint of 1. The fourth certificate does not include a pathLenConstraint. The fifth
     * certificate is an end entity certificate.
     */
    public void test4_6_13()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid pathLenConstraint Test13 EE")
            .withCrls("pathLenConstraint6subsubsubCA41X CRL")
            .withCACert("pathLenConstraint6 subsubsubCA41X Cert")
            .withCrls("pathLenConstraint6 subsubCA41 CRL")
            .withCACert("pathLenConstraint6 subsubCA41 Cert")
            .withCrls("pathLenConstraint6 subCA4 CRL")
            .withCACert("pathLenConstraint6 subCA4 Cert")
            .withCrls("pathLenConstraint6 CA CRL")
            .withCACert("pathLenConstraint6 CA Cert")
            .doTest();
    }

    /**
     * 4.6.14 Valid pathLenConstraint Test14
     * <p>
     * This test consists of a certification path of length 5. The first certificate in the path includes a
     * pathLenConstraint of 6, the second a pathLenConstraint of 4, and the third a
     * pathLenConstraint of 1. The fourth certificate does not include a pathLenConstraint. The end
     * entity certificate is a CA certificate.
     */
    public void test4_6_14()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid pathLenConstraint Test14 EE")
            .withCrls("pathLenConstraint6subsubsubCA41X CRL")
            .withCACert("pathLenConstraint6 subsubsubCA41X Cert")
            .withCrls("pathLenConstraint6 subsubCA41 CRL")
            .withCACert("pathLenConstraint6 subsubCA41 Cert")
            .withCrls("pathLenConstraint6 subCA4 CRL")
            .withCACert("pathLenConstraint6 subCA4 Cert")
            .withCrls("pathLenConstraint6 CA CRL")
            .withCACert("pathLenConstraint6 CA Cert")
            .doTest();
    }

    /**
     * 4.6.15 Valid Self-Issued pathLenConstraint Test15
     * <p>
     * In this test, the first certificate in the path includes a basicConstraints extension with a
     * pathLenConstraint of 0 (allowing 0 additional non-self-issued intermediate certificates in the
     * path). This is followed by a self-issued certificate and the end entity certificate.
     * 32
     */
    public void test4_6_15()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid SelfIssued pathLenConstraint Test15 EE")
            .withCACert("pathLenConstraint0 SelfIssued CA Cert")
            .withCrls("pathLenConstraint0 CA CRL")
            .withCACert("pathLenConstraint0 CA Cert")
            .doTest();
    }

    /**
     * 4.6.16 Invalid Self-Issued pathLenConstraint Test16
     * <p>
     * In this test, the first certificate in the path includes a basicConstraints extension with a
     * pathLenConstraint of 0 (allowing 0 additional non-self-issued intermediate certificates in the
     * path). This is followed by a self-issued certificate, an non-self-issued certificate, and the end entity
     * certificate.
     */
    public void test4_6_16()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid SelfIssued pathLenConstraint Test16 EE")
            .withCrls("pathLenConstraint0 subCA2 CRL")
            .withCACert("pathLenConstraint0 subCA2 Cert")
            .withCACert("pathLenConstraint0 SelfIssued CA Cert")
            .withCrls("pathLenConstraint0 CA CRL")
            .withCACert("pathLenConstraint0 CA Cert")
            .doExceptionTest(1, "Max path length not greater than zero");
    }

    /**
     * 4.6.17 Valid Self-Issued pathLenConstraint Test17
     * <p>
     * In this test, the first certificate in the path includes a basicConstraints extension with a
     * pathLenConstraint of 1 (allowing 1 additional non-self-issued intermediate certificate in the
     * path). This is followed by a self-issued certificate, a non-self-issued certificate, another self-issued
     * certificate, and the end entity certificate.
     */
    public void test4_6_17()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid SelfIssued pathLenConstraint Test17 EE")
            .withCACert("pathLenConstraint1 SelfIssued subCA Cert")
            .withCrls("pathLenConstraint1 subCA CRL")
            .withCACert("pathLenConstraint1 subCA Cert")
            .withCACert("pathLenConstraint1 SelfIssued CA Cert")
            .withCrls("pathLenConstraint1 CA CRL")
            .withCACert("pathLenConstraint1 CA Cert")
            .doTest();
    }

    /**
     * 4.7.1 Invalid keyUsage Critical keyCertSign False Test1
     * <p>
     * In this test, the intermediate certificate includes a critical keyUsage extension in which
     * keyCertSign is false.
     */
    public void test4_7_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid keyUsage Critical keyCertSign False Test1 EE")
            .withCrls("keyUsage Critical keyCertSignFalse CA CRL")
            .withCACert("keyUsage Critical keyCertSign False CA Cert")
            .doExceptionTest(1, "Issuer certificate keyusage extension is critical and does not permit key signing.");
    }

    /**
     * 4.7.2 Invalid keyUsage Not Critical keyCertSign False Test2
     * <p>
     * In this test, the intermediate certificate includes a non-critical keyUsage extension in which
     * keyCertSign is false.
     */
    public void test4_7_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid keyUsage Not Critical keyCertSign False Test2 EE")
            .withCrls("keyUsage Not CriticalkeyCertSign False CA CRL")
            .withCACert("keyUsage Not Critical keyCertSign False CA Cert")
            .doExceptionTest(1, "Issuer certificate keyusage extension is critical and does not permit key signing.");
    }

    /**
     * 4.7.3 Valid keyUsage Not Critical Test3
     * <p>
     * In this test, the intermediate certificate includes a non-critical keyUsage extension.
     * 34
     */
    public void test4_7_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid keyUsage Not Critical Test3 EE")
            .withCrls("keyUsage Not Critical CA CRL")
            .withCACert("keyUsage Not Critical CA Cert")
            .doTest();
    }

    /**
     * 4.7.4 Invalid keyUsage Critical cRLSign False Test4
     * <p>
     * In this test, the intermediate certificate includes a critical keyUsage extension in which cRLSign
     * is false.
     */
    public void test4_7_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid keyUsage Critical cRLSign False Test4 EE")
            .withCrls("keyUsage Critical cRLSign False CACRL")
            .withCACert("keyUsage Critical cRLSign False CA Cert")
            .doExceptionTest(0, "Issuer certificate key usage extension does not permit CRL signing.");
    }

    /**
     * 4.7.5 Invalid keyUsage Not Critical cRLSign False Test5
     * <p>
     * In this test, the intermediate certificate includes a non-critical keyUsage extension in which
     * cRLSign is false.
     */
    public void test4_7_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid keyUsage Not Critical cRLSign False Test5 EE")
            .withCrls("keyUsage Not Critical cRLSignFalse CA CRL")
            .withCACert("keyUsage Not Critical cRLSign False CA Cert")
            .doExceptionTest(0, "Issuer certificate key usage extension does not permit CRL signing.");
    }

    /**
     * 4.8.1 All Certificates Same Policy Test1
     * <p>
     * In this test, every certificate in the path asserts the same policy, NIST-test-policy-1. The
     * certification path in this test is the same certification path as in Valid Signatures Test1. If
     * possible, it is recommended that the certification path in this test be validated using the following
     * inputs:
     * 1. default settings, but with initial-explicit-policy set. The path should validate
     * successfully.
     * 2. default settings, but with initial-explicit-policy set and initial-policy-set =
     * {NIST-test-policy-1}. The path should validate successfully.
     * 3. default settings, but with initial-explicit-policy set and initial-policy-set =
     * {NIST-test-policy-2}. The path should not validate successfully.
     * 4. default settings, but with initial-explicit-policy set and initial-policy-set =
     * {NIST-test-policy-1, NIST-test-policy-2}. The path should validate
     * successfully.
     */
    public void test4_8_1()
        throws Exception
    {

        // 1
        new PKITSTest()
            .withEndEntity("Valid Certificate Path Test1 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .withExplicitPolicyRequired(true).doTest();


        // 2
        new PKITSTest()
            .withEndEntity("Valid Certificate Path Test1 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .withExplicitPolicyRequired(true)
            .withPolicyByName("NIST-test-policy-1")
            .doTest();

        // 3
        new PKITSTest()
            .withEndEntity("Valid Certificate Path Test1 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .withExplicitPolicyRequired(true)
            .withPolicyByName("NIST-test-policy-2")
            .doExceptionTest(-1, "Path processing failed on policy.");


        // 4
        new PKITSTest()
            .withEndEntity("Valid Certificate Path Test1 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .withExplicitPolicyRequired(true)
            .withPolicyByName("NIST-test-policy-1", "NIST-test-policy-2")
            .doTest();


    }

    /**
     * 4.8.2 All Certificates No Policies Test2
     * <p>
     * In this test, the certificatePolicies extension is omitted from every certificate in the path. If
     * possible, it is recommended that the certification path in this test be validated using the following
     * inputs:
     * 1. default settings. The path should validate successfully.
     * 2. default settings, but with initial-explicit-policy set . The path should not validate
     * successfully.
     */
    public void test4_8_2()
        throws Exception
    {
        // 1
        new PKITSTest()
            .withEndEntity("All Certificates No Policies Test2 EE")
            .withCrls("No Policies CA CRL")
            .withCACert("No Policies CA Cert")
            .doTest();

        // 2
        new PKITSTest()
            .withEndEntity("All Certificates No Policies Test2 EE")
            .withCrls("No Policies CA CRL")
            .withCACert("No Policies CA Cert")
            .withExplicitPolicyRequired(true)
            .doExceptionTest(1, "No valid policy tree found when one expected.");
    }

    /**
     * 4.8.3 Different Policies Test3
     * <p>
     * In this test, every certificate in the path asserts the same certificate policy except the first certificate
     * in the path. If possible, it is recommended that the certification path in this test be validated using
     * the following inputs:
     * 1. default settings. The path should validate successfully.
     * 2. default settings, but with initial-explicit-policy set . The path should not validate
     * successfully.
     * 3. default settings, but with initial-explicit-policy set and initial-policy-set =
     * {NIST-test-policy-1, NIST-test-policy-2}. The path should not validate
     * successfully.
     */
    public void test4_8_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Different Policies Test3 EE")
            .withCrls("Policies P2 subCA CRL")
            .withCACert("Policies P2 subCA Cert")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();


        new PKITSTest()
            .withEndEntity("Different Policies Test3 EE")
            .withCrls("Policies P2 subCA CRL")
            .withCACert("Policies P2 subCA Cert")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .withExplicitPolicyRequired(true)
            .doExceptionTest(1, "No valid policy tree found when one expected.");

        new PKITSTest()
            .withEndEntity("Different Policies Test3 EE")
            .withCrls("Policies P2 subCA CRL")
            .withCACert("Policies P2 subCA Cert")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .withExplicitPolicyRequired(true)
            .withPolicyByName("NIST-test-policy-1", "NIST-test-policy-2")
            .doExceptionTest(1, "No valid policy tree found when one expected.");
    }

    /**
     * 4.8.4 Different Policies Test4
     * <p>
     * In this test, every certificate in the path asserts the same certificate policy except the end entity
     * certificate.
     */
    public void test4_8_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Different Policies Test4 EE")
            .withCrls("Good subCA CRL")
            .withCACert("Good subCA Cert")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.8.5 Different Policies Test5
     * <p>
     * In this test, every certificate in the path except the second certificate asserts the same policy.
     */
    public void test4_8_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Different Policies Test5 EE")
            .withCrls("Policies P2 subCA2 CRL")
            .withCACert("Policies P2 subCA2 Cert")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.8.6 Overlapping Policies Test6
     * <p>
     * The following path is such that the intersection of certificate policies among all the certificates has
     * exactly one policy, NIST-test-policy-1. The final certificate in the path is a CA certificate. If
     * possible, it is recommended that the certification path in this test be validated using the following
     * inputs:
     * 1. default settings. The path should validate successfully.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully.
     * 3. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
     * should not validate successfully.
     */
    public void test4_8_6()
        throws Exception
    {
        // 1
        new PKITSTest()
            .withEndEntity("Overlapping Policies Test6 EE")
            .withCrls("Policies P1234 subsubCAP123P12CRL")
            .withCACert("Policies P1234 subsubCAP123P12 Cert")
            .withCrls("Policies P1234 subCAP123 CRL")
            .withCACert("Policies P1234 subCAP123 Cert")
            .withCrls("Policies P1234 CA CRL")
            .withCACert("Policies P1234 CA Cert")
            .doTest();

        // 2
        new PKITSTest()
            .withEndEntity("Overlapping Policies Test6 EE")
            .withCrls("Policies P1234 subsubCAP123P12CRL")
            .withCACert("Policies P1234 subsubCAP123P12 Cert")
            .withCrls("Policies P1234 subCAP123 CRL")
            .withCACert("Policies P1234 subCAP123 Cert")
            .withCrls("Policies P1234 CA CRL")
            .withCACert("Policies P1234 CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();


        // 3
        new PKITSTest()
            .withEndEntity("Overlapping Policies Test6 EE")
            .withCrls("Policies P1234 subsubCAP123P12CRL")
            .withCACert("Policies P1234 subsubCAP123P12 Cert")
            .withCrls("Policies P1234 subCAP123 CRL")
            .withCACert("Policies P1234 subCAP123 Cert")
            .withCrls("Policies P1234 CA CRL")
            .withCACert("Policies P1234 CA Cert")
            .withPolicyByName("NIST-test-policy-2")
            .doExceptionTest(-1, "Path processing failed on policy.");


    }

    /**
     * 4.8.7 Different Policies Test7
     * <p>
     * The following path is such that the intersection of certificate policies among all the certificates is
     * empty. The final certificate in the path is a CA certificate.
     */
    public void test4_8_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Different Policies Test7 EE")
            .withCrls("Policies P123 subsubCAP12P1 CRL")
            .withCACert("Policies P123 subsubCAP12P1 Cert")
            .withCrls("Policies P123 subCAP12 CRL")
            .withCACert("Policies P123 subCAP12 Cert")
            .withCrls("Policies P123 CA CRL")
            .withCACert("Policies P123 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.8.8 Different Policies Test8
     * <p>
     * The following path is such that the intersection of certificate policies among all the certificates is
     * empty. The final certificate in the path is a CA certificate.
     */
    public void test4_8_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Different Policies Test8 EE")
            .withCrls("Policies P12 subsubCAP1P2 CRL")
            .withCACert("Policies P12 subsubCAP1P2 Cert")
            .withCrls("Policies P12 subCAP1 CRL")
            .withCACert("Policies P12 subCAP1 Cert")
            .withCrls("Policies P12 CA CRL")
            .withCACert("Policies P12 CA Cert")
            .doExceptionTest(1, "No valid policy tree found when one expected.");
    }

    /**
     * 4.8.9 Different Policies Test9
     * <p>
     * The following path is such that the intersection of certificate policies among all the certificates is
     * empty.
     */
    public void test4_8_9()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Different Policies Test9 EE")
            .withCrls("Policies P123subsubsubCAP12P2P1 CRL")
            .withCACert("Policies P123 subsubsubCAP12P2P1 Cert")
            .withCrls("Policies P123 subsubCAP2P2 CRL")
            .withCACert("Policies P123 subsubCAP12P2 Cert")
            .withCrls("Policies P123 subCAP12 CRL")
            .withCACert("Policies P123 subCAP12 Cert")
            .withCrls("Policies P123 CA CRL")
            .withCACert("Policies P123 CA Cert")
            .doExceptionTest(1, "No valid policy tree found when one expected.");
    }

    /**
     * 4.8.10 All Certificates Same Policies Test10
     * <p>
     * In this test, every certificate in the path asserts the same policies, NIST-test-policy-1 and NISTtest-policy-2. If possible, it is recommended that the certification path in this test be validated
     * using the following inputs:
     * 1. default settings. The path should validate successfully.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully.
     * 3. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
     * should validate successfully.
     */
    public void test4_8_10()
        throws Exception
    {
        // 1
        new PKITSTest()
            .withEndEntity("All Certificates Same Policies Test10 EE")
            .withCrls("Policies P12 CA CRL")
            .withCACert("Policies P12 CA Cert")
            .doTest();
        // 2
        new PKITSTest()
            .withEndEntity("All Certificates Same Policies Test10 EE")
            .withCrls("Policies P12 CA CRL")
            .withCACert("Policies P12 CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();

        // 3
        new PKITSTest()
            .withEndEntity("All Certificates Same Policies Test10 EE")
            .withCrls("Policies P12 CA CRL")
            .withCACert("Policies P12 CA Cert")
            .withPolicyByName("NIST-test-policy-2")
            .doTest();
    }

    /**
     * 4.8.11 All Certificates AnyPolicy Test11
     * <p>
     * In this test, every certificate in the path asserts the special policy anyPolicy. If possible, it is
     * recommended that the certification path in this test be validated using the following inputs:
     * 1. default settings. The path should validate successfully.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully.
     */
    public void test4_8_11()
        throws Exception
    {
        // 2
        new PKITSTest()
            .withEndEntity("All Certificates anyPolicy Test11 EE")
            .withCrls("anyPolicy CA CRL")
            .withCACert("anyPolicy CA Cert")
            .doTest();

        // 2
        new PKITSTest()
            .withEndEntity("All Certificates anyPolicy Test11 EE")
            .withCrls("anyPolicy CA CRL")
            .withCACert("anyPolicy CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();
    }

    /**
     * 4.8.12 Different Policies Test12
     * <p>
     * In this test, the path consists of two certificates, each of which asserts a different certificate policy.
     */
    public void test4_8_12()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Different Policies Test12 EE")
            .withCrls("Policies P3 CA CRL")
            .withCACert("Policies P3 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.8.13 All Certificates Same Policies Test13
     * <p>
     * In this test, every certificate in the path asserts the same policies, NIST-test-policy-1, NIST-testpolicy-2, and NIST-test-policy-3. If possible, it is recommended that the certification path in this
     * test be validated using the following inputs:
     * 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
     * should validate successfully.
     * 3. default settings, but with initial-policy-set = {NIST-test-policy-3}. The path
     * should validate successfully.
     */
    public void test4_8_13()
        throws Exception
    {
        // 1
        new PKITSTest()
            .withEndEntity("All Certificates Same Policies Test13 EE")
            .withCrls("Policies P123 CA CRL")
            .withCACert("Policies P123 CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();

        // 2
        new PKITSTest()
            .withEndEntity("All Certificates Same Policies Test13 EE")
            .withCrls("Policies P123 CA CRL")
            .withCACert("Policies P123 CA Cert")
            .withPolicyByName("NIST-test-policy-2")
            .doTest();

        // 3
        new PKITSTest()
            .withEndEntity("All Certificates Same Policies Test13 EE")
            .withCrls("Policies P123 CA CRL")
            .withCACert("Policies P123 CA Cert")
            .withPolicyByName("NIST-test-policy-3")
            .doTest();
    }

    /**
     * 4.8.14 AnyPolicy Test14
     * <p>
     * In this test, the intermediate certificate asserts anyPolicy and the end entity certificate asserts
     * NIST-test-policy-1. If possible, it is recommended that the certification path in this test be
     * validated using the following inputs:
     * 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
     * should not validate successfully.
     */
    public void test4_8_14()
        throws Exception
    {
        // 1
        new PKITSTest()
            .withEndEntity("AnyPolicy Test14 EE")
            .withCrls("anyPolicy CA CRL")
            .withCACert("anyPolicy CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();
        // 2
        new PKITSTest()
            .withEndEntity("AnyPolicy Test14 EE")
            .withCrls("anyPolicy CA CRL")
            .withCACert("anyPolicy CA Cert")
            .withPolicyByName("NIST-test-policy-2")
            .doExceptionTest(-1, "Path processing failed on policy.");
    }

    /**
     * 4.8.15 User Notice Qualifier Test15
     * <p>
     * In this test, the path consists of a single certificate. The certificate asserts the policy NIST-testpolicy-1 and includes a user notice policy qualifier.
     * <p>
     * Display of user notice beyond CertPath API at the moment.
     * </p>
     */
    public void test4_8_15()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("User Notice Qualifier Test15 EE")
            .doTest();

        new PKITSTest()
               .withPolicyByName("NIST-test-policy-2")
               .withEndEntity("User Notice Qualifier Test15 EE")
               .doExceptionTest(-1, "Path processing failed on policy.");
    }

    /**
     * 4.8.16 User Notice Qualifier Test16
     * <p>
     * In this test, the path consists of an intermediate certificate and an end entity certificate. The
     * intermediate certificate asserts the policy NIST-test-policy-1. The end entity certificate asserts
     * both NIST-test-policy-1 and NIST-test-policy-2. Each policy in the end entity certificate has a
     * different user notice qualifier associated with it.
     * <p>
     * Display of user notice beyond CertPath API at the moment.
     * </p>
     */
    public void test4_8_16()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("User Notice Qualifier Test16 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();
    }

    /**
     * 4.8.17 User Notice Qualifier Test17
     * <p>
     * In this test, the path consists of an intermediate certificate and an end entity certificate. The
     * intermediate certificate asserts the policy NIST-test-policy-1. The end entity certificate asserts
     * anyPolicy. There is a user notice policy qualifier associated with anyPolicy in the end entity
     * certificate.
     * <p>
     * Display of user notice beyond CertPath API at the moment.
     * </p>
     */
    public void test4_8_17()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("User Notice Qualifier Test17 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();
    }

    /**
     * 4.8.18 User Notice Qualifier Test18
     * <p>
     * In this test, the intermediate certificate asserts policies NIST-test-policy-1 and NIST-test-policy-2.
     * The end certificate asserts NIST-test-policy-1 and anyPolicy. Each of the policies in the end
     * entity certificate asserts a different user notice policy qualifier. If possible, it is recommended that
     * the certification path in this test be validated using the following inputs:
     * 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully and the qualifier associated with NIST-test-policy-1
     * in the end entity certificate should be displayed.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
     * should validate successfully and the qualifier associated with anyPolicy in the
     * end entity certificate should be displayed.
     * 45
     * <p>
     * Display of policy messages beyond CertPath API at the moment.
     * </p>
     */
    public void test4_8_18()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("User Notice Qualifier Test18 EE")
            .withCrls("Policies P12 CA CRL")
            .withCACert("Policies P12 CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();

        new PKITSTest()
            .withEndEntity("User Notice Qualifier Test18 EE")
            .withCrls("Policies P12 CA CRL")
            .withCACert("Policies P12 CA Cert")
            .withPolicyByName("NIST-test-policy-2")
            .doTest();
    }

    /**
     * 4.8.19 User Notice Qualifier Test19
     * <p>
     * In this test, the path consists of a single certificate. The certificate asserts the policy NIST-testpolicy-1 and includes a user notice policy qualifier. The user notice qualifier contains explicit text
     * that is longer than 200 bytes.
     * [RFC 3280 4.2.1.5] Note: While the explicitText has a maximum size of 200 characters,
     * some non-conforming CAs exceed this limit. Therefore, certificate users SHOULD
     * gracefully handle explicitText with more than 200 characters.
     */
    public void test4_8_19()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("User Notice Qualifier Test19 EE")
            .doTest();
    }

    /**
     * 4.8.20 CPS Pointer Qualifier Test20
     * <p>
     * In this test, the path consists of an intermediate certificate and an end entity certificate, both of
     * which assert the policy NIST-test-policy-1. There is a CPS pointer policy qualifier associated with
     * NIST-test-policy-1 in the end entity certificate.
     */
    public void test4_8_20()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("CPS Pointer Qualifier Test20 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();
    }

    /**
     * 4.9.1 Valid RequireExplicitPolicy Test1
     * <p>
     * In this test, the first certificate in the path includes a policyConstraints extension with
     * requireExplicitPolicy set to 10. This is followed by three more intermediate certificates and an
     * end entity certificate. The end entity certificate does not include a certificatePolicies extension.
     * 47
     */
    public void test4_9_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid requireExplicitPolicy Test1 EE")
            .withCrls("requireExplicitPolicy10subsubsubCA CRL")
            .withCACert("requireExplicitPolicy10 subsubsubCA Cert")
            .withCrls("requireExplicitPolicy10 subsubCACRL")
            .withCACert("requireExplicitPolicy10 subsubCA Cert")
            .withCrls("requireExplicitPolicy10 subCA CRL")
            .withCACert("requireExplicitPolicy10 subCA Cert")
            .withCrls("requireExplicitPolicy10 CA CRL")
            .withCACert("requireExplicitPolicy10 CA Cert")
            .doTest();
    }

    /**
     * 4.9.2 Valid RequireExplicitPolicy Test2
     * <p>
     * In this test, the first certificate in the path includes a policyConstraints extension with
     * requireExplicitPolicy set to 5. This is followed by three more intermediate certificates and an end
     * entity certificate. The end entity certificate does not include a certificatePolicies extension.
     */
    public void test4_9_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid requireExplicitPolicy Test2 EE")
            .withCrls("requireExplicitPolicy5 subsubsubCACRL")
            .withCACert("requireExplicitPolicy5 subsubsubCA Cert")
            .withCrls("requireExplicitPolicy5 subsubCA CRL")
            .withCACert("requireExplicitPolicy5 subsubCA Cert")
            .withCrls("requireExplicitPolicy5 subCA CRL")
            .withCACert("requireExplicitPolicy5 subCA Cert")
            .withCrls("requireExplicitPolicy5 CA CRL")
            .withCACert("requireExplicitPolicy5 CA Cert")
            .doTest();
    }

    /**
     * 4.9.3 Invalid RequireExplicitPolicy Test3
     * <p>
     * In this test, the first certificate in the path includes a policyConstraints extension with
     * requireExplicitPolicy set to 4. This is followed by three more intermediate certificates and an end
     * entity certificate. The end entity certificate does not include a certificatePolicies extension.
     */
    public void test4_9_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid requireExplicitPolicy Test3 EE")
            .withCrls("requireExplicitPolicy4 subsubsubCACRL")
            .withCACert("requireExplicitPolicy4 subsubsubCA Cert")
            .withCrls("requireExplicitPolicy4 subsubCA CRL")
            .withCACert("requireExplicitPolicy4 subsubCA Cert")
            .withCrls("requireExplicitPolicy4 subCA CRL")
            .withCACert("requireExplicitPolicy4 subCA Cert")
            .withCrls("requireExplicitPolicy4 CA CRL")
            .withCACert("requireExplicitPolicy4 CA Cert")
            .doExceptionTest(-1, "Path processing failed on policy.");
    }

    /**
     * 4.9.4 Valid RequireExplicitPolicy Test4
     * <p>
     * In this test, the first certificate in the path includes a policyConstraints extension with
     * requireExplicitPolicy set to 0. This is followed by three more intermediate certificates and an end
     * entity certificate.
     */
    public void test4_9_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid requireExplicitPolicy Test4 EE")
            .withCrls("requireExplicitPolicy0 subsubsubCACRL")
            .withCACert("requireExplicitPolicy0 subsubsubCA Cert")
            .withCrls("requireExplicitPolicy0 subsubCA CRL")
            .withCACert("requireExplicitPolicy0 subsubCA Cert")
            .withCrls("requireExplicitPolicy0 subCA CRL")
            .withCACert("requireExplicitPolicy0 subCA Cert")
            .withCrls("requireExplicitPolicy0 CA CRL")
            .withCACert("requireExplicitPolicy0 CA Cert")
            .doTest();
    }

    /**
     * 4.9.5 Invalid RequireExplicitPolicy Test5
     * <p>
     * In this test, the first certificate in the path includes a policyConstraints extension with
     * requireExplicitPolicy set to 7. The second certificate in the path includes a policyConstraints
     * extension with requireExplicitPolicy set to 2. The third certificate in the path includes a
     * policyConstraints extension with requireExplicitPolicy set to 4. This is followed by one more
     * intermediate certificate and an end entity certificate. The end entity certificate does not include a
     * certificatePolicies extension.
     */
    public void test4_9_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid requireExplicitPolicy Test5 EE")
            .withCrls("requireExplicitPolicy7subsubsubCARE2RE4 CRL")
            .withCACert("requireExplicitPolicy7 subsubsubCARE2RE4 Cert")
            .withCrls("requireExplicitPolicy7subsubCARE2RE4 CRL")
            .withCACert("requireExplicitPolicy7 subsubCARE2RE4 Cert")
            .withCrls("requireExplicitPolicy7 subCARE2 CRL")
            .withCACert("requireExplicitPolicy7 subCARE2 Cert")
            .withCrls("requireExplicitPolicy7 CA CRL")
            .withCACert("requireExplicitPolicy7 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.9.6 Valid Self-Issued requireExplicitPolicy Test6
     * <p>
     * In this test, the first certificate in the path includes a policyConstraints extension with
     * requireExplicitPolicy set to 2. This is followed by a self-issued intermediate certificate and an
     * end entity certificate. The end entity certificate does not include a certificatePolicies extension.
     */
    public void test4_9_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid SelfIssued requireExplicitPolicy Test6 EE")
            .withCACert("requireExplicitPolicy2 SelfIssued CA Cert")
            .withCrls("requireExplicitPolicy2 CA CRL")
            .withCACert("requireExplicitPolicy2 CA Cert")
            .doTest();
    }

    /**
     * 4.9.7 Invalid Self-Issued requireExplicitPolicy Test7
     * <p>
     * In this test, the first certificate in the path includes a policyConstraints extension with
     * requireExplicitPolicy set to 2. This is followed by a self-issued intermediate certificate, a nonself-issued intermediate certificate, and an end entity certificate. The end entity certificate does not
     * include a certificatePolicies extension.
     */
    public void test4_9_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid SelfIssued requireExplicitPolicy Test7 EE")
            .withCrls("requireExplicitPolicy2 subCA CRL")
            .withCACert("requireExplicitPolicy2 subCA Cert")
            .withCACert("requireExplicitPolicy2 SelfIssued CA Cert")
            .withCrls("requireExplicitPolicy2 CA CRL")
            .withCACert("requireExplicitPolicy2 CA Cert")
            .doExceptionTest(-1, "Path processing failed on policy.");
    }

    /**
     * 4.9.8 Invalid Self-Issued requireExplicitPolicy Test8
     * <p>
     * In this test, the first certificate in the path includes a policyConstraints extension with
     * requireExplicitPolicy set to 2. This is followed by a self-issued intermediate certificate, a nonself-issued intermediate certificate, a self-issued intermediate certificate, and an end entity
     * certificate. The end entity certificate does not include a certificatePolicies extension.
     * 50
     */
    public void test4_9_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid SelfIssued requireExplicitPolicy Test8 EE")
            .withCACert("requireExplicitPolicy2 SelfIssued subCA Cert")
            .withCrls("requireExplicitPolicy2 subCA CRL")
            .withCACert("requireExplicitPolicy2 subCA Cert")
            .withCACert("requireExplicitPolicy2 SelfIssued CA Cert")
            .withCrls("requireExplicitPolicy2 CA CRL")
            .withCACert("requireExplicitPolicy2 CA Cert")
            .doExceptionTest(-1, "Path processing failed on policy.");
    }

    /**
     * 4.10.1 Valid Policy Mapping Test1
     * <p>
     * In this test, the intermediate certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to
     * NIST-test-policy-2. The end entity certificate asserts NIST-test-policy-2. If possible, it is
     * recommended that the certification path in this test be validated using the following inputs:
     * 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
     * should not validate successfully.
     * 3. default settings, but with initial-policy-mapping-inhibit set. The path should not
     * validate successfully.
     */
    public void test4_10_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test1 EE")
            .withCrls("Mapping 1to2 CA CRL")
            .withCACert("Mapping 1to2 CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();


        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test1 EE")
            .withCrls("Mapping 1to2 CA CRL")
            .withCACert("Mapping 1to2 CA Cert")
            .withPolicyByName("NIST-test-policy-2")
            .doExceptionTest(-1, "Path processing failed on policy.");


        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test1 EE")
            .withCrls("Mapping 1to2 CA CRL")
            .withCACert("Mapping 1to2 CA Cert")
            .withPolicyMappingInhibited(true)
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.10.2 Invalid Policy Mapping Test2
     * <p>
     * In this test, the intermediate certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to
     * NIST-test-policy-2. The end entity certificate asserts NIST-test-policy-1. If possible, it is
     * recommended that the certification path in this test be validated using the following inputs:
     * 1. default settings. The path should not validate successfully.
     * 2. default settings, but with initial-policy-mapping-inhibit set. The path should not
     * validate successfully.
     */
    public void test4_10_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Policy Mapping Test2 EE")
            .withCrls("Mapping 1to2 CA CRL")
            .withCACert("Mapping 1to2 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");

        new PKITSTest()
            .withEndEntity("Invalid Policy Mapping Test2 EE")
            .withCrls("Mapping 1to2 CA CRL")
            .withCACert("Mapping 1to2 CA Cert")
            .withPolicyMappingInhibited(true)
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.10.3 Valid Policy Mapping Test3
     * <p>
     * In this test, the path is valid under NIST-test-policy-2 as a result of policy mappings. If possible,
     * it is recommended that the certification path in this test be validated using the following inputs:
     * 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should not validate successfully.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
     * should validate successfully.
     */
    public void test4_10_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test3 EE")
            .withCrls("P12 Mapping 1to3 subsubCA CRL")
            .withCACert("P12 Mapping 1to3 subsubCA Cert")
            .withCrls("P12 Mapping 1to3 subCA CRL")
            .withCACert("P12 Mapping 1to3 subCA Cert")
            .withCrls("P12 Mapping 1to3 CA CRL")
            .withCACert("P12 Mapping 1to3 CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doExceptionTest(-1, "Path processing failed on policy.");


        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test3 EE")
            .withCrls("P12 Mapping 1to3 subsubCA CRL")
            .withCACert("P12 Mapping 1to3 subsubCA Cert")
            .withCrls("P12 Mapping 1to3 subCA CRL")
            .withCACert("P12 Mapping 1to3 subCA Cert")
            .withCrls("P12 Mapping 1to3 CA CRL")
            .withCACert("P12 Mapping 1to3 CA Cert")
            .withPolicyByName("NIST-test-policy-2")
            .doTest();

    }

    /**
     * 4.10.4 Invalid Policy Mapping Test4
     * <p>
     * In this test, the policy asserted in the end entity certificate is not in the authorities-constrainedpolicy-set.
     */
    public void test4_10_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Policy Mapping Test4 EE")
            .withCrls("P12 Mapping 1to3 subsubCA CRL")
            .withCACert("P12 Mapping 1to3 subsubCA Cert")
            .withCrls("P12 Mapping 1to3 subCA CRL")
            .withCACert("P12 Mapping 1to3 subCA Cert")
            .withCrls("P12 Mapping 1to3 CA CRL")
            .withCACert("P12 Mapping 1to3 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.10.5 Valid Policy Mapping Test5
     * <p>
     * In this test, the path is valid under NIST-test-policy-1 as a result of policy mappings. If possible,
     * it is recommended that the certification path in this test be validated using the following inputs:
     * 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-6}. The path
     * should not validate successfully.
     */
    public void test4_10_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test5 EE")
            .withCrls("P1 Mapping 1to234 subCA CRL")
            .withCACert("P1 Mapping 1to234 subCA Cert")
            .withCrls("P1 Mapping 1to234 CA CRL")
            .withCACert("P1 Mapping 1to234 CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();

        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test5 EE")
            .withCrls("P1 Mapping 1to234 subCA CRL")
            .withCACert("P1 Mapping 1to234 subCA Cert")
            .withCrls("P1 Mapping 1to234 CA CRL")
            .withCACert("P1 Mapping 1to234 CA Cert")
            .withPolicyByName("NIST-test-policy-6")
            .doExceptionTest(-1, "Path processing failed on policy.");
    }

    /**
     * 4.10.6 Valid Policy Mapping Test6
     * <p>
     * In this test, the path is valid under NIST-test-policy-1 as a result of policy mappings. If possible,
     * it is recommended that the certification path in this test be validated using the following inputs:
     * 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-6}. The path
     * should not validate successfully.
     */
    public void test4_10_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test6 EE")
            .withCrls("P1 Mapping 1to234 subCA CRL")
            .withCACert("P1 Mapping 1to234 subCA Cert")
            .withCrls("P1 Mapping 1to234 CA CRL")
            .withCACert("P1 Mapping 1to234 CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();

        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test6 EE")
            .withCrls("P1 Mapping 1to234 subCA CRL")
            .withCACert("P1 Mapping 1to234 subCA Cert")
            .withCrls("P1 Mapping 1to234 CA CRL")
            .withCACert("P1 Mapping 1to234 CA Cert")
            .withPolicyByName("NIST-test-policy-6")
            .doExceptionTest(-1, "Path processing failed on policy.");
    }

    /**
     * 4.10.7 Invalid Mapping From anyPolicy Test7
     * <p>
     * In this test, the intermediate certificate includes a policyMappings extension that includes a
     * mapping in which the issuerDomainPolicy is anyPolicy. The intermediate certificate also
     * includes a critical policyConstraints extension with requireExplicitPolicy set to 0.
     * [RFC 3280 6.1.4] (a) If a policy mapping extension is present, verify that the special
     * value anyPolicy does not appear as an issuerDomainPolicy or a subjectDomainPolicy.
     */
    public void test4_10_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Mapping From anyPolicy Test7 EE")
            .withCrls("Mapping From anyPolicy CA CRL")
            .withCACert("Mapping From anyPolicy CA Cert")
            .doExceptionTest(1, "IssuerDomainPolicy is anyPolicy");
    }

    /**
     * 4.10.8 Invalid Mapping To anyPolicy Test8
     * <p>
     * In this test, the intermediate certificate includes a policyMappings extension that includes a
     * mapping in which the subjectDomainPolicy is anyPolicy. The intermediate certificate also
     * includes a critical policyConstraints extension with requireExplicitPolicy set to 0.
     * [RFC 3280 6.1.4] (a) If a policy mapping extension is present, verify that the special
     * value anyPolicy does not appear as an issuerDomainPolicy or a subjectDomainPolicy.
     */
    public void test4_10_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Mapping To anyPolicy Test8 EE")
            .withCrls("Mapping To anyPolicy CA CRL")
            .withCACert("Mapping To anyPolicy CA Cert")
            .doExceptionTest(1, "SubjectDomainPolicy is anyPolicy");
    }

    /**
     * 4.10.9 Valid Policy Mapping Test9
     * <p>
     * In this test, the intermediate certificate asserts anyPolicy and maps NIST-test-policy-1 to NISTtest-policy-2. The end entity certificate asserts NIST-test-policy-1.
     * 55
     */
    public void test4_10_9()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test9 EE")
            .withCrls("PanyPolicy Mapping 1to2 CA CRL")
            .withCACert("PanyPolicy Mapping 1to2 CA Cert")
            .doTest();
    }

    /**
     * 4.10.10 Invalid Policy Mapping Test10
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1. The second intermediate
     * certificate asserts anyPolicy and maps NIST-test-policy-1 to NIST-test-policy-2. The end entity
     * certificate asserts NIST-test-policy-1.
     */
    public void test4_10_10()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Policy Mapping Test10 EE")
            .withCrls("Good subCA PanyPolicyMapping 1to2 CA CRL")
            .withCACert("Good subCA PanyPolicy Mapping 1to2 CA Cert")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.10.11 Valid Policy Mapping Test11
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1. The second intermediate
     * certificate asserts anyPolicy and maps NIST-test-policy-1 to NIST-test-policy-2. The end entity
     * certificate asserts NIST-test-policy-2.
     */
    public void test4_10_11()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test11 EE")
            .withCrls("Good subCA PanyPolicyMapping 1to2 CA CRL")
            .withCACert("Good subCA PanyPolicy Mapping 1to2 CA Cert")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .doTest();
    }

    /**
     * 4.10.12 Valid Policy Mapping Test12
     * <p>
     * In this test, the intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
     * maps NIST-test-policy-1 to NIST-test-policy-3. The end entity certificate asserts anyPolicy and
     * NIST-test-policy-3, each with a different user notice policy qualifier. If possible, it is
     * recommended that the certification path in this test be validated using the following inputs:
     * 1. default settings, but with initial-policy-set = {NIST-test-policy-1}. The path
     * should validate successfully and the application should display the user notice
     * associated with NIST-test-policy-3 in the end entity certificate.
     * 2. default settings, but with initial-policy-set = {NIST-test-policy-2}. The path
     * should validate successfully and the application should display the user notice
     * associated with anyPolicy in the end entity certificate.
     */
    public void test4_10_12()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test12 EE")
            .withCrls("P12 Mapping 1to3 CA CRL")
            .withCACert("P12 Mapping 1to3 CA Cert")
            .withPolicyByName("NIST-test-policy-1")
            .doTest();


        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test12 EE")
            .withCrls("P12 Mapping 1to3 CA CRL")
            .withCACert("P12 Mapping 1to3 CA Cert")
            .withPolicyByName("NIST-test-policy-2")
            .doTest();


    }

    /**
     * 4.10.13 Valid Policy Mapping Test13
     * <p>
     * In this test, the intermediate certificate asserts NIST-test-policy-1 and anyPolicy and maps NISTtest-policy-1 to NIST-test-policy-2. There is a user notice policy qualifier associated with each of
     * 57
     * the policies. The end entity certificate asserts NIST-test-policy-2.
     */
    public void test4_10_13()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test13 EE")
            .withCrls("P1anyPolicy Mapping 1to2 CA CRL")
            .withCACert("P1anyPolicy Mapping 1to2 CA Cert")
            .doTest();
    }

    /**
     * 4.10.14 Valid Policy Mapping Test14
     * <p>
     * In this test, the intermediate certificate asserts NIST-test-policy-1 and anyPolicy and maps NISTtest-policy-1 to NIST-test-policy-2. There is a user notice policy qualifier associated with each of
     * the policies. The end entity certificate asserts NIST-test-policy-1.
     */
    public void test4_10_14()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Policy Mapping Test14 EE")
            .withCrls("P1anyPolicy Mapping 1to2 CA CRL")
            .withCACert("P1anyPolicy Mapping 1to2 CA Cert")
            .doTest();
    }

    /**
     * 4.11.1 Invalid inhibitPolicyMapping Test1
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
     * policyConstraints extension with inhibitPolicyMapping set to 0. The second intermediate
     * certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The end
     * entity certificate asserts NIST-test-policy-1 and NIST-test-policy-2.
     */
    public void test4_11_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid inhibitPolicyMapping Test1 EE")
            .withCrls("inhibitPolicyMapping0 subCA CRL")
            .withCACert("inhibitPolicyMapping0 subCA Cert")
            .withCrls("inhibitPolicyMapping0 CA CRL")
            .withCACert("inhibitPolicyMapping0 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.11.2 Valid inhibitPolicyMapping Test2
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
     * includes a policyConstraints extension with inhibitPolicyMapping set to 1. The second
     * intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and maps NIST-testpolicy-1 to NIST-test-policy-3 and NIST-test-policy-2 to NIST-test-policy-4. The end entity
     * certificate asserts NIST-test-policy-3.
     * 59
     */
    public void test4_11_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid inhibitPolicyMapping Test2 EE")
            .withCrls("inhibitPolicyMapping1 P12 subCACRL")
            .withCACert("inhibitPolicyMapping1 P12 subCA Cert")
            .withCrls("inhibitPolicyMapping1 P12 CA CRL")
            .withCACert("inhibitPolicyMapping1 P12 CA Cert")
            .doTest();
    }

    /**
     * 4.11.3 Invalid inhibitPolicyMapping Test3
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
     * includes a policyConstraints extension with inhibitPolicyMapping set to 1. The second
     * intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and maps NIST-testpolicy-1 to NIST-test-policy-3 and NIST-test-policy-2 to NIST-test-policy-4. The third
     * intermediate certificate asserts NIST-test-policy-3 and NIST-test-policy-4 and maps NIST-testpolicy-3 to NIST-test-policy-5. The end entity certificate asserts NIST-test-policy-5.
     */
    public void test4_11_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid inhibitPolicyMapping Test3 EE")
            .withCrls("inhibitPolicyMapping1 P12subsubCA CRL")
            .withCACert("inhibitPolicyMapping1 P12 subsubCA Cert")
            .withCrls("inhibitPolicyMapping1 P12 subCACRL")
            .withCACert("inhibitPolicyMapping1 P12 subCA Cert")
            .withCrls("inhibitPolicyMapping1 P12 CA CRL")
            .withCACert("inhibitPolicyMapping1 P12 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.11.4 Valid inhibitPolicyMapping Test4
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
     * includes a policyConstraints extension with inhibitPolicyMapping set to 1. The second
     * intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and maps NIST-testpolicy-1 to NIST-test-policy-3 and NIST-test-policy-2 to NIST-test-policy-4. The third
     * intermediate certificate asserts NIST-test-policy-3 and NIST-test-policy-4 and maps NIST-testpolicy-3 to NIST-test-policy-5. The end entity certificate asserts NIST-test-policy-4.
     * 60
     */
    public void test4_11_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid inhibitPolicyMapping Test4 EE")
            .withCrls("inhibitPolicyMapping1 P12subsubCA CRL")
            .withCACert("inhibitPolicyMapping1 P12 subsubCA Cert")
            .withCrls("inhibitPolicyMapping1 P12 subCACRL")
            .withCACert("inhibitPolicyMapping1 P12 subCA Cert")
            .withCrls("inhibitPolicyMapping1 P12 CA CRL")
            .withCACert("inhibitPolicyMapping1 P12 CA Cert")
            .doTest();
    }

    /**
     * 4.11.5 Invalid inhibitPolicyMapping Test5
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
     * policyConstraints extension with inhibitPolicyMapping set to 5. The second intermediate
     * certificate asserts NIST-test-policy-1 and includes a policyConstraints extension with
     * inhibitPolicyMapping set to 1. The third intermediate certificate asserts NIST-test-policy-1. The
     * fourth intermediate certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NISTtest-policy-2. The end entity certificate asserts NIST-test-policy-2.
     */
    public void test4_11_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid inhibitPolicyMapping Test5 EE")
            .withCrls("inhibitPolicyMapping5subsubsubCA CRL")
            .withCACert("inhibitPolicyMapping5 subsubsubCA Cert")
            .withCrls("inhibitPolicyMapping5 subsubCA CRL")
            .withCACert("inhibitPolicyMapping5 subsubCA Cert")
            .withCrls("inhibitPolicyMapping5 subCA CRL")
            .withCACert("inhibitPolicyMapping5 subCA Cert")
            .withCrls("inhibitPolicyMapping5 CA CRL")
            .withCACert("inhibitPolicyMapping5 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.11.6 Invalid inhibitPolicyMapping Test6
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and
     * includes a policyConstraints extension with inhibitPolicyMapping set to 1. The second
     * intermediate certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and includes a
     * policyConstraints extension with inhibitPolicyMapping set to 5. The third intermediate
     * certificate asserts NIST-test-policy-1 and NIST-test-policy-2 and maps NIST-test-policy-1 to
     * NIST-test-policy-3. The end entity certificate asserts NIST-test-policy-3.
     * 61
     */
    public void test4_11_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid inhibitPolicyMapping Test6 EE")
            .withCrls("inhibitPolicyMapping1 P12subsubCAIPM5 CRL")
            .withCACert("inhibitPolicyMapping1 P12 subsubCAIPM5 Cert")
            .withCrls("inhibitPolicyMapping1 P12subCAIPM5 CRL")
            .withCACert("inhibitPolicyMapping1 P12 subCAIPM5 Cert")
            .withCrls("inhibitPolicyMapping1 P12 CA CRL")
            .withCACert("inhibitPolicyMapping1 P12 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.11.7 Valid Self-Issued inhibitPolicyMapping Test7
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
     * policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
     * certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
     * certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The end
     * entity certificate asserts NIST-test-policy-2.
     */
    public void test4_11_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid SelfIssued inhibitPolicyMapping Test7 EE")
            .withCrls("inhibitPolicyMapping1 P1 subCA CRL")
            .withCACert("inhibitPolicyMapping1 P1 subCA Cert")
            .withCACert("inhibitPolicyMapping1 P1 SelfIssued CA Cert")
            .withCrls("inhibitPolicyMapping1 P1 CA CRL")
            .withCACert("inhibitPolicyMapping1 P1 CA Cert")
            .doTest();
    }

    /**
     * 4.11.8 Invalid Self-Issued inhibitPolicyMapping Test8
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
     * policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
     * certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
     * certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The
     * fourth intermediate certificate asserts NIST-test-policy-2 and maps NIST-test-policy-2 to NISTtest-policy-3. The end entity certificate asserts NIST-test-policy-3.
     * 62
     */
    public void test4_11_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid SelfIssued inhibitPolicyMapping Test8 EE")
            .withCrls("inhibitPolicyMapping1 P1 subsubCACRL")
            .withCACert("inhibitPolicyMapping1 P1 subsubCA Cert")
            .withCrls("inhibitPolicyMapping1 P1 subCA CRL")
            .withCACert("inhibitPolicyMapping1 P1 subCA Cert")
            .withCACert("inhibitPolicyMapping1 P1 SelfIssued CA Cert")
            .withCrls("inhibitPolicyMapping1 P1 CA CRL")
            .withCACert("inhibitPolicyMapping1 P1 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.11.9 Invalid Self-Issued inhibitPolicyMapping Test9
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
     * policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
     * certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
     * certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The
     * fourth intermediate certificate asserts NIST-test-policy-2 and maps NIST-test-policy-2 to NISTtest-policy-3. The end entity certificate asserts NIST-test-policy-2.
     */
    public void test4_11_9()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid SelfIssued inhibitPolicyMapping Test9 EE")
            .withCrls("inhibitPolicyMapping1 P1 subsubCACRL")
            .withCACert("inhibitPolicyMapping1 P1 subsubCA Cert")
            .withCrls("inhibitPolicyMapping1 P1 subCA CRL")
            .withCACert("inhibitPolicyMapping1 P1 subCA Cert")
            .withCACert("inhibitPolicyMapping1 P1 SelfIssued CA Cert")
            .withCrls("inhibitPolicyMapping1 P1 CA CRL")
            .withCACert("inhibitPolicyMapping1 P1 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.11.10 Invalid Self-Issued inhibitPolicyMapping Test10
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
     * policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
     * certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
     * certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The
     * fourth intermediate certificate is a self-issued certificate that asserts NIST-test-policy-2 and maps
     * NIST-test-policy-2 to NIST-test-policy-3. The end entity certificate asserts NIST-test-policy-3.
     * 63
     */
    public void test4_11_10()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid SelfIssued inhibitPolicyMapping Test10 EE")
            .withCACert("inhibitPolicyMapping1 P1 SelfIssued subCA Cert")
            .withCrls("inhibitPolicyMapping1 P1 subCA CRL")
            .withCACert("inhibitPolicyMapping1 P1 subCA Cert")
            .withCACert("inhibitPolicyMapping1 P1 SelfIssued CA Cert")
            .withCrls("inhibitPolicyMapping1 P1 CA CRL")
            .withCACert("inhibitPolicyMapping1 P1 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.11.11 Invalid Self-Issued inhibitPolicyMapping Test11
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes a
     * policyConstraints extension with inhibitPolicyMapping set to 1. The second intermediate
     * certificate is a self-issued certificate that asserts NIST-test-policy-1. The third intermediate
     * certificate asserts NIST-test-policy-1 and maps NIST-test-policy-1 to NIST-test-policy-2. The
     * fourth intermediate certificate is a self-issued certificate that asserts NIST-test-policy-2 and maps
     * NIST-test-policy-2 to NIST-test-policy-3. The end entity certificate asserts NIST-test-policy-2.
     */
    public void test4_11_11()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid SelfIssued inhibitPolicyMapping Test11 EE")
            .withCACert("inhibitPolicyMapping1 P1 SelfIssued subCA Cert")
            .withCrls("inhibitPolicyMapping1 P1 subCA CRL")
            .withCACert("inhibitPolicyMapping1 P1 subCA Cert")
            .withCACert("inhibitPolicyMapping1 P1 SelfIssued CA Cert")
            .withCrls("inhibitPolicyMapping1 P1 CA CRL")
            .withCACert("inhibitPolicyMapping1 P1 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.12.1 Invalid inhibitAnyPolicy Test1
     * <p>
     * In this test, the intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 0. The end entity certificate asserts anyPolicy.
     */
    public void test4_12_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid inhibitAnyPolicy Test1 EE")
            .withCrls("inhibitAnyPolicy0 CA CRL")
            .withCACert("inhibitAnyPolicy0 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.12.2 Valid inhibitAnyPolicy Test2
     * <p>
     * In this test, the intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 0. The end entity certificate asserts anyPolicy and NIST-testpolicy-1.
     */
    public void test4_12_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid inhibitAnyPolicy Test2 EE")
            .withCrls("inhibitAnyPolicy0 CA CRL")
            .withCACert("inhibitAnyPolicy0 CA Cert")
            .doTest();
    }

    /**
     * 4.12.3 inhibitAnyPolicy Test3
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 1. The second intermediate certificate asserts anyPolicy. The
     * end entity certificate asserts NIST-test-policy-1. If possible, it is recommended that the
     * certification path in this test be validated using the following inputs:
     * 1. default settings. The path should validate successfully.
     * 2. default settings, but with initial-inhibit-any-policy set. The path should not
     * validate successfully.
     */
    public void test4_12_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("inhibitAnyPolicy Test3 EE")
            .withCrls("inhibitAnyPolicy1 subCA1 CRL")
            .withCACert("inhibitAnyPolicy1 subCA1 Cert")
            .withCrls("inhibitAnyPolicy1 CA CRL")
            .withCACert("inhibitAnyPolicy1 CA Cert")
            .doTest();


        new PKITSTest()
            .withEndEntity("inhibitAnyPolicy Test3 EE")
            .withCrls("inhibitAnyPolicy1 subCA1 CRL")
            .withCACert("inhibitAnyPolicy1 subCA1 Cert")
            .withCrls("inhibitAnyPolicy1 CA CRL")
            .withCACert("inhibitAnyPolicy1 CA Cert")
            .withInhibitAnyPolicy(true)
            .doExceptionTest(1, "No valid policy tree found when one expected.");
    }

    /**
     * 4.12.4 Invalid inhibitAnyPolicy Test4
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 1. The second intermediate certificate asserts anyPolicy. The
     * end entity certificate asserts anyPolicy.
     * 66
     */
    public void test4_12_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid inhibitAnyPolicy Test4 EE")
            .withCrls("inhibitAnyPolicy1 subCA1 CRL")
            .withCACert("inhibitAnyPolicy1 subCA1 Cert")
            .withCrls("inhibitAnyPolicy1 CA CRL")
            .withCACert("inhibitAnyPolicy1 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.12.5 Invalid inhibitAnyPolicy Test5
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 5. The second intermediate certificate asserts NIST-test-policy1 and includes an inhibitAnyPolicy extension set to 1. The third intermediate certificate asserts
     * NIST-test-policy-1 and the end entity certificate asserts anyPolicy.
     */
    public void test4_12_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid inhibitAnyPolicy Test5 EE")
            .withCrls("inhibitAnyPolicy5 subsubCA CRL")
            .withCACert("inhibitAnyPolicy5 subsubCA Cert")
            .withCrls("inhibitAnyPolicy5 subCA CRL")
            .withCACert("inhibitAnyPolicy5 subCA Cert")
            .withCrls("inhibitAnyPolicy5 CA CRL")
            .withCACert("inhibitAnyPolicy5 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.12.6 Invalid inhibitAnyPolicy Test6
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 1. The second intermediate certificate asserts NIST-test-policy1 and includes an inhibitAnyPolicy extension set to 5. The end entity certificate asserts
     * anyPolicy.
     */
    public void test4_12_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid inhibitAnyPolicy Test6 EE")
            .withCrls("inhibitAnyPolicy1 subCAIAP5 CRL")
            .withCACert("inhibitAnyPolicy1 subCAIAP5 Cert")
            .withCrls("inhibitAnyPolicy1 CA CRL")
            .withCACert("inhibitAnyPolicy1 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.12.7 Valid Self-Issued inhibitAnyPolicy Test7
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 1. The second intermediate certificate is a self-issued certificate
     * that asserts NIST-test-policy-1. The third intermediate certificate asserts anyPolicy and the end
     * entity certificate asserts NIST-test-policy-1.
     */
    public void test4_12_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid SelfIssued inhibitAnyPolicy Test7 EE")
            .withCrls("inhibitAnyPolicy1 subCA2 CRL")
            .withCACert("inhibitAnyPolicy1 subCA2 Cert")
            .withCACert("inhibitAnyPolicy1 SelfIssued CA Cert")
            .withCrls("inhibitAnyPolicy1 CA CRL")
            .withCACert("inhibitAnyPolicy1 CA Cert")
            .doTest();
    }

    /**
     * 4.12.8 Invalid Self-Issued inhibitAnyPolicy Test8
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 1. The second intermediate certificate is a self-issued certificate
     * that asserts NIST-test-policy-1. The third and fourth intermediate certificates assert anyPolicy
     * and the end entity certificate asserts NIST-test-policy-1.
     * 68
     */
    public void test4_12_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid SelfIssued inhibitAnyPolicy Test8 EE")
            .withCrls("inhibitAnyPolicy1 subsubCA2 CRL")
            .withCACert("inhibitAnyPolicy1 subsubCA2 Cert")
            .withCrls("inhibitAnyPolicy1 subCA2 CRL")
            .withCACert("inhibitAnyPolicy1 subCA2 Cert")
            .withCACert("inhibitAnyPolicy1 SelfIssued CA Cert")
            .withCrls("inhibitAnyPolicy1 CA CRL")
            .withCACert("inhibitAnyPolicy1 CA Cert")
            .doExceptionTest(1, "No valid policy tree found when one expected.");
    }

    /**
     * 4.12.9 Valid Self-Issued inhibitAnyPolicy Test9
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 1. The second intermediate certificate is a self-issued certificate
     * that asserts NIST-test-policy-1. The third intermediate certificate asserts anyPolicy. The fourth
     * intermediate certificate is a self-issued certificate that asserts anyPolicy. The end entity certificate
     * asserts NIST-test-policy-1.
     */
    public void test4_12_9()
        throws Exception
    {
        new PKITSTest()
            .withPolicyByName("NIST-test-policy-1")
            .withEndEntity("Valid SelfIssued inhibitAnyPolicy Test9 EE")
            .withCACert("inhibitAnyPolicy1 SelfIssued subCA2 Cert")
            .withCrls("inhibitAnyPolicy1 subCA2 CRL")
            .withCACert("inhibitAnyPolicy1 subCA2 Cert")
            .withCACert("inhibitAnyPolicy1 SelfIssued CA Cert")
            .withCrls("inhibitAnyPolicy1 CA CRL")
            .withCACert("inhibitAnyPolicy1 CA Cert")
            .doTest();
    }

    /**
     * 4.12.10 Invalid Self-Issued inhibitAnyPolicy Test10
     * <p>
     * In this test, the first intermediate certificate asserts NIST-test-policy-1 and includes an
     * inhibitAnyPolicy extension set to 1. The second intermediate certificate is a self-issued certificate
     * that asserts NIST-test-policy-1. The third intermediate certificate asserts anyPolicy. The end
     * entity certificate is a self-issued CA certificate that asserts anyPolicy.
     */
    public void test4_12_10()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid SelfIssued inhibitAnyPolicy Test10 EE")
            .withCrls("inhibitAnyPolicy1 subCA2 CRL")
            .withCACert("inhibitAnyPolicy1 subCA2 Cert")
            .withCACert("inhibitAnyPolicy1 SelfIssued CA Cert")
            .withCrls("inhibitAnyPolicy1 CA CRL")
            .withCACert("inhibitAnyPolicy1 CA Cert")
            .doExceptionTest(0, "No valid policy tree found when one expected.");
    }

    /**
     * 4.13.1 Valid DN nameConstraints Test1
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subject name that falls within that
     * subtree.
     * 70
     */
    public void test4_13_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DN nameConstraints Test1 EE")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doTest();
    }

    /**
     * 4.13.2 Invalid DN nameConstraints Test2
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subject name that falls outside that
     * subtree.
     */
    public void test4_13_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test2 EE")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.3 Invalid DN nameConstraints Test3
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subject name that falls within that
     * subtree and a subjectAltName extension with a DN that falls outside the subtree.
     */
    public void test4_13_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test3 EE")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.13.4 Valid DN nameConstraints Test4
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subject name that falls within that
     * subtree and a subjectAltName extension with an e-mail address.
     * 71
     */
    public void test4_13_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DN nameConstraints Test4 EE")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doTest();
    }

    /**
     * 4.13.5 Valid DN nameConstraints Test5
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies two
     * permitted subtrees. The end entity certificate includes a subject name that falls within one of the
     * subtrees and a subjectAltName extension with a DN that falls within the other subtree.
     */
    public void test4_13_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DN nameConstraints Test5 EE")
            .withCrls("nameConstraints DN2 CA CRL")
            .withCACert("nameConstraints DN2 CA Cert")
            .doTest();
    }

    /**
     * 4.13.6 Valid DN nameConstraints Test6
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The end entity certificate includes a subject name that falls outside that
     * subtree.
     */
    public void test4_13_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DN nameConstraints Test6 EE")
            .withCrls("nameConstraints DN3 CA CRL")
            .withCACert("nameConstraints DN3 CA Cert")
            .doTest();
    }

    /**
     * 4.13.7 Invalid DN nameConstraints Test7
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The end entity certificate includes a subject name that falls within that
     * subtree.
     * 72
     */
    public void test4_13_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test7 EE")
            .withCrls("nameConstraints DN3 CA CRL")
            .withCACert("nameConstraints DN3 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.8 Invalid DN nameConstraints Test8
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies two
     * excluded subtrees. The end entity certificate includes a subject name that falls within the first
     * subtree.
     */
    public void test4_13_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test8 EE")
            .withCrls("nameConstraints DN4 CA CRL")
            .withCACert("nameConstraints DN4 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.9 Invalid DN nameConstraints Test9
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies two
     * excluded subtrees. The end entity certificate includes a subject name that falls within the second
     * subtree.
     */
    public void test4_13_9()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test9 EE")
            .withCrls("nameConstraints DN4 CA CRL")
            .withCACert("nameConstraints DN4 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.10 Invalid DN nameConstraints Test10
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * permitted subtree and an excluded subtree. The excluded subtree specifies a subset of the name
     * space specified by the permitted subtree. The end entity certificate includes a subject name that
     * falls within both the permitted and excluded subtrees.
     * 73
     */
    public void test4_13_10()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test10 EE")
            .withCrls("nameConstraints DN5 CA CRL")
            .withCACert("nameConstraints DN5 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.11 Valid DN nameConstraints Test11
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * permitted subtree and an excluded subtree. The excluded subtree specifies a subset of the name
     * space specified by the permitted subtree. The end entity certificate includes a subject name that
     * falls within the permitted subtree but falls outside the excluded subtree.
     */
    public void test4_13_11()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DN nameConstraints Test11 EE")
            .withCrls("nameConstraints DN5 CA CRL")
            .withCACert("nameConstraints DN5 CA Cert")
            .doTest();
    }

    /**
     * 4.13.12 Invalid DN nameConstraints Test12
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The second intermediate certificate includes a subject name that falls
     * within that subtree and a nameConstraints extension that specifies a permitted subtree that is a
     * subtree of the constraint specified in the first intermediate certificate. The end entity certificate
     * includes a subject name that falls within the subtree specified by the first intermediate certificate
     * but outside the subtree specified by the second intermediate certificate.
     */
    public void test4_13_12()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test12 EE")
            .withCrls("nameConstraints DN1 subCA1 CRL")
            .withCACert("nameConstraints DN1 subCA1 Cert")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.13 Invalid DN nameConstraints Test13
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The second intermediate certificate includes a subject name that falls
     * within that subtree and a nameConstraints extension that specifies a permitted subtree that does
     * not overlap with the permitted subtree specified in the first intermediate certificate. The end entity
     * certificate includes a subject name that falls within the subtree specified by the first intermediate
     * certificate.
     */
    public void test4_13_13()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test13 EE")
            .withCrls("nameConstraints DN1 subCA2 CRL")
            .withCACert("nameConstraints DN1 subCA2 Cert")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.14 Valid DN nameConstraints Test14
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The second intermediate certificate includes a subject name that falls
     * within that subtree and a nameConstraints extension that specifies a permitted subtree that does
     * not overlap with the permitted subtree specified in the first intermediate certificate. The end entity
     * certificate has a null subject name (i.e., the subject name is a sequence of zero relative
     * distinguished names) and a critical subjectAltName extension with an e-mail address.
     */
    public void test4_13_14()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DN nameConstraints Test14 EE")
            .withCrls("nameConstraints DN1 subCA2 CRL")
            .withCACert("nameConstraints DN1 subCA2 Cert")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doTest();
    }

    /**
     * 4.13.15 Invalid DN nameConstraints Test15
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The second intermediate certificate has a subject name that falls outside
     * that subtree and includes a nameConstraints extension that specifies an excluded subtree that
     * does not overlap with the subtree specified in the first intermediate certificate. The end entity
     * certificate includes a subject name that falls within the subtree specified in the first intermediate
     * certificate.
     */
    public void test4_13_15()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test15 EE")
            .withCrls("nameConstraints DN3 subCA1 CRL")
            .withCACert("nameConstraints DN3 subCA1 Cert")
            .withCrls("nameConstraints DN3 CA CRL")
            .withCACert("nameConstraints DN3 CA Cert")
            .doExceptionTest(00, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.16 Invalid DN nameConstraints Test16
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The second intermediate certificate has a subject name that falls outside
     * that subtree and includes a nameConstraints extension that specifies an excluded subtree that
     * does not overlap with the subtree specified in the first intermediate certificate. The end entity
     * certificate includes a subject name that falls within the subtree specified in the second intermediate
     * certificate.
     */
    public void test4_13_16()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test16 EE")
            .withCrls("nameConstraints DN3 subCA1 CRL")
            .withCACert("nameConstraints DN3 subCA1 Cert")
            .withCrls("nameConstraints DN3 CA CRL")
            .withCACert("nameConstraints DN3 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.17 Invalid DN nameConstraints Test17
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The second intermediate certificate has a subject name that falls outside
     * that subtree and includes a nameConstraints extension that specifies a permitted subtree that is a
     * superset of the subtree specified in the first intermediate certificate. The end entity certificate
     * includes a subject name that falls within the excluded subtree specified in the first intermediate
     * certificate.
     */
    public void test4_13_17()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test17 EE")
            .withCrls("nameConstraints DN3 subCA2 CRL")
            .withCACert("nameConstraints DN3 subCA2 Cert")
            .withCrls("nameConstraints DN3 CA CRL")
            .withCACert("nameConstraints DN3 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.18 Valid DN nameConstraints Test18
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The second intermediate certificate has a subject name that falls outside
     * that subtree and includes a nameConstraints extension that specifies a permitted subtree that is a
     * superset of the subtree specified in the first intermediate certificate. The end entity certificate
     * includes a subject name that falls within the permitted subtree specified in the second intermediate
     * certificate but outside the excluded subtree specified in the first intermediate certificate.
     */
    public void test4_13_18()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DN nameConstraints Test18 EE")
            .withCrls("nameConstraints DN3 subCA2 CRL")
            .withCACert("nameConstraints DN3 subCA2 Cert")
            .withCrls("nameConstraints DN3 CA CRL")
            .withCACert("nameConstraints DN3 CA Cert")
            .doTest();
    }

    /**
     * 4.13.19 Valid Self-Issued DN nameConstraints Test19
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The second intermediate certificate is a self-issued certificate. The
     * subject name in the self-issued certificate does not fall within the permitted subtree specified in the
     * first intermediate certificate. The end entity certificate includes a subject name that falls within the
     * permitted subtree specified in the first intermediate certificate.
     */
    public void test4_13_19()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DN nameConstraints Test19 EE")
            .withCACert("nameConstraints DN1 SelfIssued CA Cert")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doTest();
    }

    /**
     * 4.13.20 Invalid Self-Issued DN nameConstraints Test20
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate is a self-issued certificate. The subject name in
     * the self-issued certificate does not fall within the permitted subtree specified in the intermediate
     * certificate.
     */
    public void test4_13_20()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN nameConstraints Test20 EE")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject failed.");
    }

    /**
     * 4.13.21 Valid RFC822 nameConstraints Test21
     * <p>
     * �
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subjectAltName extension with an
     * e-mail address that falls within that subtree.
     */
    public void test4_13_21()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid RFC822 nameConstraints Test21 EE")
            .withCrls("nameConstraints RFC822 CA1 CRL")
            .withCACert("nameConstraints RFC822 CA1 Cert")
            .doTest();
    }

    /**
     * 4.13.22 Invalid RFC822 nameConstraints Test22
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subjectAltName extension with an
     * e-mail address that falls outside that subtree.
     */
    public void test4_13_22()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid RFC822 nameConstraints Test22 EE")
            .withCrls("nameConstraints RFC822 CA1 CRL")
            .withCACert("nameConstraints RFC822 CA1 Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.13.23 Valid RFC822 nameConstraints Test23
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subjectAltName extension with an
     * e-mail address that falls within that subtree.
     */
    public void test4_13_23()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid RFC822 nameConstraints Test23 EE")
            .withCrls("nameConstraints RFC822 CA2 CRL")
            .withCACert("nameConstraints RFC822 CA2 Cert")
            .doTest();
    }

    /**
     * 4.13.24 Invalid RFC822 nameConstraints Test24
     * <p>
     * �
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subjectAltName extension with an
     * e-mail address that falls outside that subtree.
     */
    public void test4_13_24()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid RFC822 nameConstraints Test24 EE")
            .withCrls("nameConstraints RFC822 CA2 CRL")
            .withCACert("nameConstraints RFC822 CA2 Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.13.25 Valid RFC822 nameConstraints Test25
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The end entity certificate includes a subjectAltName extension with an
     * e-mail address that falls outside that subtree.
     */
    public void test4_13_25()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid RFC822 nameConstraints Test25 EE")
            .withCrls("nameConstraints RFC822 CA3 CRL")
            .withCACert("nameConstraints RFC822 CA3 Cert")
            .doTest();
    }

    /**
     * 4.13.26 Invalid RFC822 nameConstraints Test26
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The end entity certificate includes a subjectAltName extension with an
     * e-mail address that falls within that subtree.
     */
    public void test4_13_26()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid RFC822 nameConstraints Test26 EE")
            .withCrls("nameConstraints RFC822 CA3 CRL")
            .withCACert("nameConstraints RFC822 CA3 Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.13.27 Valid DN and RFC822 nameConstraints Test27
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree of type directoryName. The second intermediate certificate includes a
     * subject name that falls within that subtree and a nameConstraints extension that specifies a
     * permitted subtree of type rfc822Name. The end entity certificate includes a subject name that falls
     * within the subtree specified by the first intermediate certificate and an e-mail address that falls
     * within the permitted subtree specified by the second intermediate certificate.
     */
    public void test4_13_27()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DN and RFC822 nameConstraints Test27 EE")
            .withCrls("nameConstraints DN1 subCA3 CRL")
            .withCACert("nameConstraints DN1 subCA3 Cert")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doTest();
    }

    /**
     * 4.13.28 Invalid DN and RFC822 nameConstraints Test28
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree of type directoryName. The second intermediate certificate includes a
     * subject name that falls within that subtree and a nameConstraints extension that specifies a
     * permitted subtree of type rfc822Name. The end entity certificate includes a subject name that falls
     * within the subtree specified by the first intermediate certificate and an e-mail address that falls
     * outside the permitted subtree specified by the second intermediate certificate.
     */
    public void test4_13_28()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN and RFC822 nameConstraints Test28 EE")
            .withCrls("nameConstraints DN1 subCA3 CRL")
            .withCACert("nameConstraints DN1 subCA3 Cert")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.13.29 Invalid DN and RFC822 nameConstraints Test29
     * <p>
     * In this test, the first intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree of type directoryName. The second intermediate certificate includes a
     * subject name that falls within that subtree and a nameConstraints extension that specifies a
     * permitted subtree of type rfc822Name. The end entity certificate includes a subject name that falls
     * within the subtree specified by the first intermediate certificate but the subject name includes an
     * attribute of type EmailAddress whose value falls outside the permitted subtree specified in the
     * second intermediate certificate.
     */
    public void test4_13_29()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DN and RFC822 nameConstraints Test29 EE")
            .withCrls("nameConstraints DN1 subCA3 CRL")
            .withCACert("nameConstraints DN1 subCA3 Cert")
            .withCrls("nameConstraints DN1 CA CRL")
            .withCACert("nameConstraints DN1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative email failed.");
    }

    /**
     * 4.13.30 Valid DNS nameConstraints Test30
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subjectAltName extension with a
     * dNSName that falls within that subtree.
     */
    public void test4_13_30()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DNS nameConstraints Test30 EE")
            .withCrls("nameConstraints DNS1 CA CRL")
            .withCACert("nameConstraints DNS1 CA Cert")
            .doTest();
    }

    /**
     * 4.13.31 Invalid DNS nameConstraints Test31
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subjectAltName extension with a
     * dNSName that falls outside that subtree.
     */
    public void test4_13_31()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DNS nameConstraints Test31 EE")
            .withCrls("nameConstraints DNS1 CA CRL")
            .withCACert("nameConstraints DNS1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.13.32 Valid DNS nameConstraints Test32
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The end entity certificate includes a subjectAltName extension with a
     * dNSName that falls outside that subtree.
     */
    public void test4_13_32()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid DNS nameConstraints Test32 EE")
            .withCrls("nameConstraints DNS2 CA CRL")
            .withCACert("nameConstraints DNS2 CA Cert")
            .doTest();
    }

    /**
     * 4.13.33 Invalid DNS nameConstraints Test33
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The end entity certificate includes a subjectAltName extension with a
     * dNSName that falls within that subtree.
     */
    public void test4_13_33()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DNS nameConstraints Test33 EE")
            .withCrls("nameConstraints DNS2 CA CRL")
            .withCACert("nameConstraints DNS2 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.13.34 Valid URI nameConstraints Test34
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subjectAltName extension with a
     * uniformResourceIdentifier that falls within that subtree.
     */
    public void test4_13_34()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid URI nameConstraints Test34 EE")
            .withCrls("nameConstraints URI1 CA CRL")
            .withCACert("nameConstraints URI1 CA Cert")
            .doTest();
    }

    /**
     * 4.13.35 Invalid URI nameConstraints Test35
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subjectAltName extension with a
     * uniformResourceIdentifier that falls outside that subtree.
     */
    public void test4_13_35()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid URI nameConstraints Test35 EE")
            .withCrls("nameConstraints URI1 CA CRL")
            .withCACert("nameConstraints URI1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.13.36 Valid URI nameConstraints Test36
     * <p>
     * �
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The end entity certificate includes a subjectAltName extension with a
     * uniformResourceIdentifier that falls outside that subtree.
     */
    public void test4_13_36()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid URI nameConstraints Test36 EE")
            .withCrls("nameConstraints URI2 CA CRL")
            .withCACert("nameConstraints URI2 CA Cert")
            .doTest();
    }

    /**
     * 4.13.37 Invalid URI nameConstraints Test37
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single excluded subtree. The end entity certificate includes a subjectAltName extension with a
     * uniformResourceIdentifier that falls within that subtree.
     */
    public void test4_13_37()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid URI nameConstraints Test37 EE")
            .withCrls("nameConstraints URI2 CA CRL")
            .withCACert("nameConstraints URI2 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.13.38 Invalid DNS nameConstraints Test38
     * <p>
     * In this test, the intermediate certificate includes a nameConstraints extension that specifies a
     * single permitted subtree. The end entity certificate includes a subjectAltName extension with a
     * dNSName that falls outside that subtree. The permitted subtree is “testcertificates.gov” and the
     * subjectAltName is “mytestcertificates.gov”.
     */
    public void test4_13_38()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid DNS nameConstraints Test38 EE")
            .withCrls("nameConstraints DNS1 CA CRL")
            .withCACert("nameConstraints DNS1 CA Cert")
            .doExceptionTest(0, "Subtree check for certificate subject alternative name failed.");
    }

    /**
     * 4.14.1 Valid distributionPoint Test1
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
     * DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
     * covers the end entity certificate includes an issuingDistributionPoint extension with a matching
     * distributionPoint.
     */
    public void test4_14_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid distributionPoint Test1 EE")
            .withCrls("distributionPoint1 CA CRL")
            .withCACert("distributionPoint1 CA Cert")
            .doTest();
    }

    /**
     * 4.14.2 Invalid distributionPoint Test2
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
     * DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
     * covers the end entity certificate includes an issuingDistributionPoint extension with a matching
     * distributionPoint. The CRL lists the end entity certificate as being revoked.
     */
    public void test4_14_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid distributionPoint Test2 EE")
            .withCrls("distributionPoint1 CA CRL")
            .withCACert("distributionPoint1 CA Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.14.3 Invalid distributionPoint Test3
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
     * DistributionPoint consisting of a distributionPoint with a distinguished name. The only CRL
     * available from the issuer of the end entity certificate includes an issuingDistributionPoint
     * extension with a distributionPoint that does not match the distributionPoint specified in the end
     * entity certificate.
     */
    public void test4_14_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid distributionPoint Test3 EE")
            .withCrls("distributionPoint1 CA CRL")
            .withCACert("distributionPoint1 CA Cert")
            .doExceptionTest(0, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
    }

    /**
     * 4.14.4 Valid distributionPoint Test4
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
     * DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
     * covers the end entity certificate includes an issuingDistributionPoint extension with a matching
     * distributionPoint. The distributionPoint in the end entity certificate is specified as a
     * nameRelativeToCRLIssuer while the distributionPoint in the CRL is specified as a fullName.
     */
    public void test4_14_4()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid distributionPoint Test4 EE")
            .withCrls("distributionPoint1 CA CRL")
            .withCACert("distributionPoint1 CA Cert")
            .doTest();
    }

    /**
     * 4.14.5 Valid distributionPoint Test5
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
     * DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
     * covers the end entity certificate includes an issuingDistributionPoint extension with a matching
     * distributionPoint. The distributionPoint in both the end entity certificate and the CRL are
     * specified as a nameRelativeToCRLIssuer.
     * 85
     */
    public void test4_14_5()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid distributionPoint Test5 EE")
            .withCrls("distributionPoint2 CA CRL")
            .withCACert("distributionPoint2 CA Cert")
            .doTest();
    }

    /**
     * 4.14.6 Invalid distributionPoint Test6
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
     * DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
     * covers the end entity certificate includes an issuingDistributionPoint extension with a matching
     * distributionPoint. The distributionPoint in both the end entity certificate and the CRL are
     * specified as a nameRelativeToCRLIssuer. The CRL lists the end entity certificate as being
     * revoked.
     */
    public void test4_14_6()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid distributionPoint Test6 EE")
            .withCrls("distributionPoint2 CA CRL")
            .withCACert("distributionPoint2 CA Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.14.7 Valid distributionPoint Test7
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
     * DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
     * covers the end entity certificate includes an issuingDistributionPoint extension with a matching
     * distributionPoint. The distributionPoint in the CRL is specified as a
     * nameRelativeToCRLIssuer and the distributionPoint in the end entity certificate is specified as
     * a fullName.
     */
    public void test4_14_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid distributionPoint Test7 EE")
            .withCrls("distributionPoint2 CA CRL")
            .withCACert("distributionPoint2 CA Cert")
            .doTest();
    }

    /**
     * 4.14.8 Invalid distributionPoint Test8
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a single
     * DistributionPoint consisting of a distributionPoint with a distinguished name. The CRL that
     * covers the end entity certificate includes an issuingDistributionPoint extension with a
     * distributionPoint that does not match. The distributionPoint in the CRL is specified as a
     * nameRelativeToCRLIssuer and the distributionPoint in the end entity certificate is specified as
     * a fullName.
     */
    public void test4_14_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid distributionPoint Test8 EE")
            .withCrls("distributionPoint2 CA CRL")
            .withCACert("distributionPoint2 CA Cert")
            .doExceptionTest(0, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
    }

    /**
     * 4.14.9 Invalid distributionPoint Test9
     * <p>
     * In this test, the CRL that covers the end entity certificate includes an issuingDistributionPoint
     * extension with a distributionPoint. The distributionPoint does not match the CRL issuer's
     * name. The end entity certificate does not include a cRLDistributionPoints extension
     */
    public void test4_14_9()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid distributionPoint Test9 EE")
            .withCrls("distributionPoint2 CA CRL")
            .withCACert("distributionPoint2 CA Cert")
            .doExceptionTest(0, "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
    }

    /**
     * 4.14.10 Valid No issuingDistributionPoint Test10
     * <p>
     * In this test, the CRL that covers the end entity certificate does not include an
     * issuingDistributionPoint extension. The end entity certificate includes a
     * cRLDistributionPoints extension with a distributionPoint name.
     */
    public void test4_14_10()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid No issuingDistributionPoint Test10 EE")
            .withCrls("No issuingDistributionPoint CA CRL")
            .withCACert("No issuingDistributionPoint CA Cert")
            .doTest();
    }

    /**
     * 4.14.11 Invalid onlyContainsUserCerts CRL Test11
     * <p>
     * In this test, the only CRL issued by the intermediate CA includes an issuingDistributionPoint
     * extension with onlyContainsUserCerts set to TRUE. The final certificate in the path is a CA
     * certificate.
     */
    public void test4_14_11()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid onlyContainsUserCerts Test11 EE")
            .withCrls("onlyContainsUserCerts CA CRL")
            .withCACert("onlyContainsUserCerts CA Cert")
            .doExceptionTest(0, "CA Cert CRL only contains user certificates.");
    }

    /**
     * 4.14.12 Invalid onlyContainsCACerts CRL Test12
     * <p>
     * In this test, the only CRL issued by the intermediate CA includes an issuingDistributionPoint
     * extension with onlyContainsCACerts set to TRUE.
     */
    public void test4_14_12()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid onlyContainsCACerts Test12 EE")
            .withCrls("onlyContainsCACerts CA CRL")
            .withCACert("onlyContainsCACerts CA Cert")
            .doExceptionTest(0, "End CRL only contains CA certificates.");
    }

    /**
     * 4.14.13 Valid onlyContainsCACerts CRL Test13
     * <p>
     * In this test, the only CRL issued by the intermediate CA includes an issuingDistributionPoint
     * extension with onlyContainsCACerts set to TRUE. The final certificate in the path is a CA
     * certificate.
     */
    public void test4_14_13()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid onlyContainsCACerts Test13 EE")
            .withCrls("onlyContainsCACerts CA CRL")
            .withCACert("onlyContainsCACerts CA Cert")
            .doTest();
    }

    /**
     * 4.14.14 Invalid onlyContainsAttributeCerts Test14
     * <p>
     * In this test, the only CRL issued by the intermediate CA includes an issuingDistributionPoint
     * extension with onlyContainsAttributeCerts set to TRUE.
     */
    public void test4_14_14()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid onlyContainsAttributeCerts Test14 EE")
            .withCrls("onlyContainsAttributeCerts CA CRL")
            .withCACert("onlyContainsAttributeCerts CA Cert")
            .doExceptionTest(0, "onlyContainsAttributeCerts boolean is asserted.");
    }

    /**
     * 4.14.15 Invalid onlySomeReasons Test15
     * <p>
     * In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
     * and cACompromise reason codes and the other covering the remaining reason codes. The end
     * entity certificate has been revoked for key compromise.
     */
    public void test4_14_15()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid onlySomeReasons Test15 EE")
            .withCrls("onlySomeReasons CA1 other reasons CRL")
            .withCrls("onlySomeReasons CA1 compromise CRL")
            .withCACert("onlySomeReasons CA1 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.14.16 Invalid onlySomeReasons Test16
     * <p>
     * In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
     * and cACompromise reason codes and the other covering the remaining reason codes. The end
     * entity certificate has been placed on hold.
     */
    public void test4_14_16()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid onlySomeReasons Test16 EE")
            .withCrls("onlySomeReasons CA1 other reasons CRL")
            .withCrls("onlySomeReasons CA1 compromise CRL")
            .withCACert("onlySomeReasons CA1 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: certificateHold");
    }

    /**
     * 4.14.17 Invalid onlySomeReasons Test17
     * <p>
     * In this test, the intermediate certificate has issued two CRLs, one covering the affiliationChanged
     * and superseded reason codes and the other covering the cessationOfOperation and
     * certificateHold reason codes. The end entity certificate is not listed on either CRL.
     */
    public void test4_14_17()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid onlySomeReasons Test17 EE")
            .withCrls("onlySomeReasonsCA2 CRL2")
            .withCrls("onlySomeReasons CA2 CRL1")
            .withCACert("onlySomeReasons CA2 Cert")
            .doExceptionTest(0, "Certificate status could not be determined.");
    }

    /**
     * 4.14.18 Valid onlySomeReasons Test18
     * <p>
     * In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
     * and cACompromise reason codes and the other covering the remaining reason codes. Both CRLs
     * include an issuingDistributionPoint extension with the same distributionPoint name. The end
     * entity certificate includes a cRLDistributionPoints extension with the same distributionPoint
     * name.
     */
    public void test4_14_18()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid onlySomeReasons Test18 EE")
            .withCrls("onlySomeReasons CA3 other reasons CRL")
            .withCrls("onlySomeReasons CA3 compromise CRL")
            .withCACert("onlySomeReasons CA3 Cert")
            .doTest();
    }

    /**
     * 4.14.19 Valid onlySomeReasons Test19
     * <p>
     * In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
     * and cACompromise reason codes and the other covering the remaining reason codes. Both CRLs
     * include an issuingDistributionPoint extension with a different distributionPoint name. The end
     * entity certificate includes a cRLDistributionPoints extension with two DistributionPoints, one
     * for each CRL.
     */
    public void test4_14_19()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid onlySomeReasons Test19 EE")
            .withCrls("onlySomeReasons CA4 other reasons CRL")
            .withCrls("onlySomeReasons CA4 compromise CRL")
            .withCACert("onlySomeReasons CA4 Cert")
            .doTest();
    }

    /**
     * 4.14.20 Invalid onlySomeReasons Test20
     * <p>
     * In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
     * and cACompromise reason codes and the other covering the remaining reason codes. Both CRLs
     * include an issuingDistributionPoint extension with a different distributionPoint name. The end
     * entity certificate includes a cRLDistributionPoints extension with two DistributionPoints, one
     * for each CRL. The end entity certificate has been revoked for key compromise.
     */
    public void test4_14_20()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid onlySomeReasons Test20 EE")
            .withCrls("onlySomeReasons CA4 other reasons CRL")
            .withCrls("onlySomeReasons CA4 compromise CRL")
            .withCACert("onlySomeReasons CA4 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.14.21 Invalid onlySomeReasons Test21
     * <p>
     * In this test, the intermediate certificate has issued two CRLs, one covering the keyCompromise
     * and cACompromise reason codes and the other covering the remaining reason codes. Both CRLs
     * include an issuingDistributionPoint extension with a different distributionPoint name. The end
     * entity certificate includes a cRLDistributionPoints extension with two DistributionPoints, one
     * for each CRL. The end entity certificate has been revoked as a result of a change in affiliation.
     */
    public void test4_14_21()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid onlySomeReasons Test21 EE")
            .withCrls("onlySomeReasons CA4 other reasons CRL")
            .withCrls("onlySomeReasons CA4 compromise CRL")
            .withCACert("onlySomeReasons CA4 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: affiliationChanged");
    }

    /**
     * 4.14.22 Valid IDP with indirectCRL Test22
     * <p>
     * In this test, the intermediate CA has issued a CRL that contains an issuingDistributionPoint
     * extension with the indirectCRL flag set. The end entity certificate was issued by the intermediate
     * CA.
     * 91
     */
    public void test4_14_22()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid IDP with indirectCRL Test22 EE")
            .withCrls("indirectCRL CA1 CRL")
            .withCACert("indirectCRL CA1 Cert")
            .doTest();
    }

    /**
     * 4.14.23 Invalid IDP with indirectCRL Test23
     * <p>
     * In this test, the intermediate CA has issued a CRL that contains an issuingDistributionPoint
     * extension with the indirectCRL flag set. The end entity certificate was issued by the intermediate
     * CA and is listed as revoked on the CRL.
     */
    public void test4_14_23()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid IDP with indirectCRL Test23 EE")
            .withCrls("indirectCRL CA1 CRL")
            .withCACert("indirectCRL CA1 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.14.24 Valid IDP with indirectCRL Test24
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The public key needed to validate the indirect CRL is in a certificate issued by the Trust Anchor.
     */
    // CHECK.
    public void xtest4_14_24()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid IDP with indirectCRL Test24 EE")
            .withCrls("indirectCRL CA1 CRL")
            .withCACert("indirectCRL CA1 Cert")
            .withCACert("indirectCRL CA2 Cert")
            .doTest();
    }

    /**
     * 4.14.25 Valid IDP with indirectCRL Test25
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The public key needed to validate the indirect CRL is in a certificate issued by the Trust Anchor.
     * The end entity's serial number is listed on the CRL, but there is no certificateIssuer CRL entry
     * extension, indicating that the revoked certificate was one issued by the CRL issuer.
     * 92
     */
    public void xtest4_14_25()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid IDP with indirectCRL Test25 EE")
            .withCrls("indirectCRL CA1 CRL")
            .withCACert("indirectCRL CA1 Cert")
            .withCACert("indirectCRL CA2 Cert")
            .doTest();
    }

    /**
     * 4.14.26 Invalid IDP with indirectCRL Test26
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The entity specified in the cRLIssuer field does not exist.
     */
    // CHECK not forming path, "Trust anchor for certification path not found."
    // Expected it to be failing because the end entity has been revoked.
    public void xtest4_14_26()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid IDP with indirectCRL Test26 EE")
            .withCrls("indirectCRL CA1 CRL")
            .withCACert("indirectCRL CA1 Cert")
            .withCACert("indirectCRL CA2 Cert")
            .doExceptionTest(-1, "--");
    }

    /**
     * 4.14.27 Invalid cRLIssuer Test27
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The CRL issued by the entity specified in the cRLIssuer field does not include an
     * issuingDistributionPoint extension.
     */
    // CHECK not forming path, "Trust anchor for certification path not found."
    public void xtest4_14_27()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid cRLIssuer Test27 EE")
            .withCrls("Good CA CRL")
            .withCACert("Good CA Cert")
            .withCACert("indirectCRL CA2 Cert")
            .doExceptionTest(-1, "--");
    }

    /**
     * 4.14.28 Valid cRLIssuer Test28
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * <p>
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The indirect CRL issuer has been issued a certificate by the issuer of the end entity certificate. The
     * certificate issued to the CRL issuer is covered by a CRL issued by the issuer of the end entity
     * certificate.
     */
    public void xtest4_14_28()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid cRLIssuer Test28 EE")
            .withCrls("indirectCRL CA3 cRLIssuer CRL")
            .withCACert("indirectCRL CA3 cRLIssuer Cert")
            .withCrls("indirectCRL CA3 CRL")
            .withCACert("indirectCRL CA3 Cert")
            .doTest();
    }

    /**
     * 4.14.29 Valid cRLIssuer Test29
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The distributionPoint in the end entity certificate is specified as nameRelativeToCRLIssuer.
     * The indirect CRL issuer has been issued a certificate by the issuer of the end entity certificate. The
     * certificate issued to the CRL issuer is covered by a CRL issued by the issuer of the end entity
     * certificate.
     */
    public void xtest4_14_29()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid cRLIssuer Test29 EE")
            .withCrls("indirectCRL CA3 cRLIssuer CRL")
            .withCACert("indirectCRL CA3 cRLIssuer Cert")
            .withCrls("indirectCRL CA3 CRL")
            .withCACert("indirectCRL CA3 Cert")
            .doTest();
    }

    /**
     * 4.14.30 Valid cRLIssuer Test30
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The indirect CRL issuer has been issued a certificate by the issuer of the end entity certificate.
     * Both the end entity certificate and the certificate issued to the CRL issuer are covered by the
     * indirect CRL issued by the CRL issuer.
     */
    public void xtest4_14_30()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid cRLIssuer Test30 EE")
            .withCrls("indirectCRL CA4 cRLIssuer CRL")
            .withCACert("indirectCRL CA4 cRLIssuer Cert")
            .withCACert("indirectCRL CA4 Cert")
            .doTest();
    }

    /**
     * 4.14.31 Invalid cRLIssuer Test31
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The indirect CRL contains a CRL entry listing the end entity certificate's serial number that
     * includes a certificateIssuer extension specifying the end entity certificate's issuer.
     */
    // CHECK not forming path, "Trust anchor for certification path not found."
    // Expected it to be failing because the end entity has been revoked.
    public void xtest4_14_31()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid cRLIssuer Test31 EE")
            .withCACert("indirectCRL CA6 Cert")
            .withCrls("indirectCRL CA5 CRL")
            .withCACert("indirectCRL CA5 Cert")
            .doExceptionTest(-1, "--");
    }

    /**
     * 4.14.32 Invalid cRLIssuer Test32
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The indirect CRL contains a CRL entry listing the end entity certificate's serial number and the
     * preceding CRL entry includes a certificateIssuer extension specifying the end entity certificate's
     * issuer.
     */
    // CHECK not forming path, "Trust anchor for certification path not found."
    // Expected it to be failing because the end entity has been revoked.
    public void xtest4_14_32()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid cRLIssuer Test32 EE")
            .withCACert("indirectCRL CA6 Cert")
            .withCrls("indirectCRL CA5 CRL")
            .withCACert("indirectCRL CA5 Cert")
            .doExceptionTest(-1, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.14.33 Valid cRLIssuer Test33
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with a
     * cRLIssuer field indicating that the CRL is issued by an entity other than the certificate issuer.
     * The indirect CRL contains a CRL entry listing the end entity certificate's serial number, but the
     * most recent CRL entry to include a certificateIssuer extension specified a different certificate
     * issuer.
     */
    public void xtest4_14_33()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid cRLIssuer Test33 EE")
            .withCACert("indirectCRL CA6 Cert")
            .withCrls("indirectCRL CA5 CRL")
            .withCACert("indirectCRL CA5 Cert")
            .doTest();
    }

    /**
     * 4.14.34 Invalid cRLIssuer Test34
     * <p>
     * In this test, the end entity certificate is issued by the same CA that issues the corresponding CRL,
     * but the CRL is also an indirect CRL for other CAs. The end entity certificate's serial number is
     * listed on the CRL and the most recent CRL entry to include a certificateIssuer extension specifies
     * the end entity certificate's issuer.
     */
    public void test4_14_34()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid cRLIssuer Test34 EE")
            .withCrls("indirectCRL CA5 CRL")
            .withCACert("indirectCRL CA5 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.14.35 Invalid cRLIssuer Test35
     * <p>
     * In this test, the end entity certificate includes a cRLDistributionPoints extension with both a
     * distributionPoint name and a cRLIssuer field indicating that the CRL is issued by an entity other
     * than the certificate issuer. There is no CRL available from the entity specified in cRLIssuer, but
     * the certificate issuer has issued a CRL with an issuingDistributionPoint extension that includes a
     * distributionPoint that matches the distributionPoint in the certificate.
     */
    public void test4_14_35()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid cRLIssuer Test35 EE")
            .withCrls("indirectCRL CA5 CRL")
            .withCACert("indirectCRL CA5 Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"ou=indirectCRL CA5,o=Test Certificates,c=US\"");
    }

    /**
     * 4.15.1 Invalid deltaCRLIndicator No Base Test1
     * <p>
     * In this test, the CRL covering the end entity certificate includes a deltaCRLIndicator extension,
     * but no other CRLs are available for the intermediate certificate.
     */
    public void test4_15_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid deltaCRLIndicator No Base Test1 EE")
            .withCrls("deltaCRLIndicator No Base CA CRL")
            .withCACert("deltaCRLIndicator No Base CA Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"cn=deltaCRLIndicator No Base CA,o=Test Certificates,c=US\"");
    }

    /**
     * 4.15.2 Valid delta-CRL Test2
     * <p>
     * In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
     * refers to the complete CRL as its base CRL.
     */
    public void test4_15_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid deltaCRL Test2 EE")
            .withCrls("deltaCRL CA1 deltaCRL")
            .withCrls("deltaCRL CA1 CRL")
            .withCACert("deltaCRL CA1 Cert")
            .doTest();
    }

    /**
     * 4.15.3 Invalid delta-CRL Test3
     * <p>
     * In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
     * refers to the complete CRL as its base CRL. The end entity certificate is listed as revoked on the
     * complete CRL.
     * 97
     */
    public void test4_15_3()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid deltaCRL Test3 EE")
            .withCrls("deltaCRL CA1 deltaCRL")
            .withCrls("deltaCRL CA1 CRL")
            .withCACert("deltaCRL CA1 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.15.4 Invalid delta-CRL Test4
     * <p>
     * In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
     * refers to the complete CRL as its base CRL. The end entity certificate is listed as revoked on the
     * delta-CRL.
     */
    public void test4_15_4()
        throws Exception
    {
        new PKITSTest()
            .enableDeltaCRLs(true)
            .withEndEntity("Invalid deltaCRL Test4 EE")
            .withCrls("deltaCRL CA1 deltaCRL")
            .withCrls("deltaCRL CA1 CRL")
            .withCACert("deltaCRL CA1 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.15.5 Valid delta-CRL Test5
     * <p>
     * In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
     * refers to the complete CRL as its base CRL. The end entity certificate is listed as on hold on the
     * complete CRL, but the delta-CRL indicates that it should be removed from the CRL.
     */
    public void test4_15_5()
        throws Exception
    {
        new PKITSTest()
            .enableDeltaCRLs(true)
            .withEndEntity("Valid deltaCRL Test5 EE")
            .withCrls("deltaCRL CA1 deltaCRL")
            .withCrls("deltaCRL CA1 CRL")
            .withCACert("deltaCRL CA1 Cert")
            .doTest();
    }

    /**
     * 4.15.6 Invalid delta-CRL Test6
     * <p>
     * In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
     * refers to the complete CRL as its base CRL. The end entity certificate is listed as on hold on the
     * complete CRL and the delta-CRL indicates that it has been revoked.
     */
    public void test4_15_6()
        throws Exception
    {
        new PKITSTest()
            .enableDeltaCRLs(true)
            .withEndEntity("Invalid deltaCRL Test6 EE")
            .withCrls("deltaCRL CA1 deltaCRL")
            .withCrls("deltaCRL CA1 CRL")
            .withCACert("deltaCRL CA1 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.15.7 Valid delta-CRL Test7
     * <p>
     * In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
     * refers to the complete CRL as its base CRL. The end entity certificate is not listed on the complete
     * CRL and is listed on the delta-CRL as removeFromCRL.
     */
    public void test4_15_7()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid deltaCRL Test7 EE")
            .withCrls("deltaCRL CA1 deltaCRL")
            .withCrls("deltaCRL CA1 CRL")
            .withCACert("deltaCRL CA1 Cert")
            .doTest();
    }

    /**
     * 4.15.8 Valid delta-CRL Test8
     * <p>
     * In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
     * refers to a CRL that was issued earlier than the complete CRL as its base CRL. The end entity
     * certificate is not listed on either the complete CRL or the delta-CRL.
     */
    public void test4_15_8()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid deltaCRL Test8 EE")
            .withCrls("deltaCRL CA2 deltaCRL")
            .withCrls("deltaCRL CA2 CRL")
            .withCACert("deltaCRL CA2 Cert")
            .doTest();
    }

    /**
     * 4.15.9 Invalid delta-CRL Test9
     * <p>
     * In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
     * refers to a CRL that was issued earlier than the complete CRL as its base CRL. The end entity
     * certificate is listed as revoked on both the complete CRL and the delta-CRL.
     */
    public void test4_15_9()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid deltaCRL Test9 EE")
            .withCrls("deltaCRL CA2 deltaCRL")
            .withCrls("deltaCRL CA2 CRL")
            .withCACert("deltaCRL CA2 Cert")
            .doExceptionTest(0, "Certificate revocation after 2001-04-19 14:57:20 +0000, reason: keyCompromise");
    }

    /**
     * 4.15.10 Invalid delta-CRL Test10
     * <p>
     * In this test, the intermediate CA has issued a complete CRL and a delta-CRL. The delta-CRL
     * refers to a CRL that was issued later than the complete CRL as its base CRL. The end entity
     * certificate is not listed as revoked on either the complete CRL or the delta-CRL, but the delta-CRL
     * can not be used in conjunction with the provided complete CRL. The complete CRL has a
     * nextUpdate time that is in the past.
     */
    public void test4_15_10()
        throws Exception
    {
        new PKITSTest()
            .enableDeltaCRLs(true)
            .withEndEntity("Invalid deltaCRL Test10 EE")
            .withCrls("deltaCRL CA3 deltaCRL")
            .withCrls("deltaCRL CA3 CRL")
            .withCACert("deltaCRL CA3 Cert")
            .doExceptionTest(0, "No CRLs found for issuer \"cn=deltaCRL CA3,o=Test Certificates,c=US\"");
    }

    /**
     * 4.16.1 Valid Unknown Not Critical Certificate Extension Test1
     * <p>
     * In this test, the end entity certificate contains a private, non-critical certificate extension.
     */
    public void test4_16_1()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Valid Unknown Not Critical Certificate Extension Test1 EE")
            .doTest();
    }

    /**
     * 4.16.2 Invalid Unknown Critical Certificate Extension Test2
     * <p>
     * In this test, the end entity certificate contains a private, critical certificate extension.
     */
    public void test4_16_2()
        throws Exception
    {
        new PKITSTest()
            .withEndEntity("Invalid Unknown Critical Certificate Extension Test2 EE")
            .doExceptionTest(0, "Certificate has unsupported critical extension: [2.16.840.1.101.2.1.12.2]");
    }


}
