package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;


/*
 * These tests are taken from the NIST X.509 Validation Test Suite
 * available at: https://csrc.nist.gov/pki/testing/x509paths.html
 * 
 * Only the relevant certificate and crl data has been kept, in order
 * to keep the class size to a minimum.
 * 
 */

public class NISTCertPathTest 
    extends SimpleTest 
{    
    private static final String TEST_POLICY_1 = "2.16.840.1.101.3.1.48.1";
    private static final String TEST_POLICY_2 = "2.16.840.1.101.3.1.48.2";
    private static final String TEST_POLICY_3 = "2.16.840.1.101.3.1.48.3";
    private static final String TEST_POLICY_4 = "2.16.840.1.101.3.1.48.4";
    private static final String TEST_POLICY_5 = "2.16.840.1.101.3.1.48.5";
    
    private static Set ANY;
    private static Set TP1;
    private static Set TP2;
    private static Set TP3;
    private static Set TP4;
    private static Set TP1_TP2;
    
    static {
        ANY = new HashSet();
        
        TP1 = new HashSet();
        TP1.add(TEST_POLICY_1);
        
        TP2 = new HashSet();
        TP2.add(TEST_POLICY_2);
        
        TP3 = new HashSet();
        TP3.add(TEST_POLICY_3);

        TP4 = new HashSet();
        TP4.add(TEST_POLICY_4);
        
        TP1_TP2 = new HashSet();
        TP1_TP2.add(TEST_POLICY_1);
        TP1_TP2.add(TEST_POLICY_2);
    }

    /*  
     *  
     *  FIELDS
     *  
     */ 
    
    private CertificateFactory fact;
    
    private X509Certificate trustedCert;
    private X509CRL         trustedCRL;
    private Set             trustedSet;
    private int             testCount;
    private Vector          testFail;
    private StringBuffer    resultBuf;
 
    public String getName() 
    {
        return "NISTCertPathTest";
    }
    
    
    public void performTest() 
    {
        init();
        
        test(" 1", TEST_1_DATA , true , false);
        test(" 2", TEST_2_DATA , false, false);
        test(" 3", TEST_3_DATA , false, false);
        test(" 4", TEST_4_DATA , true , false);
        test(" 5", TEST_5_DATA , false, false);
        test(" 6", TEST_6_DATA , false, false);
        test(" 7", TEST_7_DATA , true , false);
        test(" 8", TEST_8_DATA , false, false);
        test(" 9", TEST_9_DATA , false, false);
        
        test("10", TEST_10_DATA, false, false);
        test("11", TEST_11_DATA, false, false);
        test("12", TEST_12_DATA, true , false);
        test("13", TEST_13_DATA, false, false);
        test("14", TEST_14_DATA, false, false);
        test("15", TEST_15_DATA, true , false);
        test("16", TEST_16_DATA, true , false);
        test("17", TEST_17_DATA, true , false);
        test("18", TEST_18_DATA, true , false);
        test("19", TEST_19_DATA, false, false);
        
        test("20", TEST_20_DATA, false, false);
        test("21", TEST_21_DATA, false, false);
        test("22", TEST_22_DATA, false, false);
        test("23", TEST_23_DATA, false, false);
        test("24", TEST_24_DATA, true , false);
        test("25", TEST_25_DATA, false, false);
        test("26", TEST_26_DATA, true , false);
        test("27", TEST_27_DATA, true , false);
        test("28", TEST_28_DATA, false, false);
        test("29", TEST_29_DATA, false, false);
        
        test("30", TEST_30_DATA, true , false);
        test("31", TEST_31_DATA, false, false);
        test("32", TEST_32_DATA, false, false);
        test("33", TEST_33_DATA, true , false);
        
        

        test("34a", TEST_34_DATA, ANY , true , true , false);
        test("34b", TEST_34_DATA, ANY , false, true , false);
        test("34c", TEST_34_DATA, TP1 , true , true , false);
        test("34d", TEST_34_DATA, TP1 , false, true , false);
        test("34e", TEST_34_DATA, TP2 , true , false, false);
        test("34f", TEST_34_DATA, TP2 , false, true , false);
        
        test("35a", TEST_35_DATA, false,  true , false);
        test("35b", TEST_35_DATA, true ,  false, false);

        test("36a", TEST_36_DATA, false,  true , false);
        test("36b", TEST_36_DATA, true ,  false, false);
        
        test("37a", TEST_37_DATA, false,  true , false);
        test("37b", TEST_37_DATA, true ,  false, false);
        
        test("38a", TEST_38_DATA, false,  true , false);
        test("38b", TEST_38_DATA, true ,  false, false);
        
        test("39a", TEST_39_DATA, ANY , true ,  true , false);
        test("39b", TEST_39_DATA, ANY , false,  true , false);
        test("39c", TEST_39_DATA, TP1 , true ,  true , false);
        test("39d", TEST_39_DATA, TP1 , false,  true , false);
        test("39e", TEST_39_DATA, TP2 , true ,  false, false);
        test("39f", TEST_39_DATA, TP2 , false,  true , false);
        

        test("40a", TEST_40_DATA, false, true , false);
        test("40b", TEST_40_DATA, true , false, false);
        
        test("41a", TEST_41_DATA, false, true , false);
        test("41b", TEST_41_DATA, true , false, false);
        
        test("42a", TEST_42_DATA, false, true , false);
        test("42b", TEST_42_DATA, true , false, false);

        test("43a", TEST_43_DATA, false, true , false);
        test("43b", TEST_43_DATA, true , false, false);
        
        test("44a", TEST_44_DATA, false, true , false);
        test("44b", TEST_44_DATA, true , false, false);
        
        test("45a", TEST_45_DATA, false, false, false);
        test("45b", TEST_45_DATA, true , false, false);
        
        test("46a", TEST_46_DATA, ANY , false, true , false);
        test("46b", TEST_46_DATA, ANY , true , true , false);
        test("46c", TEST_46_DATA, TP1 , true , true , false);
        test("46d", TEST_46_DATA, TP1 , false, true , false);
        test("46e", TEST_46_DATA, TP2 , true , false, false);
        test("46f", TEST_46_DATA, TP2 , false, false, false);
        
        test("47a", TEST_47_DATA, false, false, false);
        test("47b", TEST_47_DATA, true , false, false);
        
        test("48a", TEST_48_DATA, TP1 , false, true , false);
        test("48b", TEST_48_DATA, TP1 , true , true , false);
        test("48c", TEST_48_DATA, ANY , false, true , false);
        test("48d", TEST_48_DATA, ANY , true , true , false);
        test("48e", TEST_48_DATA, TP2 , false, true , false);
        test("48f", TEST_48_DATA, TP2 , true , false, false);
        
        test("49a", TEST_49_DATA, TP1 , false,  true , false);
        test("49b", TEST_49_DATA, TP1 , true ,  true , false);
        test("49c", TEST_49_DATA, TP3 , false,  true , false);
        test("49d", TEST_49_DATA, TP3 , true ,  false, false);
        test("49e", TEST_49_DATA, ANY , false,  true , false);
        test("49f", TEST_49_DATA, ANY , true ,  true , false);
        
        test("50a", TEST_50_DATA, TP1     , false,  true , false);
        test("50b", TEST_50_DATA, TP1     , true ,  true , false);
        test("50c", TEST_50_DATA, TP1_TP2 , false,  true , false);
        test("50d", TEST_50_DATA, TP1_TP2 , true ,  true , false);
        test("50e", TEST_50_DATA, ANY     , false,  true , false);
        test("50f", TEST_50_DATA, ANY     , true ,  true , false);
        
        test("51a", TEST_51_DATA, false, true , false);
        test("51b", TEST_51_DATA, true , false, false);
        
        test("52a", TEST_52_DATA, TP1     , false,  true , false);
        test("52b", TEST_52_DATA, TP1     , true ,  false, false);
        test("52c", TEST_52_DATA, TP1_TP2 , false,  true , false);
        test("52d", TEST_52_DATA, TP1_TP2 , true ,  false, false);
        test("52e", TEST_52_DATA, ANY     , false,  true , false);
        test("52f", TEST_52_DATA, ANY     , true ,  true , false);
        
        test("53a", TEST_53_DATA, TP1     , false,  true , false);
        test("53b", TEST_53_DATA, TP1     , true ,  true , false);
        test("53c", TEST_53_DATA, TP1_TP2 , false,  true , false);
        test("53d", TEST_53_DATA, TP1_TP2 , true ,  true , false);
        test("53e", TEST_53_DATA, TP4     , false,  true , false);
        test("53f", TEST_53_DATA, TP4     , true ,  false, false);
        test("53g", TEST_53_DATA, ANY     , false,  true , false);
        test("53h", TEST_53_DATA, ANY     , true ,  true , false);
        
        test("54", TEST_54_DATA, false, false);
        test("55", TEST_55_DATA, false, false);
        test("56", TEST_56_DATA, true , false);
        test("57", TEST_57_DATA, true , false);
        test("58", TEST_58_DATA, false, false);
        test("59", TEST_59_DATA, false, false);
        
        test("60", TEST_60_DATA, false, false);
        test("61", TEST_61_DATA, false, false);
        test("62", TEST_62_DATA, true , false);
        test("63", TEST_63_DATA, true , false);
        test("64", TEST_64_DATA, false, false);
        test("65", TEST_65_DATA, false, false);
        test("66", TEST_66_DATA, false, false);
        test("67", TEST_67_DATA, true , false);
        test("68", TEST_68_DATA, false, false);
        test("69", TEST_69_DATA, false, false);
        
        test("70", TEST_70_DATA, false, false);
        test("71", TEST_71_DATA, false, false);
        test("72", TEST_72_DATA, false, false);
        test("73", TEST_73_DATA, false, false);
        test("74", TEST_74_DATA, true , false);
        test("75", TEST_75_DATA, false, false);
        test("76", TEST_76_DATA, false, false);
        
        resultBuf.append("NISTCertPathTest -- Failed: ").append(testFail.size()).append('/').append(testCount).append('\n');
        if (!testFail.isEmpty())
        {
            fail(resultBuf.toString());
        }
    }
    
    private void init()
    {
        try
        {
            fact = CertificateFactory.getInstance("X.509", "BC");
            trustedCert = (X509Certificate)fact
                    .generateCertificate(new ByteArrayInputStream(Base64
                            .decode(Trust_Anchor_CP_01_01_crt)));
            trustedCRL = (X509CRL)fact.generateCRL(new ByteArrayInputStream(
                    Base64.decode(Trust_Anchor_CRL_CP_01_01_crl)));
            trustedSet = new HashSet();

            byte[] _ncBytes = null;
            byte[] _octBytes = trustedCert.getExtensionValue("2.5.29.30");
            if (_octBytes != null)
            {
                ASN1InputStream _ais = new ASN1InputStream(
                        new ByteArrayInputStream(_octBytes));
                ASN1OctetString _oct = ASN1OctetString.getInstance(_ais
                        .readObject());
                _ais.close();
                _ncBytes = _oct.getOctets();
            }

            trustedSet.add(new TrustAnchor(trustedCert, _ncBytes));
            testCount = 0;
            testFail = new Vector();
            resultBuf = new StringBuffer();
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage());
        }
    }

    private X509Certificate decodeCertificate(String _str)
            throws GeneralSecurityException
    {

        return (X509Certificate)fact
                .generateCertificate(new ByteArrayInputStream(Base64
                        .decode(_str)));
    }

    private X509CRL decodeCRL(String _str)
            throws GeneralSecurityException
    {

        return (X509CRL)fact.generateCRL(new ByteArrayInputStream(Base64
                .decode(_str)));
    }

    private CertStore makeCertStore(String[] _strs)
            throws GeneralSecurityException
    {

        Vector _vec = new Vector();
        _vec.addElement(trustedCRL);

        for (int i = 0; i < _strs.length; i++)
        {
            if (_strs[i].startsWith("MIIC"))
            {
                _vec.addElement(fact
                        .generateCertificate(new ByteArrayInputStream(Base64
                                .decode(_strs[i]))));
            }
            else if (_strs[i].startsWith("MIIB"))
            {
                _vec.addElement(fact.generateCRL(new ByteArrayInputStream(
                        Base64.decode(_strs[i]))));
            }
            else
            {
                throw new IllegalArgumentException("Invalid certificate or crl");
            }
        }

        // Insert elements backwards to muck up forward ordering dependency
        Vector _vec2 = new Vector();
        for (int i = _vec.size() - 1; i >= 0; i--)
        {
            _vec2.add(_vec.elementAt(i));
        }

        return CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(_vec2), "BC");
    }

    private void test(String _name, String[] _data, boolean _accept,
            boolean _debug)
    {

        test(_name, _data, null, false, _accept, _debug);
    }

    private void test(String _name, String[] _data, boolean _explicit,
            boolean _accept, boolean _debug)
    {

        test(_name, _data, null, _explicit, _accept, _debug);
    }

    private void test(String _name, String[] _data, Set _ipolset,
            boolean _explicit, boolean _accept, boolean _debug)
    {

        testCount++;
        boolean _pass = true;

        try
        {
            CertPathBuilder _cpb = CertPathBuilder.getInstance("PKIX", "BC");
            X509Certificate _ee = decodeCertificate(_data[_data.length - 1]);
            X509CertSelector _select = new X509CertSelector();
            _select.setSubject(_ee.getSubjectX500Principal().getEncoded());

            PKIXBuilderParameters _param = new PKIXBuilderParameters(
                    trustedSet, _select);
            _param.setExplicitPolicyRequired(_explicit);
            _param.addCertStore(makeCertStore(_data));
            _param.setRevocationEnabled(true);
            if (_ipolset != null)
            {
                _param.setInitialPolicies(_ipolset);
            }

            CertPathBuilderResult _result = _cpb.build(_param);

            if (!_accept)
            {
                System.out.println("Accept when it should reject");
                _pass = false;
                testFail.addElement(_name);
            }
        }
        catch (Exception ex)
        {
            if (_accept)
            {
                System.out.println("Reject when it should accept");
                _pass = false;
                testFail.addElement(_name);
            }
        }

        resultBuf.append("NISTCertPathTest -- ").append(_name).append(": ")
                .append(_pass ? "\n" : "Failed.\n");
    }
    

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new NISTCertPathTest());
    }
    
    /*  
     *  Trust Anchor
     *  
     */ 
    public static final String Trust_Anchor_CP_01_01_crt = 
        "MIICbDCCAdWgAwIBAgIDAYafMA0GCSqGSIb3DQEBBQUAMF4xCzAJBgNVBAYTAlVTMRgwFg" +
        "YDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEQMA4GA1UECxMHVGVzdGlu" +
        "ZzEVMBMGA1UEAxMMVHJ1c3QgQW5jaG9yMB4XDTk5MDEwMTEyMDEwMFoXDTQ4MDEwMTEyMD" +
        "EwMFowXjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UE" +
        "CxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5nMRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBANPzucEztz+nJ/ZBHVyceZ2q0pUQt4TO2qPlWAw+" +
        "TotWvz6qIS1QE/7zGS56yxHP89O4X1efnZeArx2VVxLfNNS9865N53ymINQETtpjYT49Ko" +
        "03z8U8yfn68DlIBHi9sN31JEYzoUafF58Eu883lAwTQ6qQrJF4HbrzGIQqgitHAgMBAAGj" +
        "ODA2MBEGA1UdDgQKBAirmuv5wudUjzAMBgNVHRMEBTADAQH/MBMGA1UdIwQMMAqACKua6/" +
        "nC51SPMA0GCSqGSIb3DQEBBQUAA4GBABZWD2Gsh4tP62QSG8OFWUpo4TulIcFZLpGsaP4T" +
        "/2Nt7lXUoIJMN7wWjqkmYf5/Rvo4HxNcimq3EkeYcrm1VoDueJUYGvRjcCY5mxkghI27Yl" +
        "/fLKE9/BvQOrvYzBs2EqKrrT7m4VK0dRMR7CeVpmPP08z0Tti6uK2tzBplp1pF";
    public static final String Trust_Anchor_CRL_CP_01_01_crl = 
        "MIIBbzCB2QIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDFRydXN0IEFuY2hvchcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWjAiMCACAS" +
        "cXDTk5MDEwMTEyMDAwMFowDDAKBgNVHRUEAwoBAaAjMCEwCgYDVR0UBAMCAQEwEwYDVR0j" +
        "BAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcNAQEFBQADgYEAC7lqZwejJRW7QvzH11/7cYcL3r" +
        "acgMxH3PSU/ufvyLk7ahR++RtHary/WeCvRdyznLiIOA8ZBiguWtVPqsNysNn7WLofQIVa" +
        "+/TD3T+lece4e1NwGQvj5Q+e2wRtGXg+gCuTjTKUFfKRnWz7O7RyiJKKim0jtAF4RkCpLe" +
        "bNChY=";


    /*  
     *  test1
     *  
     */ 

    public static final String End_Certificate_CP_01_01_crt = 
        "MIIChjCCAe+gAwIBAgIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDEuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMY07G8M4FkOvF+6LpO7BKcDuXCKudfl1+bKSowj" +
        "2GCza8uIiMfYSH5k+fYb43lGQeRh9yVHcfNQlE7yfGo3tgxGv5yWpeKvDMqL8Iy6Q0oIjm" +
        "qH80ZOz21dUkermcckzTEOfe/R2fNpJPv8M24pq29SdYAqu+CpLDHFtws9O+q1AgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIrNv88bwFLtIwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcNAQEFBQADgYEAK4hP" +
        "goWtZbHf6qWfRfmrPrz9hDH1644NrJop2Y7MXzuTtpo1zp4NCG4+ii0CSOfvhugc8yOmq3" +
        "I6olgE0V16VtC5br2892UHYZ55Q4oQ9BWouVVlOyY9rogOB160BnsqBELFhT0Wf6mnbsdD" +
        "G+BB5fFyeK61aYDWV84kS7cSX5w=";
    public static final String[] TEST_1_DATA = new String[] {
        End_Certificate_CP_01_01_crt,
    };

    /*  
     *  test2
     *  
     */ 

    public static final String Intermediate_Certificate_CP_01_02_crt = 
        "MIIClTCCAf6gAwIBAgIBAjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAxLjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDWOZ4hk+K6NX/l+OiHC4pfKCWFt+XM2n/TxwkqY+mt" +
        "j9Co77rPPPtVA7mDKU4OiYT74mIWH52HQBZr+PRmOFh0Z9S1oTpLbxNLCDc6OmQKBo6iex" +
        "SIt/jOatFFmzmTZ78Kq9s3nfrOVA83ggmPDTPkuG5GwcxPgFq0vRmAJ0CESQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQI5o5Am09NlOYwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEA3C7Ye5/Te14LIwo/LK2fnpobbQA3dhOn5UgqZ8lKbQ/HV1D8/eU9dK" +
        "2v5gW43XvFq4whK0WKLBvBFchKtp9T1QX3CI2WCqdJRyqla6TkQsS36T17/ww2nzy1853Y" +
        "hfDYNsge5XW8YZNfNjjVxcR3RnyFxPax1YIlISiGdI0dnag=";
    public static final String Intermediate_CRL_CP_01_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMS4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI5o5Am09NlOYwDQYJKoZIhvcNAQEFBQADgYEAl26W" +
        "g1Gqq3R93XPjghABVocfeIi8zcSJ0YAKqbifh5V3JCC8Piy19GzZdL244GqBDls44IAhKj" +
        "YuXN2mSohdqwULbye4agAgfl37XhhwsBDTYwaJiv3njFQ6Ml7KJ3STmoIpmlLvrXibDuHX" +
        "ocuNGo72ckhOdBpXd+PhgGuoTis=";
    public static final String End_Certificate_CP_01_02_crt = 
        "MIIChjCCAe+gAwIBAgIBAzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMS4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDEuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALwJrZT6bJXQnZzc3socZ/mNsEag4BTdym99ZCP2" +
        "3PGsTCfV2z7+p4DehIFrn/N/a1d1nvyqRqpQGPU86tl1CWgFtXS+zCctDR71P76bjd6yef" +
        "5vxxdO/SBIRHfQTjM8F3BTLkrC+PVl5wbaLcEXRORXrFvBvsj0oqwZ4C8ZObh/AgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIf5mSjuNhs/gwEwYDVR0jBAwwCoAI5o5Am09NlOYwDQYJKoZIhvcNAQEFBQADgYEAK7wd" +
        "MyLlIZ/Qsqj3/A3Gat0d5BORtFTZH0VdlVVOWN1JCZxrnjeIFB92NNzUROemxgBxzneuWN" +
        "SlYlcpTk25pAbs6RMdbT8dovKQkQkF2TXeQ+4qktFaLQntVT8UsEzHR4Diw0/gH8tseGqF" +
        "F7FyiW8ni6zInSO+embUKiibj9I=";
    public static final String[] TEST_2_DATA = new String[] {
        Intermediate_Certificate_CP_01_02_crt,
        Intermediate_CRL_CP_01_02_crl,
        End_Certificate_CP_01_02_crt
    };

    /*  
     *  test3
     *  
     */ 

    public static final String Intermediate_Certificate_CP_01_03_crt = 
        "MIIClTCCAf6gAwIBAgIBBDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAxLjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC4RZ0R82sA+BfyynFeoIDG7c5IlZ8HorEv+O4Ij3Oy" +
        "7FR1MB4no8hDEBPBf5fCrAR/8PVxCZjVj2HOwnSAqUQgxo6WPcmkabux12k8kK6yeKq3b7" +
        "u5fL6tb7eKElQzsz8Je4z4rCDkI10vV+X0VZ5Ip/Es428dw2KoN8eyGmw3+QIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIz08WhMpG2JswEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAQ+iqlFvbvDejO/m+RCHh2UuUau1FuABObkPOu2Tv9yTWvTSWDRygdO" +
        "LQRiOLsjgrdXPdbDutVGjllBoTN8cdz3SWjCpampg5TBikArxmNEYMDQvL6n2lkUcetRJR" +
        "gQ7TYLvFj9+SycKXfM5CUXAyCfcU/QwDghhZgc99AuDZtJc=";
    public static final String Intermediate_CRL_CP_01_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMS4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIz08WhMpG2JswDQYJKoZIhvcNAQEFBQADgYEAoyO/" +
        "xcpJ0Obj4rTXhHFd7XMzslt79njkEgdwnon9BaYB3xSmkEXCMwLMurrjVYKaB6SWAiPeUv" +
        "G7ScDHJE6UFVJwIt4vP/M7gTOJ7uak33aWi9e5DeIuLqE6pFqTGu+uoBkkd82SHg2GhJhZ" +
        "VXDtJ3UcO/3JQPbslc02s9HiRBg=";
    public static final String End_Certificate_CP_01_03_crt = 
        "MIIChjCCAe+gAwIBAgIBBTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMS4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDEuMDMwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBANAD1vQj//4BGEXW1Q7HX/AUyFJFyHoYcvg5y4u/" +
        "8Sj6okriXj3knnBKDiJLpKfcsO5p5MQS5QzAc+lxErXD+duiw8lm61hj0StsRzhDFsaC1g" +
        "akjzU70R2Tmz/djUnqO3aa2wICc4NVAXnIMMsH/b6XXFZpC0/C32TPTv9aa9mrAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIPw2wltiRqz4wEwYDVR0jBAwwCoAIz08WhMpG2JswDQYJKoZIhvcNAQEFBQADgYEAln42" +
        "iR3eHyazF8CRjS9Jnas/26MaBtjUyDtcSjTVDWFlccwrQ7TgtzjkNm9fCmgSyvryDnUYGM" +
        "DoEjwYNLIgtCAkVIEBTmJvlqiPHH+tV5oJvIav+Fn8okHpuuK44umDcdKiFWlOyxrShxzV" +
        "3Bez/eHklaPTw/VsVhyh+Uru5zM=";
    public static final String[] TEST_3_DATA = new String[] {
        Intermediate_Certificate_CP_01_03_crt,
        Intermediate_CRL_CP_01_03_crl,
        End_Certificate_CP_01_03_crt
    };

    /*  
     *  test4
     *  
     */ 

    public static final String Intermediate_Certificate_1_CP_02_01_crt = 
        "MIIClTCCAf6gAwIBAgIBBjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05OTAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAyLjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC/lQLtWKzklgYuzhjMiK2CzFmzODsEY/JIVNdn9T8M" +
        "W4ufpGwnfIV62EUHCFeMYydKBm8Hyjbjrz1otINJmrGL5WSAX1/UPtHy1chgXOsFYD6nAH" +
        "jZAJJGw74nUbKw5+L1wUHU8qXABaaTrRpS1UdKSq4TCZ18NCjC4Oxcf/yDdQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQINsJcxaBqdugwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAOQP3iUX7FtJlL9nvu4F+8o/N5vr+OB28OsbYtW+Q1FzEfjkUGtT9Ri" +
        "teradpN/xUnS/oj3BfqFtNANkYKrBeqRtm2VeOC3kdCVFnWFME2aoRAQZbWvOwCFc3yLA7" +
        "JBdENtDNI54yYHMHPA4/2CuNQq1Iu1ektAS95DIe7ddxL18=";
    public static final String Intermediate_Certificate_2_CP_02_01_crt = 
        "MIIClTCCAf6gAwIBAgIBBzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMi4wMTAeFw05OTAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLUNQLjAyLjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCx/mIo1Ma/IN8OR7KOjclvIwsv0JFXD/T258DruDZU" +
        "uGoYiEbAc/ZN7R8OHI7dnv9pBfsvyEl7m2DVoLZnP0eXJTHjdZxb1TwPHoSIysi9u3xWlP" +
        "Rg+v+GGfKLB9pL0m8SZh97SngerZI14w7vQy0kkXziGatSpBoXtWNmsHJNuQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIoI0mSmDmzZUwEwYDVR0jBAwwCoAINsJcxaBqdugwDQYJKoZI" +
        "hvcNAQEFBQADgYEAcfs1pH12Qwdhv4NOJO2xxgMZZo8+A9Zl9c7RxsvuoZOOyCxoE9wT/l" +
        "PdUpGoGxtIPoWQs1qXEXnAlXJCXjLCJUHIG1/E6gQUXW0Ty6Ztpc5Dz06pPTN2gt+41B3J" +
        "sL/Klqc4iyCaWr8sYgEPQ8nColWRmIwk9gAasPNkNhyxA3Y=";
    public static final String Intermediate_CRL_1_CP_02_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAINsJcxaBqdugwDQYJKoZIhvcNAQEFBQADgYEAlBaV" +
        "VfrZqvyRhGXNYFik169nBHiNfKpw8k1YgFAQeNYdmfScq1KHmKzDhsx9kQteczBL7ltviK" +
        "TN3CKlZW82c16mfd4yYx0l5tkU80lwKCHSUzx92+qrvYjSMup+bqSsi8JhqByBf6b0JbKf" +
        "yx53Vpw1OCzjxrVHcfHPx8Q/vR4=";
    public static final String Intermediate_CRL_2_CP_02_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1DUC4wMi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIoI0mSmDmzZUwDQYJKoZIhvcNAQEFBQADgYEAhAHP" +
        "QxpcrTTN0GXeOwoMXuQUoHMvezEpM0BYOVLzI3KbRXWa9iWZINr99cRQvonMtOGkhIH3iS" +
        "wSNbsjmF9HX5UvNzrofOWataVP+macpCuNlK0NS3xxJjKRWOB9C1Ib7tiSSrQqIPcchlF6" +
        "vofy2ALEL6Usa1UTVYMhzGYnVZU=";
    public static final String End_Certificate_CP_02_01_crt = 
        "MIIChjCCAe+gAwIBAgIBCDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1DUC4wMi4wMTAeFw05OTAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDIuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOzYq2murB5ZjQd4wReI51Lc1F5VwK90OMGRfi71" +
        "YvwdRjgCudeDXZGW5ayid82y+eTDKFSzo1Li/BPTUXMpeqHHMCmLeefqxAWmz3aDoilF8I" +
        "Q53PlejnXJdntsal44w6WdP6ssiXlwzcZDnobAfuDTPgsnWWfzAkr1/LqEw/QZAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIP5tVdEyxotcwEwYDVR0jBAwwCoAIoI0mSmDmzZUwDQYJKoZIhvcNAQEFBQADgYEAkVx9" +
        "S/20Hir8qMnfMpMGTgMKoVeWoljxim83IkNs1Xqe1oLGHdyDUA66uF8wPkoTqGrfDYvgBa" +
        "5Mi0iJREnMWoiWvCe467+L1b2gtvRBMl9bcRj40bvelk0Wn4lBl3VuKXarP5M0PKT5OWvN" +
        "2cPLNeXHvV6ZIrC4rmK2ISpIXX4=";
    public static final String[] TEST_4_DATA = new String[] {
        Intermediate_Certificate_1_CP_02_01_crt,
        Intermediate_Certificate_2_CP_02_01_crt,
        Intermediate_CRL_1_CP_02_01_crl,
        Intermediate_CRL_2_CP_02_01_crl,
        End_Certificate_CP_02_01_crt
    };

    /*  
     *  test5
     *  
     */ 

    public static final String Intermediate_Certificate_CP_02_02_crt = 
        "MIIClTCCAf6gAwIBAgIBCTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw00NzAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAyLjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDHJmlRKb+mjc61iiqGe9gx/VUMLNmGrXGRYKMmYSxO" +
        "Q5sGLoztd2XtEgtZEPwvzd9KLKGP3XmgTrc4BGohqoFoG9Qb+w2ZGFwVC22GpeSoXc+J2u" +
        "2t3uRKYgboHpB0Jk42XLy+2wSEtS+/er7cFu2ufdPsvT4J1AqiuZSco96vtQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIBvoP1E6PGiMwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAmOyFq2vZrUNDVWRcyzYvZhs1uQ4zgXtfqnPE0V19RgaYffCrSCI86z" +
        "5kyDUyZwbGABMxBaVxEw536MesyDTdZdEVw6lN5RRtxr8/WEiSH6oI6t0xNxuNOkSNpz4d" +
        "28HA4UfUvtXK8RK2YZnPAd6UXsRUPBPXKEpzy4v/9RyihSg=";
    public static final String Intermediate_CRL_CP_02_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMi4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIBvoP1E6PGiMwDQYJKoZIhvcNAQEFBQADgYEAALlA" +
        "f3IDWexcdkMQHWTdGeFe+bG5dBvVPL5ZyQUw9DWbLwrjw/Jm4v9t+HLjETLSymsFT4bW21" +
        "OwnEiAAdaKT96k5t+sTyU5QQ6HL/jRXLHLGdCQgMFCglm5iNqaCLIFoMAVCaFkYtFUE3m/" +
        "iVt+319JOh5UyshMuWrAEW0IGGQ=";
    public static final String End_Certificate_CP_02_02_crt = 
        "MIIChjCCAe+gAwIBAgIBCjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMi4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDIuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAL/Src6e8qXwL+KJs5+v+JsakZdSDqMAFJUMfA2O" +
        "OO2TIqcvDFHzqesX+G+28MUwy6++ux07CD3FCaapgzBN4zO4RfKcamxFReKMKcEvNVVCOO" +
        "wO4Lvku1Sad14oYyGLOMzZwZFjRp8paaz5g87k70EOPBLeDlFMcch36czw53sLAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIPoHc2Sfk6XUwEwYDVR0jBAwwCoAIBvoP1E6PGiMwDQYJKoZIhvcNAQEFBQADgYEAFHhm" +
        "o6QRFdO1x1wp7Jb1QQAlChFfP8MrGVNK04Ur8f+wfkwIypTDifJ0AoFpjcM3Ohu9Ixvb9q" +
        "3kCSIWKDnWtDWw1/dN8mPL5If5gGqPA0+wRbUKVKvduOg7hKr4mWjKw7oYiaJuIIoN9RRZ" +
        "ejzltd0NEaODNPW/JaKeQUVgZbY=";
    public static final String[] TEST_5_DATA = new String[] {
        Intermediate_Certificate_CP_02_02_crt,
        Intermediate_CRL_CP_02_02_crl,
        End_Certificate_CP_02_02_crt
    };

    /*  
     *  test6
     *  
     */ 

    public static final String Intermediate_Certificate_CP_02_03_crt = 
        "MIIClTCCAf6gAwIBAgIBCzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAyLjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCaJ7NcOvb22F6HjMF1R/AORa4+pKFfFfd9teXPpVWC" +
        "9InTq+alY11QaSj27Qg0znOIItmf2W/8Dub9sjnbg+SgAkoV5+CAkplodRNC8AbD4x8rh/" +
        "fioQ8lb0Qb4Dn9I0n2wjOgitmMRdE2uW4uwVpH52vsMyenbDVxVI7jA4NS/wIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIC2T+/BkG93AwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEApr6kDXVY5jYt23wC9n3LmhoxDoWh8cBQxcWmr1wpVxIrCbaP0/y00a" +
        "29wbewKfucUoh/W2OfjNcohjpKRrnVmOpi5vN7SmbZIHaxbKLzyQ7JwF17aznyCSZVrGpF" +
        "A/S49T5rlCm8KDBcc2ym7gRJzwUApbC0Wws4Pg46czrpQlg=";
    public static final String Intermediate_CRL_CP_02_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMi4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIC2T+/BkG93AwDQYJKoZIhvcNAQEFBQADgYEAlBFY" +
        "vPxhFYsjFOIfQkd7MwKIi7vgPgoWTP5f+QlI0ison5n4N3rYJv31hTZRRRP99JZce1hY6J" +
        "Qiv1OtkpG7VfQIhr0FAGxTNaJD6F6rLbGjG8cap4+VibFQf5gZv0XQcyW4akYiRqSXImYn" +
        "NVlNyaxiJja+5GA9XVqvWOjjz4o=";
    public static final String End_Certificate_CP_02_03_crt = 
        "MIIChjCCAe+gAwIBAgIBDDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMi4wMzAeFw00NzAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDIuMDMwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMlW6FOLwhRsKZM6p0ww4QEWjQzjpjYhKnz3BnLw" +
        "SdGZqMe4wzZnDWc/0eyDOMCSYXIWQhlDMqQn2zCVPbDKzMRkdEeRSvE6ghhYP/hn3ipjSw" +
        "D8QwaqofCp0sFkbDPke+xD2tMhLdUyNKynPjpSQmYtfoA98PD7so3cSAtrYuSDAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIc/X6kp7teCQwEwYDVR0jBAwwCoAIC2T+/BkG93AwDQYJKoZIhvcNAQEFBQADgYEAStub" +
        "g3DzhJgzYO+ZmRc0acldZGwZFm6F1Ckc1JzQDgVHU0bnCANgBcJj49UV2MwbNKPQdVzdwo" +
        "c91rfwrSY/PrvVQ9tUonZ28y/esFRBAdJTLf4u++p/gI3vfCvEXa5xVTIz1Hc+iKzAGKrI" +
        "cveDHy3ZZluQ3J6tbHs2BhnQFXM=";
    public static final String[] TEST_6_DATA = new String[] {
        Intermediate_Certificate_CP_02_03_crt,
        Intermediate_CRL_CP_02_03_crl,
        End_Certificate_CP_02_03_crt
    };

    /*  
     *  test7
     *  
     */ 

    public static final String Intermediate_Certificate_CP_02_04_crt = 
        "MIIClTCCAf6gAwIBAgIBDTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAyLjA0MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDgZy2Xs5pIoJrT7GuagmKLrn8F9rj8p8w2wELorGhM" +
        "1HJMVOurH+o+y6RXd0oMGJkKNrhjEnbHKm3PBYiLgpCjVEcFNhQF1OOxJ7RdahvA9ifsuw" +
        "jV1TxTGq35jeaJYASRXb2TiNfzuPWSVm0MWr5zz+YB6NNuvjxwEBgZvNiV8QIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIWAOnkHkwSVkwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAMiHozz92EOhSXU/krwQVs0GNEWoAUH3LHt70Zr01dFzEF6QhA/wUa4" +
        "+V4XwbMob+q4zGnTHj+tL9ChGWi3NDGELQ4cN64OMPsToGKkepLy+sDwdm9LaUP1bDvPxd" +
        "v2hjlskJ7TEu4+6ltXSG/k36Jk8C0/I/ayNGbYcEcLyes3s=";
    public static final String Intermediate_CRL_CP_02_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMi4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIWAOnkHkwSVkwDQYJKoZIhvcNAQEFBQADgYEAVtCi" +
        "IocktnWOwWiaOc7tTUJvvH5+IYVyB/XhmMhF7cDbL292gyrnuh1+3+lHwZQBPoF9kzF0vt" +
        "WaweG7mDvYKxENQODdph/VcnypgUiFTWRTIPB1ZXfCTMWYf2QSalpHRDR4vVsqF748QbcG" +
        "E9mbzvLUz6NDA+Vf8wEwZehqSDM=";
    public static final String End_Certificate_CP_02_04_crt = 
        "MIIChjCCAe+gAwIBAgIBDjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMi4wNDAeFw01MDAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDIuMDQwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALBX5GIQtvwswWwMDDPnphIk1rJSbcq7iClXLM2E" +
        "kgvBu+hbOzb0v9mtl0KJB71TWJCfwceVQiXc3Gk+YduujAbZRVTkROf9UOWD9bfrI7g+52" +
        "g4ms2n7evCO33b+kGEf4I014xl8dJDWtHK9Bhr+569RW9TzO06IeVeTD7whxMXAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIuKXv5WkUTWAwEwYDVR0jBAwwCoAIWAOnkHkwSVkwDQYJKoZIhvcNAQEFBQADgYEAiu0B" +
        "yR5Ru8qVsgRqkOpCvrJnkqBAImbbR6+BUYH0juRxxKzKnbFOjU6a9WvkKpEBB8Q2xLynPN" +
        "68ecLpnOynx3xj2sWWSVbsRKPy0iOesQblKrq3yHAm4lhzoWA8t1Xz29Ko1WxylDhyxGpR" +
        "QAWsyGVCfJFlsZE0ibw3erlWTnA=";
    public static final String[] TEST_7_DATA = new String[] {
        Intermediate_Certificate_CP_02_04_crt,
        Intermediate_CRL_CP_02_04_crl,
        End_Certificate_CP_02_04_crt
    };

    /*  
     *  test8
     *  
     */ 

    public static final String Intermediate_Certificate_CP_02_05_crt = 
        "MIIClTCCAf6gAwIBAgIBDzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAyLjA1MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC2d80bD1RounqjKizkZJYPFUuVWZQ8W2nZDkEp8qR9" +
        "fRWCAGOZGs84tgHj5gasmxy1mxJc9ogyQ2mcZhJRitRm5LVNuGevO6JmfqYtJxbW54aZGE" +
        "5AWSRXqjJKJEih4VmPjA3vjQaSZSZJnu0DSnO82qWfu1ZUDlvIG6dfKJWRQQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQI3uNhI+QuI4owEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAG/+Rpk8dYrSFdaEO8Ch5tuvvKTOMi7W/DRA4B4xR7WyRJmosPB+37c" +
        "teGKVzqFND22Xc8xQH/b/nxYW08sCSLAfN0cRusoSWwWSRtPO2f9fyC/BqCy2B2kQLFNPM" +
        "Bk22jNFwLqPUeZn1UHN05RFAqVx325kpl2m1V7tw/mrXATI=";
    public static final String Intermediate_CRL_CP_02_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMi4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI3uNhI+QuI4owDQYJKoZIhvcNAQEFBQADgYEAWZUI" +
        "2VGY4pak0kICONP/CKvamYFs5txJfR69AC5tEJ+Fy3PmSeHkLUZf/oc9d8EEyr0MsIjRHj" +
        "N4X4MquMlk4FflZcc8GblQK8LdXBK4Dy1SiXHA5GB3U1AmgzAzEQGwGRZnzWP5+rJ65upX" +
        "vksAYyPQmruRM0O5sElctPn6B+Y=";
    public static final String End_Certificate_CP_02_05_crt = 
        "MIICiDCCAfGgAwIBAgIBEDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMi4wNTAgGA8yMDUwMDEwMTEyMDEwMFoXDTQ4MDEwMTEyMD" +
        "EwMFowYDELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UE" +
        "CxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5nMRcwFQYDVQQDEw5Vc2VyMS1DUC4wMi4wNTCBnz" +
        "ANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAviLKpW4iblWNLQfmBJJ+ruMgygmjRWfoFGya" +
        "Ndv2ma0Ugqm5xXq8c0orbnezwSp+tnzZZhG5KDNZr5+z3krCkqOGGzuUvVLqeJxPOLu7Js" +
        "y472nAA7+FhwfZrXUI+Vg9F4qF+Ye81ivDrYVAEmalCpCyHOAKdvwkwQjRucifu90CAwEA" +
        "AaNSMFAwDgYDVR0PAQH/BAQDAgXgMBYGA1UdIAQPMA0wCwYJYIZIAWUDATABMBEGA1UdDg" +
        "QKBAjgph7BA5L7dzATBgNVHSMEDDAKgAje42Ej5C4jijANBgkqhkiG9w0BAQUFAAOBgQBr" +
        "MDMv9NWCTIQ3blMEqPiEyjiBhSJl88Cu797P4lIn+gc6E+0vZp61X7B2k5CHgsnxyVLK5e" +
        "bwl0bYAPKwRI9yzHLrj71RNw8HA7PCRPn1GNrtBBbIpLE0/sqLo51UPu/377+CnzYhIycL" +
        "tvS0KDLUTDSY/OowDcplF6Xwnt8cUQ==";
    public static final String[] TEST_8_DATA = new String[] {
        Intermediate_Certificate_CP_02_05_crt,
        Intermediate_CRL_CP_02_05_crl,
        End_Certificate_CP_02_05_crt
    };

    /*  
     *  test9
     *  
     */ 

    public static final String Intermediate_Certificate_CP_03_01_crt = 
        "MIIClTCCAf6gAwIBAgIBETANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw0wMDAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAzLjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCuF8mub5cgUYZytrRjJ5Rhc2fgazGxWIj6EIKzeSpo" +
        "FwScItRX9KxnTIXEBTguBk7eQUsbN8yu49/Mlq45EAnemyZRBWzLFLYLPCco7pyTsWm7Ps" +
        "2FAGJ3vE9pC9xaZC+KrwF3Ho+DZNDwhj5InXTP8pChAIPfB8/7V/2mk0lN0wIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQI4mI6Ojs0onswEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAMVGzU6f4YOHpHla+YuGCjHOUZYrA9J25G3UFFoPr2JZEG+Fb5hRQUh" +
        "4S1qUQKXn6dpVua+qTJDk3Tg2N8OdIHG/gy0hvYHsxhLCSDQBsfPN7p3FClM7r/VHOqgAN" +
        "vzT+KYvxx6gwn6O+n7ERkrBIfkyrGFhnmjx3+VOCc9P4SDE=";
    public static final String Intermediate_CRL_CP_03_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMy4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI4mI6Ojs0onswDQYJKoZIhvcNAQEFBQADgYEAfwYf" +
        "4kAG4srB2VxWimJs1HwXTaPDooellQclZ5hP/EluT7oe03+ReFef6uXbHt/xRdeaoQhJGy" +
        "SP8dWf6UIbL82oaSYqChIvAZD6zTMavEgSET0PlUsK1aEMTpMEtKPvedFSOTNBaMNvMzSW" +
        "t5xwurn63qyXTOxHf4m2L4w8+i0=";
    public static final String End_Certificate_CP_03_01_crt = 
        "MIIChjCCAe+gAwIBAgIBEjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMy4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDMuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ/ALaZ+MdNxKDH49+7jUm+17DII5QQEfjk8IaEU" +
        "syApOhsByOG06HPItiBEnnfDDxU5kjsZDtw/9LlouBocNXAJt+ZmL3QYyOgeH4SQ4f21rw" +
        "7j8fw57gUkP5oWhEc0loXr/hB92hoKbsBoRpv8F1zPZcPNLUnyUzqLH5+CeIibAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QI822isg/wPCowEwYDVR0jBAwwCoAI4mI6Ojs0onswDQYJKoZIhvcNAQEFBQADgYEAilIn" +
        "OD0iQrLrHRkO4zr9S9VXAJXJV3l9wfbLBweXM3q/zt4HGKBw4Wq1Yn+AfDxXrBtJA5hP5e" +
        "d7CDd4eM93yeKozdZCLNZfUM8sJ2/MRh07tvwJ19e2STklED8b/ndmr5my8H8jjJDaaYww" +
        "qTSnXqpcqsUsj+kV4Mk0DvVWT3w=";
    public static final String[] TEST_9_DATA = new String[] {
        Intermediate_Certificate_CP_03_01_crt,
        Intermediate_CRL_CP_03_01_crl,
        End_Certificate_CP_03_01_crt
    };

    /*  
     *  test10
     *  
     */ 

    public static final String Intermediate_Certificate_CP_03_02_crt = 
        "MIIClTCCAf6gAwIBAgIBEzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAzLjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC4AbP8gDUUcIa8w4pEsGgbYH2sz08QMUXd4xwx691i" +
        "9QCcyWSovQO4Jozeb9JwtyN2+f3T+JqZL/gwUHuLO2IEXpzE2C8FzQg6Ma+TiSrlvGJfec" +
        "TlSooFmEtD3Xh6I6N5PM1fpyyY2sOOhARN5S6qR9BOuxkBAqrAT0fgqD2TswIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQI97nJCqq6+kIwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAWwpfh9oOOvj9xHS0zcczaUIHTkpjgk09I+pERlu0Z0+rHvpZGge4Ov" +
        "NDFtMc4TgthGcydbIwiKogjtGBM2/sNHIO2jcpNeOtNKLxrzD4Y0Ve164kXBu9Mmsxx4sG" +
        "7XUXZWgiOPfu/HmyPVdzbIReJdQO515SNx7JdgVyUkyhBxM=";
    public static final String Intermediate_CRL_CP_03_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMy4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI97nJCqq6+kIwDQYJKoZIhvcNAQEFBQADgYEAC9Hv" +
        "NevV6/Oz3wcgEbDgZYRKJRdr4OW4Es7R4ahjz3sH6GXZ1HiEjx2+frmp8LMshQ4D+hpjRk" +
        "drSPko1M4a/fQCYxbonZ0xjpYw067dwLmr56+GPJAxkzcSmFKXx+ejyQpG+9+qCR+zm98V" +
        "lop6besAaGUjZKnYShIQOfNzDZk=";
    public static final String End_Certificate_CP_03_02_crt = 
        "MIIChjCCAe+gAwIBAgIBFDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMy4wMjAeFw05ODAxMDExMjAxMDBaFw0wMDAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDMuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMJMiW+G4bgoRaYz2OUu/+PQ/yp4JgFOB3Vegf5/" +
        "vIrF4gsnoQxOCCsO5JTLrbS5fi3COjvM5w9/SZpNHtSfyWb9afmx4DdrT1bNjma7I6PCid" +
        "yxMzX4iTLeaMRnqBk4A+/0Wf2+4VzCqr8aViIiQ7u2JfZiTQ4dZxDoUW6G8lrbAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIEjny2GzFXGQwEwYDVR0jBAwwCoAI97nJCqq6+kIwDQYJKoZIhvcNAQEFBQADgYEAJw3T" +
        "3aL3pYbZhswgshOvJ9Y1qv65R6rClSxB5lqBw6+Qki4ZpW57NK8LwaGS03XzDUPaDi4/9R" +
        "hGCHpP24fIskS4n4jNZgKpGtt6VEVorUH7cOLNCw2cuwMlKbkyZnNdx2JqTMMlHzNJ3cmy" +
        "aX3F70IY0OZbwCKdUo/uMVC6hss=";
    public static final String[] TEST_10_DATA = new String[] {
        Intermediate_Certificate_CP_03_02_crt,
        Intermediate_CRL_CP_03_02_crl,
        End_Certificate_CP_03_02_crt
    };

    /*  
     *  test11
     *  
     */ 

    public static final String Intermediate_Certificate_CP_03_03_crt = 
        "MIIClTCCAf6gAwIBAgIBFTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAzLjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCjLYKGKEMJgC/r0NH7vubQZ5qPEFEEN6QdLUWWqf/O" +
        "Yqo9hboQq6S8dFHp3DVR5x/4NOdNRjsTABbXsnz8U+L7+4CorhDhXj29weGMYIIfJ3XSIb" +
        "T7sE/GOPmXeGhrTv2zucI1j80sN5nTEoiGFm10LQqAgoyV46BxDltf3/D7wwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIhCIOyzfScpAwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAA18kQijoJebmTQS7n/q/fQx2iblOJaJAWQLHeGCCGqKxCjUpOxuD+y" +
        "xMspmTKdQqEkqQ5vpHdFYQ5MYuecqAdp6woWUNQGVd4HHPmHsAW3Oppwb0yLggYs8IVHjm" +
        "dNO1pYb+YYciCKBtX8D1OnedIRcrQmDMJUjbfmAEv/4b0EM=";
    public static final String Intermediate_CRL_CP_03_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMy4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIhCIOyzfScpAwDQYJKoZIhvcNAQEFBQADgYEAk34j" +
        "SxMr8p1h1qJWlfoh4er9pu1AkkHujovan6Ctx89VwFdOS5Kw82OCvD+nmJAHrFuncNlClf" +
        "51G8FCEAFLhMNwic4WAxrBX15hcUTaWk8Wj00dfUFwjG8/Kv3QUCDBN8f3KC8/oBeORRX9" +
        "dHW5ei2IUKuD1ITCeIoyRDBxQIg=";
    public static final String End_Certificate_CP_03_03_crt = 
        "MIIChjCCAe+gAwIBAgIBFjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMy4wMzAeFw05ODAxMDExMjAxMDBaFw01MDA3MDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDMuMDMwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALSw1Ey7kzFzzjMS4oTSrZH/95NMHLxtUSaVGMCy" +
        "0q2iLfGZ79eTS9megQUranYlIuK411yvFtskbFKf0idMKBtM8nX3Rxubm5EnbnpgvNrBEg" +
        "0FbOPqpSaR+8pxZ6lweB45tkzLU3OZeAZSpGOY1UvT/htn6Ae8JQAVajSvYyfNAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIF014kOHikvcwEwYDVR0jBAwwCoAIhCIOyzfScpAwDQYJKoZIhvcNAQEFBQADgYEAdLMM" +
        "zGPPvBLgPbhn2tba/7HiaZaayHIxTXmpW0KAhP+8hwapOitrtLGPwqVtxQ3GoSMZJPMDCV" +
        "WsrT3OZm27G6ytqqNZ2ZO49UC7WwQ49TVlN79Ui9RZIBnRzlMIDNKsyuohfSRhFZTkWdoH" +
        "/y8ulY8k4xBThV8e8IRgtYj3nhc=";
    public static final String[] TEST_11_DATA = new String[] {
        Intermediate_Certificate_CP_03_03_crt,
        Intermediate_CRL_CP_03_03_crl,
        End_Certificate_CP_03_03_crt
    };

    /*  
     *  test12
     *  
     */ 

    public static final String Intermediate_Certificate_CP_03_04_crt = 
        "MIIClTCCAf6gAwIBAgIBFzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjAzLjA0MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDbUii3czeUQ2zNlxvrhnJ0LcBGxCDHFr3xx+plDg3f" +
        "uasDKCY/VjCLEfQ5a2oqcovvGKsd2CPXbCFJtimW1R7Dvt+a0y95fppsdseorYDikiBlOj" +
        "ja6LR3Cz3bslYc133C+W/MKHMJ0tdvtTk+SJrq7lqs+iv/b/xHC3k/gDjIswIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIFNw3o1kc4XkwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAn/pr7/noYyjXSKEe/eLk3l4Rb6PEhNAnzySmxGkjIjWKAgh5IVYSGV" +
        "KFO/FaNOiYkRFHwXZFNj71q7gbM+HwALurN0Mr/MUA1TSpPy7YhFL0SWq3C3XsC/dVJ50b" +
        "HmTW+dGcxboX0h9HeKFxp3VyOY/dUut2oc+s/TnmqQII1CU=";
    public static final String Intermediate_CRL_CP_03_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wMy4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIFNw3o1kc4XkwDQYJKoZIhvcNAQEFBQADgYEAMoJ5" +
        "jGE1AxxfluixG8Sk7H4W2rqSEkQyNHfnlKSMbh9KZA3evI8HGKGGfkbBNoe4/HauZ4NVFw" +
        "FXgllCp+TI8Qd+HafFoDv6ff1K7T86p6r7tE3AEM1XmbnfohP3/ivpIzustv/f2rqjxILK" +
        "Ldvrth2/OlNygwY+D54lcWH1DX8=";
    public static final String End_Certificate_CP_03_04_crt = 
        "MIICiDCCAfGgAwIBAgIBGDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wMy4wNDAgFw05ODAxMDExMjAxMDBaGA8yMDUwMDEwMTEyMD" +
        "EwMFowYDELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UE" +
        "CxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5nMRcwFQYDVQQDEw5Vc2VyMS1DUC4wMy4wNDCBnz" +
        "ANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAuSL9tB1JW6JPUO2Xw6TMYkPX41lru3EPyYko" +
        "YgXy4giy6LGoqbgtskHehD22v3rfWjqOd9iV2PBio/vYE4zEz0H0n84dpnBvog6A1AlE19" +
        "PkQ1txjzIA52FQIRwRfZ38LaulQEfJ0a+fiRHQiM960O3YvHXV+GEbNcw4jo8b0sUCAwEA" +
        "AaNSMFAwDgYDVR0PAQH/BAQDAgXgMBYGA1UdIAQPMA0wCwYJYIZIAWUDATABMBEGA1UdDg" +
        "QKBAh9/WgM+UT6bTATBgNVHSMEDDAKgAgU3DejWRzheTANBgkqhkiG9w0BAQUFAAOBgQDR" +
        "I6PKUGg876/fSljtqxXCR4CoGAAurNFOcM4EWeoc6ZvuDOi3P7rNYiYAXXlmp7epOAgvZP" +
        "EV4vS16ODaJO6qIMR1YsaGEPo0ecT2pEStvP37X6pb5TdyjyKYF3586IN6TJdFMFsW/Lqg" +
        "tucl9bGlWmfTVwxTexq6+D8diK48KQ==";
    public static final String[] TEST_12_DATA = new String[] {
        Intermediate_Certificate_CP_03_04_crt,
        Intermediate_CRL_CP_03_04_crl,
        End_Certificate_CP_03_04_crt
    };

    /*  
     *  test13
     *  
     */ 

    public static final String Intermediate_Certificate_CP_04_01_crt = 
        "MIIClTCCAf6gAwIBAgIBGTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjA0LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC5UJ+KMj8tAmzr3OGYL2gSFcNTf8ik+ZVxlaPVGHyS" +
        "KjYQBAEbefhfg5Ps2aIuqBwYkbtFXuHif5GEhgObA4InCyESeRjYLGcVMqwSZzAOFAR0dP" +
        "1LzgzQs3ZgG9JX5MO5wEZ8IMnVN4Otu4XIlWSgIpUNS2vyet8Zi7t9fX+JewIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIOZvfph4Uu9YwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAXMyscmGpKSLG3hQltMQLegy0+g5wzgOrbFOWxZmiVNR+zSsHDD3UAH" +
        "H4SyTozlooC0jAY4yAhZ5RX6SSJKx9fHsOZD9ldCmst14qLk3pkI+M0QiPBZkVTx5/7dR2" +
        "wGkuNKSVWH6woOq7BbEzpO7xMlrUr6tgHt4Dc6Evt1pVZls=";
    public static final String Intermediate_CRL_CP_04_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wNC4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIOZvfph4Uu9YwDQYJKoZIhvcNAQEFBQADgYEAe79z" +
        "iEUgP/mvouJ9ufit1y4SjnHQWik75W65eGn/XGArRrBqJ8jZVJE4/rpDBbzm2V0hQoWU8z" +
        "zchZFlesUyqQZ9KUlT0YGR0YPcNw/V+58RonWWfmU3M2DvWDrXgCOXPm61+AYq4+kTowsG" +
        "0stmeML6NxjDzWpfAgI/MpXqe80=";
    public static final String End_Certificate_CP_04_01_crt = 
        "MIIChjCCAe+gAwIBAgIBGjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC45OS45OTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDQuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPiAZKXPjK8jvaNj34VynyKPK7dQtFysBPKFW5Y1" +
        "Bc+OMsyd2pPpQoJYcQTMMomlAqoBvSXUJCMNly/BxVuvn7l6I9crtx6PjBBUlEzdcsscaa" +
        "EaHuCCVl+Msnr66cSV3GqVGAhujun81+lyurcTEog3ftsohwbQnfA76qNU/N3/AgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIJZPDbf2xNv8wEwYDVR0jBAwwCoAIOZvfph4Uu9YwDQYJKoZIhvcNAQEFBQADgYEAZf4L" +
        "1RDHDXwwA2CgcIhM4CAfZ72CR2zOan0at38VVFB3u9vs4VLwFcrOQCIjDbdLijc0XWLima" +
        "4vCD1qrsv6Hk5+6113HfFNmD8mp6X5jAwoNPa/I4kmFOA8iIm4TTk7M75vQyCQTPG0VzbU" +
        "Nu3uwTbXKm5ME9C5MFMf7z347CM=";
    public static final String[] TEST_13_DATA = new String[] {
        Intermediate_Certificate_CP_04_01_crt,
        Intermediate_CRL_CP_04_01_crl,
        End_Certificate_CP_04_01_crt
    };

    /*  
     *  test14
     *  
     */ 

    public static final String Intermediate_Certificate_CP_04_02_crt = 
        "MIIClTCCAf6gAwIBAgIBGzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjA0LjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCteErspc5ekSOel/wmjn/XQ0HUy4XzxB5Zj0nGn9FD" +
        "PbjF2LERCHOn5aBnIMHYhyr7PDynwbvSx2egzGC6wGe9Zrri1MteirQ9Ppw7062IIleloy" +
        "UAiuwvD+s0npKsvboarQsCMfOB1hOB1tGG1bjXP6B5B187SZXuR3KawggyJwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIUjnGp96itUMwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAR6fmN+9p5AWy/asEAiVBnbY9q7EQXyB8WuZK9FtFmupe3hlfcTq84E" +
        "A+TGvXOlNr05/1iLRv82GsWXDif7DlGVPN8CS1+0kb5Ve8Pmv2ziiWVREqWx916ioPjDRp" +
        "wvdGcCNC26+fyvv5TrP8uzojurl1ZlVRRqi2sIbopVX5r8w=";
    public static final String Intermediate_CRL_CP_04_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wNC4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIUjnGp96itUMwDQYJKoZIhvcNAQEFBQADgYEAZkXJ" +
        "aJG4QDE02wFURwaxWuv2VyD7m+N/2B0/9KR+6UKVpsMd2XHq+G3SlFOa6dA/fHUdhtUs2D" +
        "gpx3SfQYbcgKFrryZHqJDK230eP3F41S9g5XJTRaNR5iZvxvh4bmSf4l6a5MXsKEoBoJoT" +
        "j8cU4qg6j7Xk4NpIR1JbWiSIYQc=";
    public static final String End_Certificate_CP_04_02_crt = 
        "MIIChjCCAe+gAwIBAgIBHDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MRAwDgYDVQQLEwdUZXN0aW5nMQwwCgYDVQQLEwNEb0Qx" +
        "FTATBgNVBAMTDENBMS1DUC4wNC4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDQuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALM7mfq+hpLfvQdqZUJfIx/2gFcgHS2AsgZn0An+" +
        "Yn61WtG8K2+lt/a8aypa/q+J93RVkRYKWKFQcJHiRgx7DMlXElVnfQbSFuLX46ng4hqmQL" +
        "sSOKmXDld2BlyMZ41B3rfdhJT8P12RMR6uAwvc9CH3b0UTcsc498Kj+JeaRbzxAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIo7S64S6t5nswEwYDVR0jBAwwCoAIUjnGp96itUMwDQYJKoZIhvcNAQEFBQADgYEApNT5" +
        "Y+9Jc28m5Qwjm+/8SKk83iCPnIW3BsAvQUB9Wmd1+kMZvqLySQjm1tBBbcGYuSERMJ2Et5" +
        "eoTdL9B6EG2CZYnPqu1vk0TVugRxs7IJm4h5z4MCInf2g1KTt0AMEasQW6ZTj7DIkkU48Z" +
        "EKLPoBGXfD9t9Y9cmdj1e1RQbog=";
    public static final String[] TEST_14_DATA = new String[] {
        Intermediate_Certificate_CP_04_02_crt,
        Intermediate_CRL_CP_04_02_crl,
        End_Certificate_CP_04_02_crt
    };

    /*  
     *  test15
     *  
     */ 

    public static final String Intermediate_Certificate_CP_04_03_crt = 
        "MIICmzCCAgSgAwIBAgIBHTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGQxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEbMBkGA1UEAxMSICBDQTEgLSAgIENQLjA0LjAzMI" +
        "GfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD11QBcw4P2rTUfPmbVNYqdo0AMmcB3Yxsx" +
        "Iz5me/S1I2PJLtRh9KP7lUV20SMEFsFKtE1C+9O7ODtOUCJA/6ECeXbyj20SbG1E2oQrZe" +
        "gkcn7IQDUgnuedzdFj4kTevok6ao9hycg+qeZrL6oeBD2XQCd9nqMmzhihNu/QOSnp5wID" +
        "AQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMA" +
        "sGCWCGSAFlAwEwATARBgNVHQ4ECgQInx+ELo31rJMwEwYDVR0jBAwwCoAIq5rr+cLnVI8w" +
        "DQYJKoZIhvcNAQEFBQADgYEAriYMoRDpSPI4HWrxN1rjqWIzggz8p1wpbEFgK5o/Fi2KT3" +
        "jCd6bfCcIFDpoXNqlsc+dvzc4XB1Eg/Qbcror8HP8LSxrbFw/y7VhC+wCaDCmhcqQn3rp/" +
        "WaOWnR7/H7HlKM9m1u7MBtwlxHINnLKwPHIA1XwmAnItAXIL2yHRJhU=";
    public static final String Intermediate_CRL_CP_04_03_crl = 
        "MIIBUTCBuwIBATANBgkqhkiG9w0BAQUFADBkMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxGzAZBgNV" +
        "BAMTEiAgQ0ExIC0gICBDUC4wNC4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWq" +
        "AjMCEwCgYDVR0UBAMCAQEwEwYDVR0jBAwwCoAInx+ELo31rJMwDQYJKoZIhvcNAQEFBQAD" +
        "gYEAvJgOX6tewnRbC9Ch+Fe4KjkB9IAhe5anQKGfnDHuLfga6JEjOzyfhonWZeppJwvYpl" +
        "1rZbsKICNphMDkd/eaWnn8Q9w02ah4kzIb0LuzrNBrxpFv9AAidfGU2VeF0gRi02jtAZsh" +
        "gUNbrdC+ovA8mAsBigy+HMzCi61+wrumwvo=";
    public static final String End_Certificate_CP_04_03_crt = 
        "MIICijCCAfOgAwIBAgIBHjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "GTAXBgNVBAMTEGNhMSAtIENQLjA0LjAzICAwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMT" +
        "IwMTAwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYD" +
        "VQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLUNQLjA0LjAzMI" +
        "GfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2Rd0VKnTIrME7hzpnpIPGXGXZCjpf5lSO" +
        "19zvB3WdZumLGdwUBXpIQTrl5teYgL62PpOwNC93URZDEUt+rqoqvs8E7MpF3IulStp2+H" +
        "/xa6Ihf4OmkgKjpHNTWOIFXeRJ4sVgWuH6cqQ+6GL+0fa1sed1crsEgTTAGYNhFi6ebwID" +
        "AQABo1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR" +
        "0OBAoECBNwCFdDgPCqMBMGA1UdIwQMMAqACJ8fhC6N9ayTMA0GCSqGSIb3DQEBBQUAA4GB" +
        "ABAjSPg794yiVz9RqdNxic8TGnApNrZui/vwr1U8ZkETZfx8W1fWgQ0z7KjryML5IOmvps" +
        "zycM7by6jb2kMmxI1SQCwjiNQ1fb1osrNAj2bRfpp2YgjjbHx1XkddommtVc0V8kvyQBcb" +
        "7NdxfbwKr8AtpiWTWIajc2uqUlELsLzr";
    public static final String[] TEST_15_DATA = new String[] {
        Intermediate_Certificate_CP_04_03_crt,
        Intermediate_CRL_CP_04_03_crl,
        End_Certificate_CP_04_03_crt
    };

    /*  
     *  test16
     *  
     */ 

    public static final String Intermediate_Certificate_CP_04_04_crt = 
        "MIIClzCCAgCgAwIBAgIBHzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOQ0ExIC0gQ1AuMDQuMDQwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOFf5hr4R8IqTp53qQSiBEjOFQ3Q3ICcafl+FLzm" +
        "K3xIFqERjyXARsTM4gDQ9yntFeNp2TiIi98xBrz7D8TlrbTAmxO/PUfAQ68tXpz9Id/XrU" +
        "WeAKxMZULPL9nPFcGQoh0qq3JKpFRSb3Iobryfysblm7cCDDCJOI7uK14XZtTFAgMBAAGj" +
        "YzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMBYGA1UdIAQPMA0wCwYJYI" +
        "ZIAWUDATABMBEGA1UdDgQKBAjior7qCuLBljATBgNVHSMEDDAKgAirmuv5wudUjzANBgkq" +
        "hkiG9w0BAQUFAAOBgQBhh55gTy5htqjxW1Ch2hRrRikhBH7LJz1PmDuzwiIOtnWL+EiQOY" +
        "T6h3NV1j8Kn5S4KhUOrhnvrPXRi22HdqRzEPl7y/wXm6G0XcgYlyy2ofZKdYVWCVStKAMW" +
        "5SwV2wC5RPK2KphdhnlEqss6QVRUsliDDjnf9Saiey9nzJAfNw==";
    public static final String Intermediate_CRL_CP_04_04_crl = 
        "MIIBTTCBtwIBATANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNV" +
        "BAMTDkNBMSAtIENQLjA0LjA0Fw05OTAxMDExMjAxMDBaFw00ODAxMDExMjAxMDBaoCMwIT" +
        "AKBgNVHRQEAwIBATATBgNVHSMEDDAKgAjior7qCuLBljANBgkqhkiG9w0BAQUFAAOBgQBI" +
        "VlXD5FnIiO8tavLJ8qo/qRhbBNgUbFBdAgAY6yVnFNP6YN4qPineYPN6NV1XdqNDrZh2Nz" +
        "GHzX3YDo1Uv9yABVR0NvXCaMIW5/raqZp/on6bPuQLgJe9UisOPKunzehTm/NmO1RW9dwU" +
        "37UzC0XnVHyVipDVh07DrTKBUtQJQw==";
    public static final String End_Certificate_CP_04_04_crt = 
        "MIICjTCCAfagAwIBAgIBIDANBgkqhkiG9w0BAQUFADBlMQswCQYDVQQGEwJVUzEZMBcGA1" +
        "UEChMQVS5TLiAgR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRswGQYDVQQDExJDQTEgICAgLSAgQ1AuMDQuMDQwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMT" +
        "AxMTIwMTAwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQww" +
        "CgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLUNQLjA0Lj" +
        "A0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCegy6qOnM14CS7+enBElgh2DLtF5bn" +
        "ah0yfA18/hbqnmUaWOWJQllyXa8QFawnvdXOOEXJm1ErIm3rDYihkbUTP+ybOBH9dprWtl" +
        "1cSGL9CkoxwzkJRLQTu5xG72EhET3S3kwqZsmYbgy4MduGKv9VGFbv75Wr17Vo9K4Lz6QK" +
        "vQIDAQABo1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQ" +
        "YDVR0OBAoECEc4b3BP059HMBMGA1UdIwQMMAqACOKivuoK4sGWMA0GCSqGSIb3DQEBBQUA" +
        "A4GBADj73jXpPLev5crwZIoXCJd/nXXp1fJzEEbByWggsR9cFHN4wnp7N6gpIxQbLQwjmo" +
        "cLPC1pHQ3A5VHVrCbxAk6nifmSvnKFWHTBftZGpfTGkrXbURFF64T/CB4O+JXr1eBUGheN" +
        "Q0T8L17UNgi3oBENKjASWnpjxvD2QrOnH0rb";
    public static final String[] TEST_16_DATA = new String[] {
        Intermediate_Certificate_CP_04_04_crt,
        Intermediate_CRL_CP_04_04_crl,
        End_Certificate_CP_04_04_crt
    };

    /*  
     *  test17
     *  
     */ 

    public static final String Intermediate_Certificate_CP_04_05_crt = 
        "MIIClzCCAgCgAwIBAgIBITANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOICBDQTEtQ1AuMDQuMDUwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMBsWmrcKH0J9bkI3zHthZ0S3904f3fMUSasY5qp" +
        "7CSQ0sbXTwP947sfAPK4Dso6Bpwl0WExRCdFHd6qfY9wR+NtfuI/DkFEY8WveoqM4Vskpi" +
        "cutWghCx14PiPY5YGFn8VvXu7wbuHp4TnHtUCMEUt3EfYO5oqm+/I8y0eTKMNHAgMBAAGj" +
        "YzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMBYGA1UdIAQPMA0wCwYJYI" +
        "ZIAWUDATABMBEGA1UdDgQKBAjOoKlp+BfGqTATBgNVHSMEDDAKgAirmuv5wudUjzANBgkq" +
        "hkiG9w0BAQUFAAOBgQDLhQ/RJFqMDNRonAHZ30DYyphf8do4q6ARikhhXSSa6G2G/PzbpS" +
        "x3T+3G8ot+NnFhtf9ZWo7KfwmFEbUA/B/X2vJaJbNImkMDT1aTY5sPXtA69B3QKQVz7HST" +
        "f5XH6DjuoV0/m1M153A4vf1Z783dOPw1MzOq19t+6tYFeELEHQ==";
    public static final String Intermediate_CRL_CP_04_05_crl = 
        "MIIBTTCBtwIBATANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNV" +
        "BAMTDiAgQ0ExLUNQLjA0LjA1Fw05OTAxMDExMjAxMDBaFw00ODAxMDExMjAxMDBaoCMwIT" +
        "AKBgNVHRQEAwIBATATBgNVHSMEDDAKgAjOoKlp+BfGqTANBgkqhkiG9w0BAQUFAAOBgQAp" +
        "6gLCdPQw7Hisnr1i3QbD7GybqfD6b1s10GQ3c/j59RYDe1Fk47Srs9ol/baleasWjcdt8M" +
        "SlTc66KvK9YPFAqIdYoOW4FidpJBF/1cvSc2hGYwVsxLnXKr9CJ5Py5vBCCjovIRiLdzoL" +
        "ZoteOKFIEHkV7V8V2OTFawxpW9hkiA==";
    public static final String End_Certificate_CP_04_05_crt = 
        "MIICiDCCAfGgAwIBAgIBIjANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FzAVBgNVBAMTDkNBMS1DUC4wNC4wNSAgMB4XDTk4MDEwMTEyMDEwMFoXDTQ4MDEwMTEyMD" +
        "EwMFowYDELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UE" +
        "CxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5nMRcwFQYDVQQDEw5Vc2VyMS1DUC4wNC4wNTCBnz" +
        "ANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwZsiUhXiFHN9dfJb0Yyy+rYtV8gx+d0+8WkW" +
        "5C68nQgSqqk2uSTpvZbx0bpHF+s+LKppj2M2tt/AfZgVQHTsp5rO0IftZE2iLwqejj0rYU" +
        "Poprq1PE3vVhs818ZlDS0PTUP97YxLysQjq2jS/d/9lF5pS3sMlP4Usp24gXX0vG0CAwEA" +
        "AaNSMFAwDgYDVR0PAQH/BAQDAgXgMBYGA1UdIAQPMA0wCwYJYIZIAWUDATABMBEGA1UdDg" +
        "QKBAjpC0ZvCXrvBTATBgNVHSMEDDAKgAjOoKlp+BfGqTANBgkqhkiG9w0BAQUFAAOBgQB7" +
        "YwJWcx+PU1sUZUOVleoB5amHFu0GT+Hy7cRa82UJMHFkz0bmnyEV8CBNcnn0xa5iVfwe2y" +
        "5ZKwy61DLR3MPTar9eKITL67uZag9w+1tnIf594XRbEiUzn20uxuDFX3oPoZCemtWdVanj" +
        "2T+9TVQKfrp15+qzOCObNNRHZw29EA==";
    public static final String[] TEST_17_DATA = new String[] {
        Intermediate_Certificate_CP_04_05_crt,
        Intermediate_CRL_CP_04_05_crl,
        End_Certificate_CP_04_05_crt
    };

    /*  
     *  test18
     *  
     */ 

    public static final String Intermediate_Certificate_CP_04_06_crt = 
        "MIIClTCCAf6gAwIBAgIBIzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjA0LjA2MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQD0t0dfe82Su58bJdn4dh7E3OCam1AUPTzPnt7DwT2w" +
        "1XwD76OCUYP7SBBjsLYDDfUCb2ek96pSK4jpzyE6/4IOtfObe7OW+iBT9YAB5WeW+SmvEO" +
        "TIX+xo13sbz6rG6j9svcOxtth98yv7mxzV/ZwTNBSO72CcfDXIIq20TVunlwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQI0AufZEn1f9AwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAbfhxuNBYizxfMZNcyiN61j+7LXZZo3SmMU21UmOhPBTmdTbIkuVCI+" +
        "F1jSWdu3eGShVNJ3jmkidDvojMm+E8ZZ1YGHYfgeG16dDQudaGUjGmOfYzzlkFmsaf0paG" +
        "4y4sBerPsZCmhN7BanGh3qYPFvadSmp3OapGfEmDtS+BbVQ=";
    public static final String Intermediate_CRL_CP_04_06_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wNC4wNhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI0AufZEn1f9AwDQYJKoZIhvcNAQEFBQADgYEAIAI7" +
        "W6K69twJZnHx6CoIMs5+P9DrJ2yKHptmntlOCTSJirC/xdj0Zv2k5FW84VrTtdCSZDT1Ce" +
        "4Dh69fT2sUUexJb/4IcDtzloiuASSJzKWCeVIj9A8e6+coNUJVKtRKRX8bHJ5Un7xpFrY6" +
        "t1hdxt8gUecAAdXEFGuZ3QEHHN0=";
    public static final String End_Certificate_CP_04_06_crt = 
        "MIIChjCCAe+gAwIBAgIBJDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPdS5zLiBHT1ZFUk5NRU5UMQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1RFU1RJTkcx" +
        "FTATBgNVBAMTDGNhMS1DUC4wNC4wNjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDQuMDYwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKq8rAPXsu1RVm3vT7od7CDLn8k/C3x3wvfzoWrm" +
        "W0cmlhp9xRy5a3HWiJATD8yCKY1psBgnrOpv37sdtUX4P2kf668HrYOaGo365fKPeT5Wjm" +
        "gp0pL3sXKNNsCuJPd3wKAXGHAi1R9arZFYPsKJlfQl1774dwAvzxSOMr5+pbnzAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QI33MEYdo5YX4wEwYDVR0jBAwwCoAI0AufZEn1f9AwDQYJKoZIhvcNAQEFBQADgYEAo8Ge" +
        "ADBoJFEIRzdO37uasuyIBhClTUgyFhEKemMBN6aelYeiJMX6FZIL3DgZOce4dg7Zg3Ak/w" +
        "B5m8XlGQLW9xIbpEzY/Iq9kr+qK6k9YmvtcOiHFbnudCFNZngTQZpxjiDaj4eA48uqKIxs" +
        "51taC5gOv9LYWPnugN8TsUUFZ1s=";
    public static final String[] TEST_18_DATA = new String[] {
        Intermediate_Certificate_CP_04_06_crt,
        Intermediate_CRL_CP_04_06_crl,
        End_Certificate_CP_04_06_crt
    };

    /*  
     *  test19
     *  
     */ 

    public static final String Intermediate_Certificate_CP_05_01_crt = 
        "MIIClTCCAf6gAwIBAgIBJTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjA1LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCshocJtyGsxeEd2ouVTVKp+HuhDjnDk9eXtaLQIKaB" +
        "7aTODHYbq1mC+1LO5DmRV5PBVd8NuuCA+1DmzFrfYl+nMCjjgOkC0//Gf9O85Hi/n21q0T" +
        "F+oVa1j9fc7nAgLIziexaXrflYSbaeNWkwHHftGUninKPuNGM2re0krEeurQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIaUi/P20o4LcwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAWBLeJl4qlAPKxmBM5QZ2JYsbCV3VBeYGAKQ+4L7ehS63VQMCwIjBCI" +
        "LaHGIFfCqecDNd6cpYIArdx4tY7X2/Zxm3j5ocngpI1Tv8zydQcFeraILglsHf2UZUuK/N" +
        "6jKGjwL68C8YwmA+u6ZhcQFD2Xg4wSMC/xxzAs9zEAQGBPo=";
    public static final String End_Certificate_CP_05_01_crt = 
        "MIIChjCCAe+gAwIBAgIBJjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wNS4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDUuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAO9ODA12Fky/Md5AELkaOvOwB31UlfZq3SHAOvs0" +
        "Y4NYoA7Q5KDIwW8RNzMSKD30z51VlgOAaBVR6HLo6rkcWB4wGiV7EPelewdSOdk72IrnYR" +
        "npJEm2KEuLkHB+gejgk+paw8CejxMsrvT6loN8Pz0btBKxWaCfknTIyXVyQsolAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QI5LtSKs/inGMwEwYDVR0jBAwwCoAIaUi/P20o4LcwDQYJKoZIhvcNAQEFBQADgYEAOMrC" +
        "38uzHckKMkiawXhPUHtDQfyR7bLweS2qro7GyndfxPpeMJwjzVxqvQBtMuHON+al8jyXpy" +
        "BsEryV6qvdFC1vczLzJHAJZmLe5np27zQIXOObsyYcOG+aPq727/pKoD90DAlBvrxNW0ox" +
        "x7citflEYpmOEv9Do5xiO3MuCFw=";
    public static final String[] TEST_19_DATA = new String[] {
        Intermediate_Certificate_CP_05_01_crt,
        End_Certificate_CP_05_01_crt
    };

    /*  
     *  test20
     *  
     */ 

    public static final String Intermediate_Certificate_CP_06_01_crt = 
        "MIIClTCCAf6gAwIBAgIBJzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjA2LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDI4MXZB08BfUHxo//4Re7Ax0qWkHgy6nb+/XaLQ2Fw" +
        "Pbvpb5mkhLhqDZBSX3KQL0YiJ8p81tmdvRQH/LbFzX/3OKBTUfV5imYy979A2NEb4otFp6" +
        "EDSskZhttY3d2IzUICoCWUXhObnmkHJ2jEc81bggFkK5Lir1m/tKq2IOPFJQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQICIAmlz6+Cc0wEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEA0ZvIG2cnk32p6uxqGw8Bu40NrfHu9gNkJL5MhDHJXA6OxU5BX5bWZp" +
        "LnKXLoHiqSdtEdmy5cLZw3kggxndxjsnRFMyCawaYupJBhlgquFbuvBtA8rMtkc5H4zudP" +
        "ZcOcvXu7Xw58K+1caSGURL+A6uXFPnMUBd1+k+ejbtO8Pto=";
    public static final String Intermediate_CRL_CP_06_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wNi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAICIAmlz6+Cc0wDQYJKoZIhvcNAQEFBQADgYEAbkJe" +
        "jfc1rztCbtC6xJZ3iZEDDMW2CxFvOvSwhmCjPqVY3lrCPNSQzdjmqepioCnu7ongP+HAA7" +
        "hM7bm+SoN7KzXKufQ7C2ONoAwvoPZgnoidg7RVECxUByD6AJu04yd2wCLYRpCfS2tDtXLh" +
        "HEDpe+ELwv35pbkCMlCO2u7J+Tc=";
    public static final String End_Certificate_CP_06_01_crt = 
        "MIIChjCCAe+gAwIBAgIBKDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wNi4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDYuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOh7lUwMRet7t/ABI6mo27CsnRzQ64Xx7f1dqxrJ" +
        "NuuSRslVShaWnwiGHjc+5/TS7Urfj9VO0dseBCzPsyYFoIX1q7Q5zlArwy24qpXTGMmlpE" +
        "GByzi7jkXO8w5+wqh3+8RFrQQzr71zLtAVV/qPUyleuF8M8jzkwfPvawunmwdLAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIayC0PPU9zyswEwYDVR0jBAwwCoAICIAmlz6+Cc0wDQYJKoZIhvcNAQEFBQADgYEAPz7b" +
        "UvaEV7Myjhe8LJO/soj84X71rvVPtBPrhYjWTJ6p69GCfJRyho3vAUIt8RFal1GFb72c45" +
        "DQGkcVzLLJw8cDP3ajtWac5HZ9dNPJkW+Kh12l9gqjn061XAjQ4XnbbwQDYCuXhguPE9v3" +
        "kzDbimwVwIEOB/4SARX37y7TUWk=";
    public static final String[] TEST_20_DATA = new String[] {
        Intermediate_Certificate_CP_06_01_crt,
        Intermediate_CRL_CP_06_01_crl,
        End_Certificate_CP_06_01_crt
    };

    /*  
     *  test21
     *  
     */ 

    public static final String Intermediate_Certificate_CP_06_02_crt = 
        "MIIClTCCAf6gAwIBAgIBKTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUNQLjA2LjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC/IejV3DmeaLW8OwMfAGyr5+8NOxM1C+UBYslbOfWj" +
        "KUGdhlX6TxFc5AOJVJBpS/QjeA+RWoUCxnxKb9QSlOrBmADrcnGz8zV0/c0JDLaU3oSgsV" +
        "EWZE0SexBVWrKcl1j7wN0RuxMeAp342/YoyvBwea3VeqJkmSCc7Y2TjruWEQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIaHxWOdHsLbUwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAuzeq/lqp0qs62krK6EA81Silhy42l/KmynE3mVu9GPBgQS0BUDi7+r" +
        "QQ+m0UxYElzj2SNO4J5aBYeC98lVJFCHX7QE8yVOoPBQd5rA+rrz4HD9QoP7glxTqLU6Tc" +
        "9VFd+iaFpqsVtSh2bxH2BtUB2ARgebTklaNl5VPbu0+yc2I=";
    public static final String Intermediate_CRL_CP_06_02_crl = 
        "MIIBbzCB2QIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1DUC4wNi4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWjAiMCACAS" +
        "oXDTk5MDEwMTEyMDAwMFowDDAKBgNVHRUEAwoBAaAjMCEwCgYDVR0UBAMCAQEwEwYDVR0j" +
        "BAwwCoAIaHxWOdHsLbUwDQYJKoZIhvcNAQEFBQADgYEAYGaAzVoUdlSZ3uGKiRPfHAFIoK" +
        "T79hNOvtOxaGA0aIek9OypDrDqYAh/s2jsXSheL0pr/v9WRIHvtCt7ytXDxVyn4Nxjpfv7" +
        "BkAMMiccdUx1OH1VElTRkmmtMe7ROzUeHUGzXJNPex1Bc9BvSChH18bWYckyOZdYJBjctC" +
        "KJFgw=";
    public static final String End_Certificate_CP_06_02_crt = 
        "MIIChjCCAe+gAwIBAgIBKjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1DUC4wNi4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtQ1AuMDYuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK4D9H8JxeIrFuOmx0cSkIYNS0p7cDSBlcc57Na3" +
        "+1k7lJD7mE9ZP6/47YsDVK2bwe4aTKCTXtPk/kGQ6bsLswJXbyW4k4+f5LeAYoXgbmZXjA" +
        "WF+BKIl8uKetsqC3HkCeqhBaY1AGUqef4oOAkakEP+1jYFumNYtMaB+9x/0ncBAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIC9MiJNI71RMwEwYDVR0jBAwwCoAIaHxWOdHsLbUwDQYJKoZIhvcNAQEFBQADgYEAo/ib" +
        "mIxteityjZlszjCc/s7yM/0snL78pYpMOZ3P2TPKkYh2Th4+Bw8JqX10+M/zwFBj5Bw7Im" +
        "zCIRfS3GFuKmcVcyHB4OZLMcQZtXWA8GOZ94YvWq5TBINlVtThQtusQj15KBq2TJNNFUyD" +
        "pBdvyo05AnEsRY0HbIQu6ZhNQ40=";
    public static final String[] TEST_21_DATA = new String[] {
        Intermediate_Certificate_CP_06_02_crt,
        Intermediate_CRL_CP_06_02_crl,
        End_Certificate_CP_06_02_crt
    };

    /*  
     *  test22
     *  
     */ 

    public static final String Intermediate_Certificate_IC_01_01_crt = 
        "MIIChDCCAe2gAwIBAgIBKzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjAxLjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDDOu1J/VIzbB4VcS2Dwf2fsHOmIj3iatM8y61V7CrN" +
        "RCxCWTJ1Os8e/mFWOi/zN+0afizA0UzJDTe8L++/RlP68IFg5Ju2OhXqQC3HbUZmQ7ve9g" +
        "QdWTfur3oEJV6/XoVE4WG0Ic7D1p7BENb3LUT+8MJdSboTvAggA1CiOI6zRQIDAQABo1Iw" +
        "UDAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBAoECP" +
        "RyRiSV+4XrMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqGSIb3DQEBBQUAA4GBAJlmJ9EW" +
        "9ujUosqHZyZkniu2vX8VOL52OnxtLxw3LqxLyuxivjyYCaMAaJNr7/xfm3C2ozh9mQyZTQ" +
        "6TpBapLFUH8QsEKUhy57MDUgIvZsyOvvjJh3AXfSkXDaMZ3ncLg6x0wwjN/Hxu9i+IhX1W" +
        "1E7/5foGx7AEVfwY7Fo9S82d";
    public static final String Intermediate_CRL_IC_01_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wMS4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI9HJGJJX7heswDQYJKoZIhvcNAQEFBQADgYEAV4DM" +
        "F5gU8MZ6E/mnjAWS+dIRKUBJV1GZJ+hOysdbmK1hD0mj5Pd5qTzlcvLjuatIoIsB5DCpYd" +
        "AcNRLVvF5EJFhVjqsPzRlfUZth0Xqa+U/DeHjVxHxYsLEOSt+v2bLkbGh88SmOAk6F8xj1" +
        "l7YIfPX5cIkUBTVZlsUt51slMXc=";
    public static final String End_Certificate_IC_01_01_crt = 
        "MIIChjCCAe+gAwIBAgIBLDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wMS4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDEuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPrk1fosBu0hemIKgTDCeV/RoFbbsm02X4LfZonX" +
        "KeGRGYZXz4tpWgbNpjKBq1e/2bOO1DCn9I8I2kjvZdOkabk4MLeuRDo/sqlNndu4Ar5502" +
        "pAo4A2V0QLR4IDHAJoDpxtSFrqELOiiyCx9O9V19ywe5pcBFrxVEWDqTnBUeDJAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIbI6BhABrmQ8wEwYDVR0jBAwwCoAI9HJGJJX7heswDQYJKoZIhvcNAQEFBQADgYEAYzYy" +
        "M0wbzNhZftAWz7TfFi64uA9WmTmd4MeK9vga4ChswT4H1zlaV1Sr+3hqpGmOoP5AUd9XIq" +
        "O/ui+/gFaeuOLI+ATmK+V2KHGAneMwzcw9qbXRc+xZqGGjbXMb3Bowe3qrj3mhyowfa1n7" +
        "x5xB7XEOqO6sfWxLdDjLVo4sn88=";
    public static final String[] TEST_22_DATA = new String[] {
        Intermediate_Certificate_IC_01_01_crt,
        Intermediate_CRL_IC_01_01_crl,
        End_Certificate_IC_01_01_crt
    };

    /*  
     *  test23
     *  
     */ 

    public static final String Intermediate_Certificate_IC_02_01_crt = 
        "MIICkjCCAfugAwIBAgIBLTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjAyLjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDemJgZnOzXOwNGqRA3Xq9aMrAWQU4oFuhSELsEYfLZ" +
        "GO3ntBjJLqCn+rs3FjR9N94cu63TduOAgqlXqrNbvyO1+SF9m35JXreqn/OS6KrK6c8W2I" +
        "pDAWJcr89nGyyCXMoJeaOOtj8m2NjZblmCZvtAl5UMOew73GE7Z5fE+jtA2wIDAQABo2Aw" +
        "XjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSAFlAw" +
        "EwATARBgNVHQ4ECgQIhT9GjaaHj68wEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcN" +
        "AQEFBQADgYEAWhKJUujLapxpz/DoD/w48HMzkL6UQCxQPOAjwwHicX8wFcKmcrWLVBdVC3" +
        "0+ywrzMraWhaq+QCOqsgtxCwTZrfUxbCNqhKS0lZijCMgNN4Jht+PAZ22tzEsw7nCwiMM2" +
        "n1jeKF/3btoDEUvZn9SuzhkIyxy7Q8l2tbNOsANqpxE=";
    public static final String Intermediate_CRL_IC_02_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wMi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIhT9GjaaHj68wDQYJKoZIhvcNAQEFBQADgYEAJsjf" +
        "oS3F1KMpcVBOC1Z6P5N20TYLCCHG6KETlBA3Rjf8ehNxJKJW0lGd7qHpVHp4BGvkSfaOAa" +
        "OrC0G59wjDEY+Ci4QS46OYzBcHXMFX5HF2xMq+y5SfQnyV6MQUVVkxJRjgsTLrYwP2JaYm" +
        "BK/zExhqQgPfgcR+56swBPXqogo=";
    public static final String End_Certificate_IC_02_01_crt = 
        "MIIChjCCAe+gAwIBAgIBLjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wMi4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDIuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBANbTVeAxOibAO3KGqxxY3VqKXDr9tKJN+igpKb4w" +
        "goR0ZnWGDusSVm4pvneZ9qfmi8A0sM0E91+B2hAwsU6Y9RoA7nPsTkFYi5F+hHGIF46Op6" +
        "8blGrZraGf9bsWXCZFoLoxcgltwjGPQqyZ5mnnm8cxUbtaWmgo28MK1yBH/sS5AgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QI3gkBNo/SISMwEwYDVR0jBAwwCoAIhT9GjaaHj68wDQYJKoZIhvcNAQEFBQADgYEAQGl1" +
        "7uT2xxYDks6HolrQIpesIoPqEiZ8TkizEBuLG3sUKsC7klHwy2iyVvA6nRUDwf/XzDLpGW" +
        "/Gn0KTW6ZYIX6snOC1+7HX5OJglQx8tDpDvcAgyocK8PvCrHfu9o33J49aSeLAVpoCHwne" +
        "tTtJxVfTMmjYWKeDbHHHi8a2YTI=";
    public static final String[] TEST_23_DATA = new String[] {
        Intermediate_Certificate_IC_02_01_crt,
        Intermediate_CRL_IC_02_01_crl,
        End_Certificate_IC_02_01_crt
    };

    /*  
     *  test24
     *  
     */ 

    public static final String Intermediate_Certificate_IC_02_02_crt = 
        "MIIClTCCAf6gAwIBAgIBLzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjAyLjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDoeA32BPwgq8pLJoR/tbOSjHtAz6fmzvzJrhJMvl64" +
        "ccVuIzGxzOneYsO/ZYWy3ZGtlCoMZJRnS83tw0ikU9vQUwBw7DEcfRlLKYkY68rp25N1V5" +
        "JEjnlHw+RvubdGkonWzUNJFbY1GA24J3no2GZHiLPgWmGb1jsA8Ag32MUrCQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIKx4Ybzu2PaYwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAotGeNFzmktvcxpCRcpuARHkv1lW+LegvbDBnSPvGnr1+Cn9rZcuLup" +
        "u8ex6VJ7KWtgWBtzdOelerO6ytfWQ67uNpTOuc0SDdk/f3tCagdx44LBVQywuq/Kj57ZuN" +
        "jpe4J8UPZSBFFK+P3gTX3S/lIKsDi6xjRnqFLSQYGX2XiIE=";
    public static final String Intermediate_CRL_IC_02_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wMi4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIKx4Ybzu2PaYwDQYJKoZIhvcNAQEFBQADgYEAOfuX" +
        "wRv4skbPZAbOH/LVXdc/cA7vCSTAnWecN3ZKm/eCsxbyRxqn7fcDyHmqg5H3Ac5UOlMHR4" +
        "FMe0Dp+Yu4Xg8xg3zRvE/3M/5jyRILGGi7olh4ikkOMD+UlreysvYvUX2MVP1iM9qAkXh8" +
        "E8n/LZIlABN2GGkFEMRMJA6KTXg=";
    public static final String End_Certificate_IC_02_02_crt = 
        "MIIChjCCAe+gAwIBAgIBMDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wMi4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDIuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKogqWGx9EpJ/0G7ORopyIQ4IZXYKKTE48WqOJbu" +
        "nLD3txGjMUb5Xefl/QyTfd6J758ddGzPiKs1zWO6riffJLIBoOFDmt8tchPBJuIM3gKgXe" +
        "VcZMyF5mebm5/GZekMOjbs8P/zbLdrlu1D9CZWZMXONYitdluSg2moMGbewS2NAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIP8N7OmNGshEwEwYDVR0jBAwwCoAIKx4Ybzu2PaYwDQYJKoZIhvcNAQEFBQADgYEAwkpF" +
        "j6Kv+OcKrUtOgnH9QddB0Ej0oU6B5/5Hhhf3liAPKtllDHnhUj6nqfh4APNq/iqYFOkKMR" +
        "RUZoaj6kakJNSOlgvRIiQfuFIgv3CqLZnhr85YFRnKgoluZE1pq3TvunoiKyJbCjbmyCos" +
        "Rd32gVcJq024xvY2eVBTl6tfn5A=";
    public static final String[] TEST_24_DATA = new String[] {
        Intermediate_Certificate_IC_02_02_crt,
        Intermediate_CRL_IC_02_02_crl,
        End_Certificate_IC_02_02_crt
    };

    /*  
     *  test25
     *  
     */ 

    public static final String Intermediate_Certificate_IC_02_03_crt = 
        "MIICjzCCAfigAwIBAgIBMTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjAyLjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC7LFt+yGItQFqSEPi03ICIr5ydWnFPQHZdEMNu2tRU" +
        "3XiOpfam1wl0xgAPGBkQK768OfidpP/i1hgYOU/isOB5dyALscvIQ9XJG1OWQXBBLgKuCb" +
        "MS5fuDhBNa4KiFuGMbJ3/UjluRsD9qaXwGUavc436JwbRHvW8FomaBYYY1hQIDAQABo10w" +
        "WzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSAFlAwEwAT" +
        "ARBgNVHQ4ECgQIPsBg9tMABhAwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcNAQEF" +
        "BQADgYEANZcayTTX+FGhtRUJ+XuYA7jR14CJL6qTHPvdSMgHNw9mGXI/7sO5I4v1vayOCI" +
        "YQ9luBvrTYlMPmuej8+bhM8YTYpiiOjVFANwvSKArI9U2CAGBcoBMXydykkm8qYw4gtYQT" +
        "neiOz7VqI9plLWA111IRMgayD3CAt4Ntpzd1VSE=";
    public static final String Intermediate_CRL_IC_02_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wMi4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIPsBg9tMABhAwDQYJKoZIhvcNAQEFBQADgYEAVeQi" +
        "tT1FRUaJlhfpkfjZr6VHmvGnqYapdo4DRT/pm8tsp1LbZZXpYW638ztwgZNgeBRPFlcb+x" +
        "8naQjEkoaYzLbCYfdY+PPVDv7ym15PE48Kve8ImvANY0YnTGS8pcKdK1dpNKBnYYMOG9JN" +
        "+H5K/4cSm/WMCKIuKdsiAWFYauE=";
    public static final String End_Certificate_IC_02_03_crt = 
        "MIIChjCCAe+gAwIBAgIBMjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wMi4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDIuMDMwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALGbo9yEujZ9RFU+Vmxb5+Rx1VdIG/3E/5hXV/xI" +
        "OFu4mEfYh2tBhP2qIMH2KbrR1tiW5t4DvTCBM3NKKqp75wpiuu7E3q6imt1pLbGW13NVL+" +
        "81gYWXnCnzHpxYjMTIqqCkPIAeOG+SBJ1MgERbL+NBl+AK3WG4TeQ8vw7r2CGrAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIS/HbII+ki/kwEwYDVR0jBAwwCoAIPsBg9tMABhAwDQYJKoZIhvcNAQEFBQADgYEAWHy4" +
        "sHrTkqY1XjDBY5XpNEyhP6htcnjYD9bos4wjxPlJUyxdIWACWrLDE+R5iRCOYsh/nDAJEt" +
        "CUcVASukvP6VLJaFjyxUOaCp6JCVV+txk7Fh0S/Ur3Zyysfp5LllP1plOA3N/k1Hliljp0" +
        "+bnSiDhA1+3hJh0gDMjWUdRq9yM=";
    public static final String[] TEST_25_DATA = new String[] {
        Intermediate_Certificate_IC_02_03_crt,
        Intermediate_CRL_IC_02_03_crl,
        End_Certificate_IC_02_03_crt
    };

    /*  
     *  test26
     *  
     */ 

    public static final String Intermediate_Certificate_IC_02_04_crt = 
        "MIICkjCCAfugAwIBAgIBMzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjAyLjA0MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDf5u5ouGQlQmdNfc4ell3RXKWmtq+ar9VKMme3kp8D" +
        "cbDbUaVwlvhWTkOKxb9I208wfGG2nQiArezIwutlASf7sWo16EPapmGdCF+rp1dpjAPBUu" +
        "fruEyCZ8nu2ITD52wuPY9OAcKHQE2/bBpCJWkw97fYX6Q9PPW5uobWoUJtOwIDAQABo2Aw" +
        "XjAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSAFlAw" +
        "EwATARBgNVHQ4ECgQIjDm8K5YcGakwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcN" +
        "AQEFBQADgYEAEQIJeZj/HE3HvjjJV7PdU+2Ze8OeCYeeWDocxrA647xpeOksVXBXKmq2OV" +
        "NqoFk7YNtlSUqiS2TlqjGqLtKYetk7a17qS/8EIQct+H5KWdvkLkYMkfIAAMJvJZHPGxEv" +
        "j+oVPAi9FITRbFdN8Jvdo9MAuU2q8d2x8MF236RmEds=";
    public static final String Intermediate_CRL_IC_02_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wMi4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIjDm8K5YcGakwDQYJKoZIhvcNAQEFBQADgYEAV5bX" +
        "7WsT8sWeA0iQ7V/+ZQESDzvyHA7Ziju0iRsvTL7qOVF/Nl5v+zND+ZNPhdJDKEM/Q0lEaA" +
        "ybe0E73NMmM1qRX1daAwE++jHukF9TMeNl750HJaS667H6jcjeRrHUJDD0+AgqrZY52dL6" +
        "CPM3V4QSvdfc1/xtKmNIZWSSoqY=";
    public static final String End_Certificate_IC_02_04_crt = 
        "MIIChjCCAe+gAwIBAgIBNDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wMi4wNDAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDIuMDQwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMW45d5dPrzUJbuRIDeQ5gIJRYxi80PxPvxSmJe8" +
        "ScG1A+l75SAtgLGWAxBqxPSzL+teBBUsnmf2Xsc8/qQHHev74uat0lxq9YrZ3npLW2YNo2" +
        "CfxLK0M7F1/bhkHK2f9ttIvOrrKI67BeEjfACULdJEhl431uWINWV0pY+fHq+pAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QII61NnUvgvjYwEwYDVR0jBAwwCoAIjDm8K5YcGakwDQYJKoZIhvcNAQEFBQADgYEAjwgL" +
        "6qMnnqUvNspsDaYpPQzTCqXkqshZhsy5G/nLk621H/YbNGlnZ6asHGljYVYMzjmcny16y6" +
        "ntiv9QPB7YorAx27WT7pQPFla96s+nM/rfwWHPWI6QGDsquPriwJm/MwQC+1oDXEFKvdIL" +
        "0urejfd5hgiXYbRRwMI7km97iHg=";
    public static final String[] TEST_26_DATA = new String[] {
        Intermediate_Certificate_IC_02_04_crt,
        Intermediate_CRL_IC_02_04_crl,
        End_Certificate_IC_02_04_crt
    };

    /*  
     *  test27
     *  
     */ 

    public static final String Intermediate_Certificate_IC_04_01_crt = 
        "MIICjzCCAfigAwIBAgIBNTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjA0LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDBtNwpr9LZBF2LRtAp9Tb1FZnfM3b/Jv2sdO5zc/Bk" +
        "sO4ByUgY+Mux9dEvFrkVWBK110TvXn+dj+85TuboILv4MDKlu+tI/rtuadXGwwDIg8TQnz" +
        "uyC7LWhxM5JZs1/Is+sPKUY4PTCHs3+EHPBWf2tFiP3l6ZftkySEiL6+2LSQIDAQABo10w" +
        "WzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSAFlAwEwAT" +
        "ARBgNVHQ4ECgQIbMuZ73onuZswEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcNAQEF" +
        "BQADgYEAhaTSc2xafdP/QceMm9YJ/rZJ5gTgBR/SlmKQwd2BclHabG+Fozdg4delDjtRXS" +
        "FKY3sFWBFZHVeprh4T93Oj6IVA5X4DIuUeBpprtS+psCnWZxdtcUWmbyYQwZNCifG5C5D0" +
        "lRwxlMlv40xT2oCM1zPZpfmqemBDUPJ2OhkCjvo=";
    public static final String Intermediate_CRL_IC_04_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wNC4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIbMuZ73onuZswDQYJKoZIhvcNAQEFBQADgYEAMk6D" +
        "Rztz1AyFnFr1KAlbjLLwxtQplf2eIc//zUkDFVUHtX5TrEC/ijUaItjdkOoPGQfpnL0w8x" +
        "wyqWndMh593QPCqIJTtv/iACoiJNZ90ZJS0adcdZ+AEmQpa0Zv0e1JOqRrPoAfTq4HrOfR" +
        "vhBwhvKQNtTExupW/EBudznKC6Q=";
    public static final String End_Certificate_IC_04_01_crt = 
        "MIIChjCCAe+gAwIBAgIBNjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wNC4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDQuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAM2dGkraKGdIi6EXxAu6/ekMqDloX5YSVBGh4Hp2" +
        "faujr1u4j8Lp8afqjngRxFUpTqGbqH0ETgm4cVPXmc9rUvUzYTMdxTUmIZ+iW+ULZEvzNB" +
        "712kxRPCD2kDFN2fH2ai8miXr434w+weLm8VQN4jJGo4nswhSs2w1gsUmWyn/ZAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QITsLx/sO1edwwEwYDVR0jBAwwCoAIbMuZ73onuZswDQYJKoZIhvcNAQEFBQADgYEAeKft" +
        "0RM8/b3zQodaKrTdWiFyLg5fzoOsTecSfdFPXoqz9J5ejLVkvJevSmfXJrIUhKXySzsQi+" +
        "GazuTh/hvWjwUTIvmupi+EiFudnMpXCro8bgi48+NkepNjXvjsSmOfzlrK3SxtpH5dqonL" +
        "6LHjGyg+Xp0Nor1m5g1rLHyrcEk=";
    public static final String[] TEST_27_DATA = new String[] {
        Intermediate_Certificate_IC_04_01_crt,
        Intermediate_CRL_IC_04_01_crl,
        End_Certificate_IC_04_01_crt
    };

    /*  
     *  test28
     *  
     */ 

    public static final String Intermediate_Certificate_IC_05_01_crt = 
        "MIIClTCCAf6gAwIBAgIBNzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjA1LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDM3aWmgX3OzAaBg6lnWjpFQ9ufeTOia3+lIUqn+Ypf" +
        "5OH/s9dLRqg1ZynV3YIUyzaJPP/YlUEmrhheJn3Bjw25bHeIKdge73pfEbuBAugbUMS75D" +
        "csBV7Ze9D+sVw8w/LtT3ZPcvM3Vju4d+c14Ip/8pC15jlgQPhwVQSf0x3V2QIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBAjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIJ2DFtxoQnXkwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEASvdcfBOh2d1dC10pGLZLI3T+oSPCup/U9riynIR3RxZsIaS/+Q2s81" +
        "oeg++WQV6pyYvCLneZIp0efvqh5DThNV9lhBcJjlYwm/T8Hi2IaRGsSMwIvzrFN7zxA/zu" +
        "tW98wigAKM2myk/nlYxmholgbQkQ7ZxYM3lD1TDRl69N66Q=";
    public static final String Intermediate_CRL_IC_05_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wNS4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIJ2DFtxoQnXkwDQYJKoZIhvcNAQEFBQADgYEAK7Ym" +
        "Y9PjX5CpVewe2E9PNxj3dLYElghaQyapYoVtNq3jDqLMWspdmHdNdeaQoXsjlSJe0Zy8xH" +
        "ZvpimwifnFZ5hq4yByzHjzNMpcA2yFtg2MtPWGEia+BmaZYZi3X0lR+OShKpNLFc4CfVM/" +
        "aWG6W2BulHjIAThZhTg3uRekDzs=";
    public static final String End_Certificate_IC_05_01_crt = 
        "MIIChjCCAe+gAwIBAgIBODANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wNS4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDUuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALlcUtceuxDznvI3pVM7YddPcBOrNvrOtpuLOa1L" +
        "Lj9LeNH6+8CzRZnMsUtt+bRGqCKMEJLUIIstWwGg4SskXWk2m+nDKm5Ai6Kyx4nldpgtgQ" +
        "xZSEwNcwRhpy7TtmLkxDVM9DoTbIbK0dZ7aWw4bXVHPK/lnOMtOaJbFDq0sLfxAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIiXgrRBVcDf0wEwYDVR0jBAwwCoAIJ2DFtxoQnXkwDQYJKoZIhvcNAQEFBQADgYEAhyO6" +
        "SP6brWDDKZwdQGULno4Om5+DuilJKamyEcvSqE666z1KhvOCdLicqwVa6tQiAL6akrt5Kv" +
        "R+TT0xqHR4JGosGLGolvK4DLrMeD+PRK7m1a+nJl44luo5Mn48HrKI7jn7n8Lp9bNdCHvr" +
        "NHaQksCIR/Q8xoucPa+8sCTVSj4=";
    public static final String[] TEST_28_DATA = new String[] {
        Intermediate_Certificate_IC_05_01_crt,
        Intermediate_CRL_IC_05_01_crl,
        End_Certificate_IC_05_01_crt
    };

    /*  
     *  test29
     *  
     */ 

    public static final String Intermediate_Certificate_IC_05_02_crt = 
        "MIICkjCCAfugAwIBAgIBOTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjA1LjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCrtIYqo2Is8Cd6Ld+fyWC755oA6hQiiruooaR/6O4z" +
        "ikyhOUztnHkOGMF5H4CKWafwwVrfFtqe7iop3N6AToEIpNlJLVy3cj14A/IASVYSSNFeHd" +
        "O44Id1NWhPiKx3paPTWslMEdKQV9BlXb7gu8pQpvqTa/38hNQ9vdil/4QZbQIDAQABo2Aw" +
        "XjAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIBAjAWBgNVHSAEDzANMAsGCWCGSAFlAw" +
        "EwATARBgNVHQ4ECgQI9P78RavuWW8wEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcN" +
        "AQEFBQADgYEA0sAEmWBYSazUav6RtuNFtZgNrlQ2i5i138VzRHoF/kq/CxeR/lINQqgJhC" +
        "ZlUnlslUuM86g8OQGlR8SS0Wsi0MdCQCtPCKA2hStlTx9MMux2IZAGoyHy6P95UE9qINHE" +
        "fYZUYjO9rh96fzNyJ5Oy2kJdJWdhFXtSh3BSOe0ZD+Y=";
    public static final String Intermediate_CRL_IC_05_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wNS4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI9P78RavuWW8wDQYJKoZIhvcNAQEFBQADgYEAlPLh" +
        "+CMqRcbLgUKEAL2UlSY5tjsF8At0hf000kec93TnBf7f1NKYVJ5eyeoh/WK4s+k4paAA5E" +
        "/P2C8JMlGXNTrqKZXMy2zIlufE1ymXAZCKLOLC5ezXRSpwIsBWxko2nfw8Bz/mZO/bCSCT" +
        "nDwkH8BJIbFV51vJFlyyOmZnCz4=";
    public static final String End_Certificate_IC_05_02_crt = 
        "MIIChjCCAe+gAwIBAgIBOjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wNS4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDUuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMPsWBfT8HqaiLnoUCPAFniq502odL4uVqzOOxkx" +
        "evZtjh7NaFlRjuYjTofdkj/IAgg7lkkBEW3auK47Td3TvqnHO401PqvOFNTlbhr5wDLmXS" +
        "WWcR6XrvgYL3Z3wx15/z6eojcSgu07kdvKqzuLzcDs+noG8lbcruokX0A186pVAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QImgomUTkzwbEwEwYDVR0jBAwwCoAI9P78RavuWW8wDQYJKoZIhvcNAQEFBQADgYEATAEq" +
        "YVV0iYdYomPqxbTapSCJFAMQO/WZhN9brCXP88+jRfk6cAHzTodQOYTOAVe8YXa904505e" +
        "RA11NNTViP3s/AseGWuqbWjsom9mbR+tVkvufGqPQtm1JhfLgR/68e29AI7tj7zIJyFVYD" +
        "nLRXGwMGnosqSHDle+WYyfok6a8=";
    public static final String[] TEST_29_DATA = new String[] {
        Intermediate_Certificate_IC_05_02_crt,
        Intermediate_CRL_IC_05_02_crl,
        End_Certificate_IC_05_02_crt
    };

    /*  
     *  test30
     *  
     */ 

    public static final String Intermediate_Certificate_IC_05_03_crt = 
        "MIICkjCCAfugAwIBAgIBOzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjA1LjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCajRjoRNL9HFTytLLx7C8WYouW0uONGsrtGS5tKMiW" +
        "oLlQUkohqB2a2PhA1InNGQqnbDtNdqKbR1k6EzD6MyegvXK1sXs0ZE8gt0LZYio7Xp3k+Q" +
        "7i4Rk5iTruAUrV8bFMYmeIXHXL/9rl5LQV8YRp/Ut3Bg3VECzfhQG4EavMlwIDAQABo2Aw" +
        "XjAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSAFlAw" +
        "EwATARBgNVHQ4ECgQI9041oiwvHsgwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcN" +
        "AQEFBQADgYEAYwGYwLsA/kxYZG/RM+kvoH+mUebrBVZRBxjovYsYzNznD26fssjBFfiTmg" +
        "zwZJfG7MZRsgDSRsS+bxuTlXMVeGRKH8fVj7PNq05sS18QZQOF0CCKzg9DLkCzkzkEWBxc" +
        "5ersciPrL90UarOIPIJWUxQ/5sdMS/wZtYTU34rNNWE=";
    public static final String Intermediate_CRL_IC_05_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wNS4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI9041oiwvHsgwDQYJKoZIhvcNAQEFBQADgYEAJHTp" +
        "k+RRsD0dUv59J1GQMWjQTjVz39Xaonx2sk38WHcrHBB78L0W6Skjvt082PwZg32sb7FQBt" +
        "boAQ3PIKpXMnFnkjnkyaFihrnMdfa0abCPtQhFl3yra+w+1a2RDjQBZOOdq3xlFcLi9unT" +
        "YYome7eS93wchIvNWFpgwF5A5XY=";
    public static final String End_Certificate_IC_05_03_crt = 
        "MIIChjCCAe+gAwIBAgIBPDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wNS4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDUuMDMwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYxdSZq7qRBdPOz6H+l0GGAtymAWTshfZZCubHK" +
        "lQjbVq98qudORfhCOZgOy83j/mo2KAecBhxaxB9YA5ggWNAgaKtFvknvjFemtBCZwt6cVK" +
        "8LCyUGKzStwAV1+HSDlHxdWo7pRwP0beXFvFECrX418osGt6E/v7Cz++ZtvaDhAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIgTuCLfTVa+QwEwYDVR0jBAwwCoAI9041oiwvHsgwDQYJKoZIhvcNAQEFBQADgYEAQRuC" +
        "rAx9zzu9QwOq9weNit9PNgFHBpo3Gh9jPVYGJjOQxeSqqou503xi82H3W30FT/3ESCO7IF" +
        "hfpr/uQZVEmUQnvDsVwbKvED1QF9qkTp6ILk38ITJJgfb+sdSL3bsUeNqVXd0C9wzVoErc" +
        "OuoCulwkZzfoIOlO2YAjAnR1nUc=";
    public static final String[] TEST_30_DATA = new String[] {
        Intermediate_Certificate_IC_05_03_crt,
        Intermediate_CRL_IC_05_03_crl,
        End_Certificate_IC_05_03_crt
    };

    /*  
     *  test31
     *  
     */ 

    public static final String Intermediate_Certificate_IC_06_01_crt = 
        "MIIClTCCAf6gAwIBAgIBPTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjA2LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDmutL9PY/BLXvXMEDQLQnWE7dCOsrLNvJiuSjDdznF" +
        "vBz6WS/RqUr9zsDFknpOWB3Epo2syV4ZFto+v4VWNo61uaClIEsw5x1y0saG19px34KVpQ" +
        "wkpvLeRZySdCydKdE1rptYR/JbHvPo5TU4mxOo6L7JeEwAvjSI4tK4rwJ4MwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQI1BB9j6Jyny4wEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAajWMbY8zL8jS2VUjCPBMuIjUvBfy55+92EXg5pZnyNNwN1diZfJFiB" +
        "rrPWEg3Fa4NMLgaDKWZsYkOcDDo8I+Qb9FsU9LphCzQ1ubIEuxu6KPX9X29BscFOxUnZCz" +
        "yuzVfadACxi5Y7Bz5pN5LfC/jEb2iXjkdN5Rm8AqT81syIo=";
    public static final String Intermediate_CRL_IC_06_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wNi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI1BB9j6Jyny4wDQYJKoZIhvcNAQEFBQADgYEAxH4/" +
        "mgACT847PyufmF1nob9TSqBj+cM5ye2bgv83gTVd3B1Gopr75Tnu4iP10d0PpSXjySWCjB" +
        "0HPJ7BdxzkKxSrcM5vcb/jLdk9PqMUS30ohexsx1xK+E38pDJdLX4kbJ3E62AgyXm9WQlD" +
        "9xsDk7TMXwuxHT4fX070HL6lWGI=";
    public static final String End_Certificate_IC_06_01_crt = 
        "MIIChjCCAe+gAwIBAgIBPjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wNi4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDYuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAO1VOl25MTf068LOgzmQOmyh8MXunBrQ4t6UYuEj" +
        "H7v+owR9JTDXpfzLPcYfkR+BH2jjISSHIJsUDesKVhpmhABNXcOI5tiRNkeDlV2zKCBXKC" +
        "wFi5qkhrE8FUCP0hL8YzbybOrYZYSVEP8GgIgMSQcTvhN/Tor0o1jdJvRLmevXAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIFJA9XGd9UZUwEwYDVR0jBAwwCoAI1BB9j6Jyny4wDQYJKoZIhvcNAQEFBQADgYEApRQC" +
        "OTU9cp16BHM2n0TdZThgj9kSAQ4wHk/dKNOjYNEWu6n/GQ0alxy1dyRzpsr058FOvft23Z" +
        "Kp0YhdKG/7F1hkcoNvC2yN+Re44n7S+F/jcEPTWnOX6h1Nkw8OS7Uz2fZ8t61iHjqjX4sv" +
        "M/cKP+AkC8g7p2tfdkP1fQ6ww5E=";
    public static final String[] TEST_31_DATA = new String[] {
        Intermediate_Certificate_IC_06_01_crt,
        Intermediate_CRL_IC_06_01_crl,
        End_Certificate_IC_06_01_crt
    };

    /*  
     *  test32
     *  
     */ 

    public static final String Intermediate_Certificate_IC_06_02_crt = 
        "MIICkjCCAfugAwIBAgIBPzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjA2LjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC0JoTnPaI/HT2eAqCW1204nRNjcA8EQSp87tvHLpWy" +
        "5aafmxeJxvk5V9Ba7Ye8eY8yX9losbNUpHJFNdE46fD5qp/oS7Cn3NXA0dwIDQEn1X9vaz" +
        "nqtZtMjt1S/yGv2xDOb2LKT9zRrqSvxGszCHFUBcJ4HDFJMAdhXPUZiLyXVQIDAQABo2Aw" +
        "XjAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwICBDAWBgNVHSAEDzANMAsGCWCGSAFlAw" +
        "EwATARBgNVHQ4ECgQI7j2LO1CcsE4wEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcN" +
        "AQEFBQADgYEAfXIh0oYlM2pagAWzTuYqTl0NavtfqibPgolvhgIG/XmmjswHOg/JVCLb7O" +
        "jIYtEG2MAD0xQXwu0mc9Deufed2embP/wc0qVG7rj7lxUq6p0aMQJNndBw4m9KlSnjdzyG" +
        "lwE9pNd2BgEeD516J2k7dspCZHDw3qLer4i2JYoCo2Y=";
    public static final String Intermediate_CRL_IC_06_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wNi4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI7j2LO1CcsE4wDQYJKoZIhvcNAQEFBQADgYEAJej7" +
        "23qVtwkcvCTPb6afTosYMnVppPXWbtvqn0N5mAFHQfE27x1YPOXOQHBrpQuTyiUdUmPXiH" +
        "xMKbuR5o2lfdQgew9hbYVk6GegSu+DBC1JKv2YSTgzgRAlJfyByDZ7mbJwZWHVHys08oGk" +
        "adG6zstavg5EkEeRuAp47T+7cZc=";
    public static final String End_Certificate_IC_06_02_crt = 
        "MIIChjCCAe+gAwIBAgIBQDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wNi4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDYuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMkIzl9+NRTZf/xaA8noiHRt65Zo6Zp57YvCKUe+" +
        "YfoC8koMq12MBgrc0IyIfJoqEDEMfD1WbitZdGZMQZ7D9BP2Bk09NXLEAAuj+waFhYk0bW" +
        "vHBH90O7HpMGmxwHmzOjDV3JHYsU8hq77/5gRFDNRkSCJe2A1Maj8Gcqi6tYf5AgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIYDfThEjNL28wEwYDVR0jBAwwCoAI7j2LO1CcsE4wDQYJKoZIhvcNAQEFBQADgYEAJiHT" +
        "CjLGZK5Lyw+7ICDHs3eS1OGJH/wfsLcBP5sLER41qJfrXGTl2XdKvBMIpriUmJYzjkjof4" +
        "bvS/VPDNlhI9AJadicW8LM4L3qpy7/YV4Dd/C/BJphJ6cZcT+hjaRKeC7gQVjMeC/npu/p" +
        "jLgIgzf7HC4WYnaS3h9oYl0cMJk=";
    public static final String[] TEST_32_DATA = new String[] {
        Intermediate_Certificate_IC_06_02_crt,
        Intermediate_CRL_IC_06_02_crl,
        End_Certificate_IC_06_02_crt
    };

    /*  
     *  test33
     *  
     */ 

    public static final String Intermediate_Certificate_IC_06_03_crt = 
        "MIICkjCCAfugAwIBAgIBQTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLUlDLjA2LjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCuUtIYFbVjg8VLLUqIEQ6r7hjTaqYVs8DJnJPHUWPA" +
        "JW9HEIV+d6hj/so76Bff4KJRX7MgoXbvq4ivmn8656N7YSGk9GPuJ25SXK7RJyoqzG/x2R" +
        "AVUCx/wG99VXVDZhd5ZAVBG2JCkHImsWAei6/Tz8UgXmmLBM8rZNJ/hNtTBwIDAQABo2Aw" +
        "XjAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSAFlAw" +
        "EwATARBgNVHQ4ECgQIpwUlwG1W+sMwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcN" +
        "AQEFBQADgYEAqJhUfgar10fl5qG+oH34s/JS3ku0dRm4cTQvqUNOWA9ALnBhSkmOpoMMzH" +
        "sE9FXXcZ072a8/ecpviP04X5mt5QSLreh3hPVvgWv1LiZ9YkS4Z2kcr+3Gx7zj4gQgT5vG" +
        "QPpbIBAtBRH5xNHIYQsk6kOe2+t7b0Q82Wnj8UoznmQ=";
    public static final String Intermediate_CRL_IC_06_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1JQy4wNi4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIpwUlwG1W+sMwDQYJKoZIhvcNAQEFBQADgYEAKCp7" +
        "ViY1cajXpbjCIqe8yo/98SQRIxoTNgp7EUaaV17FeHZ59nJhRtsF1XnLP4cK0lPBkKFhHK" +
        "2XyDEWx2hK3X7Z3lSAtn12WFJHOP5T5i0DmYfMJYAFbuPD0JQEWCM3aYsgbXKbbFH1BURh" +
        "L/uy3arVBP4FaJB8gH678K4J1p4=";
    public static final String End_Certificate_IC_06_03_crt = 
        "MIIChjCCAe+gAwIBAgIBQjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1JQy4wNi4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtSUMuMDYuMDMwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALZw+GpvdleGlmdqZ/zEO2DUGhwgrsselBUNnEzR" +
        "bcuzr5O1WwiG6aLjrPxIXeL1wLS1/u9AD9p3CQU0XFhi+bEI9+LLnt2y3707O+AQxy1PnQ" +
        "6qmYE4jMwqDGHn8WVanN2joFT3isLH5wJD0Jh74eoG0tqCHUyOiXaZNo78qgB3AgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIJOeyCnvfJtAwEwYDVR0jBAwwCoAIpwUlwG1W+sMwDQYJKoZIhvcNAQEFBQADgYEAJbz1" +
        "RipbW6uu7B+f2Ol1iq4AVOUuET2S9vi9ojReyAIka3q1XUceZCm5Et0KqpOoOLiu8IRuNB" +
        "bvKwRcZ4hcVEXv5bRMqaPEK2B0VrRAV/Llj5A+RGn6yc1ZdkJeBRhoSsaHn5whfICaiJX6" +
        "j3lMpo/CiMRViL+gZLU3SdKqvdY=";
    public static final String[] TEST_33_DATA = new String[] {
        Intermediate_Certificate_IC_06_03_crt,
        Intermediate_CRL_IC_06_03_crl,
        End_Certificate_IC_06_03_crt
    };

    /*  
     *  test34
     *  
     */ 

    public static final String Intermediate_Certificate_PP_01_01_crt = 
        "MIIClTCCAf6gAwIBAgIBQzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjAxLjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDRkBhJJVgOXHjydAHAnokd/XfEiW+bnWd2ZPJrMBmP" +
        "7TlvVpxOGqLd6lGdbelbSyAzut1i8lyYn9NSDR0PcyehCSS+MsKS2uNKsTEuH3mlMK/7C5" +
        "B1qggKqE8f7opyl9+U+Qyi1WQj01gY6XYXaCxksCB0Oqx2737d7QWMvl15dQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIO1U69B4DBHQwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAcHWV4Q4z7C+IC4bWgIf1+BzkszCN+LSb4JquR7GgICESbwF2JzR+xL" +
        "7yoKvB/NBcCqtMY4Hi1DHACbIGJwRe68vVHzz4CmYEK50UUCbAtiAiy9Od6wwrTyFyacBd" +
        "CBjiO6mkFEp6jOsoIgXRfxK4kDNcMkGUUwMbSR/wZKFuImc=";
    public static final String Intermediate_CRL_PP_01_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wMS4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIO1U69B4DBHQwDQYJKoZIhvcNAQEFBQADgYEAHtbX" +
        "MUofQlCnbJhgLQw96jsBRu0Kdx/Rk4LWxEbZQOWNaD7aukASjEv63d1qZIDgpefuUNTz5s" +
        "3eascdtI6iyWFtBO3r6tihtkkSbxocN2Rz7OlR4rW9VwuUirxP0145nMd5CEL03/CNABP5" +
        "zUo1bNgswHW3z/RaH6h0j0yTkbo=";
    public static final String End_Certificate_PP_01_01_crt = 
        "MIIChjCCAe+gAwIBAgIBRDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wMS4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDEuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALQaTS1wvv551g3BP9JYBMM+KXXLzxtOwPlO5NR4" +
        "LwuJJB2WuO4vmbn8AG35in/0JqwjZeroLQvbCPxZseXsyA0+7cMO0qcjRJ5l5WdFsahT6g" +
        "z1YW8pYYY5i2eDUkIRsM7roHMiNjt3zpkuUGX0xZQfAxhuWnRIvlGg5J4r7UOdAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIeyLSANVaTpQwEwYDVR0jBAwwCoAIO1U69B4DBHQwDQYJKoZIhvcNAQEFBQADgYEAvZ4a" +
        "SQMNl+Q++D9yVaGr+37XJyxs4yow5e5YM9LXn1qBASQ+GNfqPWoe2cPCPYKj32yulxyFEu" +
        "RHrbhpEQe+nrKWJgO9W1bmfwgQDin29ne/JCQPlznhd3EPFvCkmPLnTyJmSLR6B2VxvndM" +
        "GO8JEbj3KCf51uf3VnC/Qj11mX8=";
    public static final String[] TEST_34_DATA = new String[] {
        Intermediate_Certificate_PP_01_01_crt,
        Intermediate_CRL_PP_01_01_crl,
        End_Certificate_PP_01_01_crt
    };

    /*  
     *  test35
     *  
     */ 

    public static final String Intermediate_Certificate_PP_01_02_crt = 
        "MIICfTCCAeagAwIBAgIBRTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjAxLjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCkQQXRO+dnU2v7EbaqQNmfPD8v0s5Wa50hl9M1Gfr5" +
        "5nuVUZs/RI//1VksTNrW10MVh11nsxpA/XRPntEIbHiH1OoECd4dnZBiA/2xEueM02fTjj" +
        "fb/t7g+pr9dSU/TzCVZDVWFBcPn4VNz7BBqIrTAOXaJkyBZ8hh7vyiE1Y2VQIDAQABo0sw" +
        "STAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjARBgNVHQ4ECgQIoTKVlZ8YCR" +
        "AwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcNAQEFBQADgYEADhtnd6ifr6kyfC5D" +
        "UWuAXLtoccMj8Jaur/1YT1DgnH1XbBsEeZwm9Jkzr1a3cXPIHgaHYgXvBeGUtZ3XhbCSGp" +
        "8U6clJz3lm3qKPKkb5rdDrpdTaPnEJJjS3C4ZK1L7UZtQga2Enlelm5vIkhjsF3Sexe1kY" +
        "mzqiLZZ8yLxJ/Tg=";
    public static final String Intermediate_CRL_PP_01_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wMS4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIoTKVlZ8YCRAwDQYJKoZIhvcNAQEFBQADgYEAn94u" +
        "sT8ZYNzfHIdnx0+fV0jglL0Kn1duz+ehKHow+RGqH+J9opMYuXVD+rVQnLdZl5LbFBcv+5" +
        "TSP9WR9QtyoXar4/jmY2FFdBjfgO9w7p7OHD4WxblJmfPVOvrzFm/slZE39Oe5Qn4KlS03" +
        "9tttEFTKDH3qREQbT6g4k4ExxYM=";
    public static final String End_Certificate_PP_01_02_crt = 
        "MIICbjCCAdegAwIBAgIBRjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wMS4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDEuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBANBwkwTWdZ977UAx6CCpXc9T4MX9T3/Tt6LbtY9I" +
        "eXxI9W15eXm/aqrKiXhULB+oF9/qNeUi2fAtrURZ7hgHbTaswr8CZ3Uwc6Rbkyj2GGiM6Z" +
        "8sKFztYZfFyGBiNEwfTT0yaUUQ6etIFqPuL/6qLvqXmvNPxFb9gjTH/azs/MdNAgMBAAGj" +
        "OjA4MA4GA1UdDwEB/wQEAwIF4DARBgNVHQ4ECgQIW1/BRCbe3c0wEwYDVR0jBAwwCoAIoT" +
        "KVlZ8YCRAwDQYJKoZIhvcNAQEFBQADgYEAPJg24q7wCU8CVlxFLchoe7txhkzApkVMIJ9G" +
        "+QTnraHDn0CZS6undCsJw8mrTNBQPHFn2Ixa5lrPfJvwW4Med1bcJKbwR4TveL1WeYYq6+" +
        "9k1kS/7KmqyKAKC/s504jAc7qgMd4b08oLxbGVfFVjWG/ZMbO770FrsyRHHs2rTOU=";
    public static final String[] TEST_35_DATA = new String[] {
        Intermediate_Certificate_PP_01_02_crt,
        Intermediate_CRL_PP_01_02_crl,
        End_Certificate_PP_01_02_crt
    };

    /*  
     *  test36
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_01_03_crt = 
        "MIIClTCCAf6gAwIBAgIBRzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjAxLjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDL/XgMvoeszcAzZqMYnv1At5u83Gb/CEX3fv6O1jL4" +
        "W3XbdvBNIZpuTwQhTH4Iofk9rIuQdkR7xOmbk4AqZINuas3Y1CPdzss7teraK0CNralNl1" +
        "jPYK+ClDBHt32Iw3bAl7RqWX73hl3YH6/7cvG4XCo1HqeeFFHUGa7HXGXq9QIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwAjARBgNVHQ4ECgQITMu5Qbn1Cm4wEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAuCnzXbHg87PIYYRbCCiXKDKA3MOcEKuxpNaSbtm12DQWpnvzmaK5nB" +
        "D/Ebko97CS7u9Tpwa7TmTyi39bYzY0dmVaotCDzfSTpzw6qHZl/w8riS+cKr0mimnjW1cq" +
        "kGPyHf0zBBqh0liGbd7EOLIBln0ASrn8V+G4Tj0Q6aQVcko=";
    public static final String Intermediate_Certificate_2_PP_01_03_crt = 
        "MIIClTCCAf6gAwIBAgIBSDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wMS4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjAxLjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCu1Fq+gBJsBf5EjKKtNIxgdtgPMObby7tKH7fTJxYE" +
        "5LPyPi/IiWQ5Mi/8BCG3zmQhu9ZdBbpal350qCGVTbaMlnpi98D4WwXSw7e8oHIJIK689p" +
        "Q6Z5cf8hgwPnwDpYLeEaqxwhd4bu0x1lG1fUISA0ZZIQaEeNSJfdh15IkAswIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQILRhQwULcyPYwEwYDVR0jBAwwCoAITMu5Qbn1Cm4wDQYJKoZI" +
        "hvcNAQEFBQADgYEAlEVOqXcdeTU7wT0l+/BJhlG5iaAcanAsOaJFZsXPjLMSjhldQe11/z" +
        "BsrrqjcpdctcmBarKO4MnwqVU9DN2RZ/v5Gps6OcPxj3T8wlrCGe4l6s9d1FncBMJ0RAUe" +
        "QEn2JLkQW5JWRBQ00+RXJYFuIM6Ger2MipWj1oOciv9MMoc=";
    public static final String Intermediate_CRL_1_PP_01_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wMS4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAITMu5Qbn1Cm4wDQYJKoZIhvcNAQEFBQADgYEAycux" +
        "rzvy2IiYfFkTw7QgGuBhxIQPbSIbfudqyUumuviHJkIMZpPwYj2wltjyiRaozrDAWq8mlc" +
        "PsFYNr2lUYN5Cj4BhNQCNZlyBw7LLdzRgza55zVjmYkHWedyZm3kPWe7Y0w8xc/XIvi3iC" +
        "qlwV+X85cgHNJarx3GEYdb7Yos4=";
    public static final String Intermediate_CRL_2_PP_01_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wMS4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAILRhQwULcyPYwDQYJKoZIhvcNAQEFBQADgYEAbcjU" +
        "+8l6pSik8PcuIzWndAg/w8uRfAgR5W9hPSXZChlx7uM+48wK98DGEXuTkJcbeclZia+Mpi" +
        "J5u3qG1zhoL1aHr+RqyJrjiWKC4/rDBuiUk/ftU54mrYn0qev3aSjf/GLtpcC8kC3gpqD+" +
        "20bvxLjBG3Vc9ZrxDvzfj8cD9K4=";
    public static final String End_Certificate_PP_01_03_crt = 
        "MIIChjCCAe+gAwIBAgIBSTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wMS4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDEuMDMwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMO0l0+X6jfT8cY4DumtseTryyIJ7h+nraogXmYo" +
        "uhFGvMUWEAZVGD4x9QTTVEL/UCqNfzpI//Pp/uZpDudSgOX0ZdAbykObqCAEO85msK+eie" +
        "8baS1cW1XGjCuWDqNZko3Uo3c5lLPlRMbZ3hjvA1zmYh3prYnOh032GZAArVcVAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIMh2aWvtm0mgwEwYDVR0jBAwwCoAILRhQwULcyPYwDQYJKoZIhvcNAQEFBQADgYEAigVE" +
        "FlCgbgKLR9FWIiwnz1bZ0MKsfhytllCI+jGx0Q3o3CxCGXs9PvL6BPDdMOxNIT/oU2uG64" +
        "EhZEjcZCnUknGx9OkkSSVq44P/pGuUx1g4Kx4i8gsJ/UPrPpYv/3heuMcKWCr92l33cxPT" +
        "IU+kmAtqy0MBvBKL4p635+MSIVA=";
    public static final String[] TEST_36_DATA = new String[] {
        Intermediate_Certificate_1_PP_01_03_crt,
        Intermediate_Certificate_2_PP_01_03_crt,
        Intermediate_CRL_1_PP_01_03_crl,
        Intermediate_CRL_2_PP_01_03_crl,
        End_Certificate_PP_01_03_crt
    };

    /*  
     *  test37
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_01_04_crt = 
        "MIIClTCCAf6gAwIBAgIBSjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjAxLjA0MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC9gxMP8j4L+ISffY9wkislQ/V5sO9LzZOncYK93lZf" +
        "HXJG1MPSQzFPNzDLSc2zsilA03v6q+zr4NRrRWwWGmB34NGM4aqkoxox/7ngTn0MIq5gZ2" +
        "eOx0FbjA9W9DHEceVDS6kgs9lFcN2W+muCG2/fGqQUED9Fzl9JSM/tE8XAKwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIgdUt9H4i6kwwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAxPe0vM0BvormJLF5HxkyFcTtoombfDGANoLoyj+PTWRD6z1/AcAx5K" +
        "rn/0J1sZo13M2ezaZUABbbpNH9X0OS225IJF4mXNpfkYhsz/+jNPGjRpN2p0K+DhMSawUw" +
        "QfGv2x6f31k6WCdy/769i1mwKP6Rpph2nkRyYW8MwO0N5HU=";
    public static final String Intermediate_Certificate_2_PP_01_04_crt = 
        "MIIClTCCAf6gAwIBAgIBSzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wMS4wNDAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjAxLjA0MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC7YCtN67S/ItOzaSGqTvfEE483HoQGiQZ0ob3+0beK" +
        "kmbSGADBQVBKe/sLJEKddyV2Gl8S4x+cKaKBWUI8lMZViJwWqVnyAFd8ZiAB/BpXaKKgP5" +
        "pFsg10Yo/EtsxGlLSTLurst0azNnFv7ca5Hb8te3T91eaI6y59IjbsRgilSQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIGazrt+QRNCkwEwYDVR0jBAwwCoAIgdUt9H4i6kwwDQYJKoZI" +
        "hvcNAQEFBQADgYEAUIz/MSc6K5eaIAg8skaAgm6rSPvcU/711b9G0qsIs6YqvEz4zhGi5X" +
        "nalYYXfaSQzomuRuABNvuR1Ydaw/B9OdPMro0DhX8VpY6NzCL5Qj60/I4is5a+Hzgk82ck" +
        "eAC3okPHbVMd7R9kdFsWNE3Capnv7rriqXO3vwFw8b9vXD4=";
    public static final String Intermediate_CRL_1_PP_01_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wMS4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIgdUt9H4i6kwwDQYJKoZIhvcNAQEFBQADgYEAkR24" +
        "ebKfvEhDA0C7sawukQbv/q8mjSS3CrhA/oqeb8bML1IlW8rjHSXuRU/n3oeyAZuxLCAQMU" +
        "TPG6Vq4dOu8XC1RY74xIm8ps4mE0xB8/nI5kadHUSDPtUZhNzc8tv+z7fUGRaVGL7CBEpq" +
        "ICyQKYytCwxyf4xu2Ip71Uy2tuo=";
    public static final String Intermediate_CRL_2_PP_01_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wMS4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIGazrt+QRNCkwDQYJKoZIhvcNAQEFBQADgYEAjpUo" +
        "XSj0HX7Wm4w1FiRBBazInGOhSQX9VP2GcGb5lfr3GKt75Y+C+C9qd5X25DVkA4M1gPBK+u" +
        "XjSMQoHAmFJychQG23rcGcuDJlzRMyfvPCF9dOGLFdmkuHSo5hQUyYsxnXV8cWLIkR1AUz" +
        "PtUbTJL9g98R/OJFsCBiPi+By6w=";
    public static final String End_Certificate_PP_01_04_crt = 
        "MIIChjCCAe+gAwIBAgIBTDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wMS4wNDAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDEuMDQwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOtf65MaydWM3bmMT8tAGCX8gZkx1JlgQyBlJT67" +
        "2APIkfmKRFK/dBtSwwCVGHZG4JYBrrwMpzUPrkGKYI6ZVIvvPnPfadZns9i5SM5LZFS+a5" +
        "JfbRnSJd8dXhZsKHxqkxIWwG6+VgnRKXE/Uc4m8TePQJZEOra5ezna5yhvqUwPAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwAjARBgNVHQ4ECg" +
        "QI4iNoMjKiXMkwEwYDVR0jBAwwCoAIGazrt+QRNCkwDQYJKoZIhvcNAQEFBQADgYEAmOjp" +
        "2EupE1AmgjGfiGK1fk9kf39yQXK1EDsyO6KLdWL/bmWeYi/G7ZE57/+yVVADJuHI8xVIDZ" +
        "LAC0u5p35OLgbcmmA5bs52KWJJfa0nbgGpVaUSMg9SkEGS997OsgExWMvYhdFIKXlq4Rwc" +
        "ca89Hg1GlXdrpfD2OCDNBvcWB5Y=";
    public static final String[] TEST_37_DATA = new String[] {
        Intermediate_Certificate_1_PP_01_04_crt,
        Intermediate_Certificate_2_PP_01_04_crt,
        Intermediate_CRL_1_PP_01_04_crl,
        Intermediate_CRL_2_PP_01_04_crl,
        End_Certificate_PP_01_04_crt
    };

    /*  
     *  test38
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_01_05_crt = 
        "MIIClTCCAf6gAwIBAgIBTTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjAxLjA1MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDFzEEzV/yUEORIOufyqpZzKpYz5aPyBbcDf8AMMCM5" +
        "tEz7j39cf1f227cbrTcAaUfYFwkrb07RU4bTS2X+U2Ak7Q5OROz5rrZBbsfwF3yHhwHxCg" +
        "KLjbwz7D+OJdNfv7x2HRckwfMUkmP4cEuJIIPwj1ieBbsnUi9dkWZePwl80QIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIjsCjmszYCHMwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAWMUBdOdHMB/SV5kPUk+zut9g/1v/GyxyB60mq9jGqjrIsk4a9JRqa5" +
        "MWju+6kVfSLelAOCR24EQsXnZM/5Qqg3Wb/SFJXWDcBnfWQWgh8UmJfmPhD7jViG5QVIxn" +
        "iALNCYtz373L+IDECLMO6S3wcTPsHdYv14jl6BKtabwIpE4=";
    public static final String Intermediate_Certificate_2_PP_01_05_crt = 
        "MIIClTCCAf6gAwIBAgIBTjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wMS4wNTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjAxLjA1MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCZzdj+ixWCuxJGMjcoHUwSNqI9Wt9gYwXUTl+dWg/E" +
        "lg2SPJP7lrBOibAhSmaTorhunUSEf2adhdxhuGrd5Ucp6G0oZAa6ZDWaID4rKYWsI7d5kv" +
        "mrUhDEEdzk2s4PCoPiQm4dKwRg2rIvA5Dv+W1ldqSVSG376zVrQ5xdjDUX5QIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwAjARBgNVHQ4ECgQIUASviIKBmJgwEwYDVR0jBAwwCoAIjsCjmszYCHMwDQYJKoZI" +
        "hvcNAQEFBQADgYEAa3c+0Drcq7iWP7K+gE6Mz/0ATQoiG87irXWfWBUGWtYnsh6K+1THMl" +
        "ibmZjYhsztK1P5rm6qL6HAyw0PhrRE9imqZ16cgiMomh65BWQImOeiXx9YWIPvjXWsE6iV" +
        "E31XShr9b9OZBA2+Zpydc3ID/SQzy9PiTAfL5yJiW/JZvFw=";
    public static final String Intermediate_CRL_1_PP_01_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wMS4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIjsCjmszYCHMwDQYJKoZIhvcNAQEFBQADgYEAZIzN" +
        "pXT89MplQgcXcA/K7YKlf62QCbw3rE+bUQiumJMlNGiVdaNJ8T66ObyoOWE+s+KN/Oetlu" +
        "HglQ7r6RG68gHYtZZiO6kmxq+wor65dFGQyRggpD+D47yioEgR12wUUksL/8oBW1pfGW2B" +
        "dR4sNWjzV5k5EWbLYu7wxj2/ubo=";
    public static final String Intermediate_CRL_2_PP_01_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wMS4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIUASviIKBmJgwDQYJKoZIhvcNAQEFBQADgYEAlZ06" +
        "h2L/89GvCtU1K1VtbHPMN/LAUYJrWFID1Eo+Cf/5wKEGBr8hxRtvshTK436zqVQRQN/XTq" +
        "7u0SLxvIixNRErlmUlGByi5vumN2OA77SxOyqYLCnBXTd5tWbFGz/udjaNk1MxOK0MQxPV" +
        "9R+HHUUVojRnAIQvlcqx/sMzU5o=";
    public static final String End_Certificate_PP_01_05_crt = 
        "MIIChjCCAe+gAwIBAgIBTzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wMS4wNTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDEuMDUwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALyBn2GKvoKNHcu3AEJRCbWOyUpCc/onvRoQgWRr" +
        "wE7vMI7vjqnoR8mXdWDW5u9DFu9V5pb/yHBWn1zpgFGNnLrqn8irwR9i6Q+qlu4lXL5WSr" +
        "DqBqEKxrOBDPgkVz8Ldjt/Hy57qEukBarvpAwTc4XEJPAmxNrboMeGCEn2UShbAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIaV3Cd/83r08wEwYDVR0jBAwwCoAIUASviIKBmJgwDQYJKoZIhvcNAQEFBQADgYEAVJXz" +
        "gooT1qd6rdehnLxJMf1HZ6JuqpyoQjzWF1jA3SkJmBDMXvAkMmIcQ7r5CZHaVF0iMQl5JW" +
        "fxPtM9Bws6jZhVL0TkwJHmbnSvbzUkJYeXPCP7ags4bu5I32co1nFVF6wf3aQDZeLFj/TU" +
        "1GCQ4rh80T5oknuazD4xXAYx9sE=";
    public static final String[] TEST_38_DATA = new String[] {
        Intermediate_Certificate_1_PP_01_05_crt,
        Intermediate_Certificate_2_PP_01_05_crt,
        Intermediate_CRL_1_PP_01_05_crl,
        Intermediate_CRL_2_PP_01_05_crl,
        End_Certificate_PP_01_05_crt
    };

    /*  
     *  test39
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_01_06_crt = 
        "MIICvjCCAiegAwIBAgIBUDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjAxLjA2MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCjeJAwaZ0cw6O76hu15XadwJiTsIJcXZxGAETq8H9p" +
        "VJs7kJh57oLpO/lG8zG89QS9g1ozxaaGDWsSyXsDzv1eqDVZg3ISQu6XcKdDu8EwgQDY3S" +
        "EGkJ2AidFue3l0kEwR9+rtsuVKd/P+ULF1hWcoyLB/sQD5z8GvIiDKyRBiFwIDAQABo4GL" +
        "MIGIMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMD0GA1UdIAQ2MDQwCwYJYI" +
        "ZIAWUDATABMAsGCWCGSAFlAwEwAjALBglghkgBZQMBMAMwCwYJYIZIAWUDATAEMBEGA1Ud" +
        "DgQKBAh9i6tKUsPTgTATBgNVHSMEDDAKgAirmuv5wudUjzANBgkqhkiG9w0BAQUFAAOBgQ" +
        "B/Gxsb5lxSTN21CrjBp2aE+U1oTP2MpIFWUD1q8KWhZZF1iCQ7orcDVITqJPdPxDu1YwKk" +
        "zOegc4YBSJzHZqF/W4Kw4wisMfnWLTsUAeP/Ucz4vXk5rsf7IRssFG6PLxVmtRZizoxl9a" +
        "DO9abTM/jV8Mgi1IB6LdWgmtosBGBzbQ==";
    public static final String Intermediate_Certificate_2_PP_01_06_crt = 
        "MIICrzCCAhigAwIBAgIBUTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wMS4wNjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjAxLjA2MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC8DbqYUf437toWlRkOQA5PloqYQjWYpiR67yGSjQHp" +
        "j/HlduTYFS4qfUbLCjH4qsNUH8yQDvogImQw5M1IQOsUAqO6mYFxjqUWccuOaHT6XfUaOs" +
        "DDHr/tQUvhz3LJryaILiPlNcQF8QiYpujM1utVRyFpmUrMAlOvWUB93c/xUQIDAQABo30w" +
        "ezAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAwBgNVHSAEKTAnMAsGCWCGSA" +
        "FlAwEwATALBglghkgBZQMBMAIwCwYJYIZIAWUDATADMBEGA1UdDgQKBAgQxGVMTJml1TAT" +
        "BgNVHSMEDDAKgAh9i6tKUsPTgTANBgkqhkiG9w0BAQUFAAOBgQALJtPqY5uROJ+2QYTekn" +
        "fSUc0gC7j3/cngIvxGT385xDLTrd6TjYSi+12+vU7RNd3MIZoz1o7RpWQV6C751WtOFuZi" +
        "iXeQ758aLqfhjYSVW/NHkO8vjrAMUzUbgjqb03k7q5JgtT6udB+9ySmou2/RxYW5p/IT17" +
        "euMVGmQb/RFg==";
    public static final String Intermediate_Certificate_3_PP_01_06_crt = 
        "MIICojCCAgugAwIBAgIBUjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wMS4wNjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EzLVBQLjAxLjA2MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCsQqIx0ayxpIE8NduclvK1ubbNkXyvr0RDqnGOoyTj" +
        "yMtnfnwRbclkFCNBdalZYofuTWP0reqvqGqsBj+RS3uazvDBqVmn0J0AGRiLILummgEFRJ" +
        "ow8IB1hduDYJpDMrHRpfXpbG2H3fzN1XeX/B0hUZgdQ86GyK2qrmyIcyqZXwIDAQABo3Aw" +
        "bjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAjBgNVHSAEHDAaMAsGCWCGSA" +
        "FlAwEwATALBglghkgBZQMBMAIwEQYDVR0OBAoECNKJMmEWCA+jMBMGA1UdIwQMMAqACBDE" +
        "ZUxMmaXVMA0GCSqGSIb3DQEBBQUAA4GBAKv9F3+Y4N8RX4bRZ4fFTKri2rrB4BsVrBFpOr" +
        "SLzKnuyO1O5gg45d70pSHUAVBn3pz0f/6WwWLECq9tB7/Fphi0TyqeFmkRnysygZGlvLgs" +
        "L19bpIgVPkjFFziMGuzdAFIGy8vnV19yJ2euMygEHr20yiGBUaHHnKyuOGbDg4i7";
    public static final String Intermediate_CRL_1_PP_01_06_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wMS4wNhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIfYurSlLD04EwDQYJKoZIhvcNAQEFBQADgYEARL4u" +
        "DZvfcQDYanTfwU/hWAJDdDO7m7oQZLy3o0PTqXkk2Jd2v3+M2U8UN2PcuqZXT1lwS/piiW" +
        "Sc1x1YndD0qUtV4bOZ9SESPhCeOc1lQTk5mMf/zqFxQqYv8rfDB5O3QY4bjS7QQzSsvmal" +
        "TGCnoHmUJ4skmZJrQAzYnXyD9G4=";
    public static final String Intermediate_CRL_2_PP_01_06_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wMS4wNhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIEMRlTEyZpdUwDQYJKoZIhvcNAQEFBQADgYEAcEyr" +
        "sgLhVq0L6N5fww/U6TW4lqaVAEtjqxluWRyZnL3AJLEHfwh1lllCG5dNM5fahGDOW/53fV" +
        "+gW5l92bsi2D/lAkDfNUdQdi5ZpQG9y2zhTArUlx9z1+KXklCi2Gg1X22gi+cYbK2hfzk6" +
        "kNGP1v42bjrkF/ECczpy3e41rEg=";
    public static final String Intermediate_CRL_3_PP_01_06_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QUC4wMS4wNhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI0okyYRYID6MwDQYJKoZIhvcNAQEFBQADgYEAp3uQ" +
        "Tn2HC65TFmSjzvjuStIJwJcVahNcTWiGdtfTalZrMtuC9vUgQq0K1QIa7QNC9C3hQlzb5e" +
        "bO7JhJDs+5GZnnsqHN3pvdKEoueRfWBjUGpPnSGFD61ysf9aDFY2j9Amf3zcBFsXZs4+DM" +
        "dIENndbjkwqCV4zRTajAqCsIy20=";
    public static final String End_Certificate_PP_01_06_crt = 
        "MIIClTCCAf6gAwIBAgIBUzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMy1QUC4wMS4wNjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0E0LVBQLjAxLjA2MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC+IxiNJMOQG2gx1xd9ELNuzs9LrVJVRLvgP0lpWrx2" +
        "2HTEXPDB6YmrEg/YgyptmQ5Z4K6CEgJz3EdDOarCSGcL7DmcSEwEw46MV3piS5DrHwQ4GH" +
        "a2/ENSh3lF+6dliBwbQR2necmQ5g8ekqkWNb65pLl6RCNGkntJpdu8w5GWbwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIMf/eRyakKwgwEwYDVR0jBAwwCoAI0okyYRYID6MwDQYJKoZI" +
        "hvcNAQEFBQADgYEADgpHRDgyPuK4dc+m2p0IELHUAK3qsdTZzBXsaA0rkkk1aRjI6DQ2qg" +
        "b4crRU3spQgYwBC7KQYd/hp8Lk17iX6fdV/9wol0DxTGhamOJA0uRl768awRArf4cEUElF" +
        "uWPN8D3wJEfL6BWgReUJWg8V9HEtdvXZZgzFN/CgHRkQ2RM=";
    public static final String[] TEST_39_DATA = new String[] {
        Intermediate_Certificate_1_PP_01_06_crt,
        Intermediate_Certificate_2_PP_01_06_crt,
        Intermediate_Certificate_3_PP_01_06_crt,
        Intermediate_CRL_1_PP_01_06_crl,
        Intermediate_CRL_2_PP_01_06_crl,
        Intermediate_CRL_3_PP_01_06_crl,
        End_Certificate_PP_01_06_crt
    };

    /*  
     *  test40
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_01_07_crt = 
        "MIICrzCCAhigAwIBAgIBVDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjAxLjA3MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDs3Z/FfgJOyKp+Ds8xiQBM053cWylYbD+g+zuWDz3d" +
        "nD0eF77TLPITL7hwI058Pn3tXHlveuKMFqbvzWUgFXaBoHmmRohIj1eqfJQhlmKLjlSYyC" +
        "N4xhLVi7vg71ZjFdRk1k8ME1HDfpb2WXqXh9LyRYY8b/aqL+NHe1PUDbT6FQIDAQABo30w" +
        "ezAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAwBgNVHSAEKTAnMAsGCWCGSA" +
        "FlAwEwATALBglghkgBZQMBMAIwCwYJYIZIAWUDATADMBEGA1UdDgQKBAgvehPxsTfSBDAT" +
        "BgNVHSMEDDAKgAirmuv5wudUjzANBgkqhkiG9w0BAQUFAAOBgQBpdMBEONGcpFitMN1ihf" +
        "W441E4HVTQwtF+h56aagVFndUF1gQsVEdDNmvvN/jdlzXotcfdEj1lOahmcwWbPOlNx3PB" +
        "LUPAcaNM9SCrXWi1gKJK3gXC2OAxj0mT5XhfPlAdfhZXTBZLqMqebmk6kVwa+VyPPZFHGy" +
        "BW0fV2ClJ69Q==";
    public static final String Intermediate_Certificate_2_PP_01_07_crt = 
        "MIICojCCAgugAwIBAgIBVTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wMS4wNzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjAxLjA3MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCrO/98w96Bg5YTTmtdc9sL8AOABGcYx5J8E1Y7/GhU" +
        "2sInc/j0dtBbE0Tj4KFIKpVLD0m2mTyHVCUA0/QGiS1Tq6DzmZW/V36Clya3CoX9rDTJyU" +
        "cKHpgntV19fFAK58aksyKCdP9jjLpbSspzOlIc+mVW+hkjgw3NcuY6fAOQvQIDAQABo3Aw" +
        "bjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAjBgNVHSAEHDAaMAsGCWCGSA" +
        "FlAwEwATALBglghkgBZQMBMAIwEQYDVR0OBAoECEmeATXRkM5EMBMGA1UdIwQMMAqACC96" +
        "E/GxN9IEMA0GCSqGSIb3DQEBBQUAA4GBAG/Qv60jyImedUXtCYl0QpQ1Ne2ZLxvUHRLms8" +
        "B1nXC/Rze7zfz5cwiyQn+6XN2rhuYFdTMDEFZDIjeeCLNllfan4GUAdRGtoJnfoLOGLlQf" +
        "RW1ONc80cxd1NTxHqxOtqpWdoJQEn8070WLqQPACEs88XYKBZ00sF9ZdSg5vhHUu";
    public static final String Intermediate_Certificate_3_PP_01_07_crt = 
        "MIIClTCCAf6gAwIBAgIBVjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wMS4wNzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EzLVBQLjAxLjA3MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC+5b7o4iWl80ntDMKGcnquLQDTGlf6Gy/8y34Vw08/" +
        "8ij+nuHMiKpo6UCF0OpDcnkJ2ovvMsY5dAb5ErhH64UbnMlKbghnGv0sVidtipoC8u7ey1" +
        "YUIzDCdmbNvTfho6IXKzH8ev//K+FJd3qBuKHl9u2Kk5+igsyb+bPSid7d/QIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIUDKu7h5EQ70wEwYDVR0jBAwwCoAISZ4BNdGQzkQwDQYJKoZI" +
        "hvcNAQEFBQADgYEAnKhR3OvdgtVtmio7ikCvjxlSoKVbUleazxONOxHUAKdXEv0/mSOTwp" +
        "hPPIoE2xAqPOOHvXPmzmJpPADjrfhU6afJ7ThDRFTMk4ZLOkT1SvRlymK7uWhj5bhUgi6S" +
        "UQ2LUmrY2hIN4cTrrzZvDw2Q/6UIuqpmySXEOHDL5T5MXEo=";
    public static final String Intermediate_CRL_1_PP_01_07_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wMS4wNxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIL3oT8bE30gQwDQYJKoZIhvcNAQEFBQADgYEA4gZR" +
        "71wRXNdxWe7kaQPAw44UUw+cN1bDBU0RV7nwYAFDYxDIaDGOfjhUVTMBq4rb51S7uqIqYS" +
        "F6j7BdLXl9WVRJobfkRH0t0cBnuSeQRz3ckrZrCuvyxb3PEL3pbf0UH1i/BfoG+EHJAY7R" +
        "OVOL/dyoXeX6ehH6ImGhucDixS0=";
    public static final String Intermediate_CRL_2_PP_01_07_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wMS4wNxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAISZ4BNdGQzkQwDQYJKoZIhvcNAQEFBQADgYEAfzKw" +
        "NHrl10PJDHa3olBYXYzXi94zxDsEQSIb+W4pPXUfDZijPqL1NzapLqc/uL1Sl28GmLDrbm" +
        "nCrlMn1Kt/gI6XndOnSyC9Sg6WDxAI3HTHxlG5MHLBn9Lb36CHobnwep1BMo8zl2clh0Kz" +
        "PIxQSGXM1BDpHkwF5eoFAolDih4=";
    public static final String Intermediate_CRL_3_PP_01_07_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QUC4wMS4wNxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIUDKu7h5EQ70wDQYJKoZIhvcNAQEFBQADgYEAj7+M" +
        "EeIe1GmJpbRUFqbNrDvT5tHjKQMNdbe5Y8F920U5t0ig1Up60kc7hs7LH57i6R/quPOpym" +
        "a9Eo9Bql+P2Bg9FELih5/a4B021TZBmmdSI5fwQZ6Q5PjgG58Zl2cJitNYvGi7tVUBojA5" +
        "CSN7KBMyipia9ivxm9a/llJPrQY=";
    public static final String End_Certificate_PP_01_07_crt = 
        "MIIClTCCAf6gAwIBAgIBVzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMy1QUC4wMS4wNzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0E0LVBQLjAxLjA3MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC/RmUcYHxgQRHCUh5cMug/J2o8DzYbT+2pIehJkNCr" +
        "zfqemV3qshLdMct5GV73oEkG5b6n7tj3/hI1TLh/A3LQpKROAGZybdo9fk4Pa0+6V6ql/U" +
        "NnSpcAKct/f3IvchGo9nBGdi9aE+j+xKhMM6E8xj1+Jc7Z0xz7zE4+qRbeZQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwAjARBgNVHQ4ECgQI/y572lfRyH4wEwYDVR0jBAwwCoAIUDKu7h5EQ70wDQYJKoZI" +
        "hvcNAQEFBQADgYEANl9zdMKbaq14OP45PeK9D4ftOSuliW2di1qAX38FQoWPYLLoaDU0Q1" +
        "9I54PDY/UYRR9jKDl1WPhV6cD+65eadtiOZVr/h1CaW/HxTloouzN4z1zCXMC7AxZKo+EI" +
        "XLN8f4w7hKLFYgf6gP9+iVi+T2gKfH5Ch2zjRhlmGFRgsBQ=";
    public static final String[] TEST_40_DATA = new String[] {
        Intermediate_Certificate_1_PP_01_07_crt,
        Intermediate_Certificate_2_PP_01_07_crt,
        Intermediate_Certificate_3_PP_01_07_crt,
        Intermediate_CRL_1_PP_01_07_crl,
        Intermediate_CRL_2_PP_01_07_crl,
        Intermediate_CRL_3_PP_01_07_crl,
        End_Certificate_PP_01_07_crt
    };

    /*  
     *  test41
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_01_08_crt = 
        "MIICojCCAgugAwIBAgIBWDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjAxLjA4MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDDe20HLq7R8b0fWTsEiNV3Z5IbQseZ8QCW+1cb6yM+" +
        "ArKLJDnXx8zmTHSHQCpw3G7xhGsxA1btm0cSC5P/1bw/kFWsSLRe2NFF6oKU+7c+cgIUMB" +
        "kzyXk+kpWAQRb7hcb50iKdKFtO8gMNGMAxlHRI05/1tThyAs9suI4TrxTS9QIDAQABo3Aw" +
        "bjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAjBgNVHSAEHDAaMAsGCWCGSA" +
        "FlAwEwATALBglghkgBZQMBMAIwEQYDVR0OBAoECFxr9vgF31fKMBMGA1UdIwQMMAqACKua" +
        "6/nC51SPMA0GCSqGSIb3DQEBBQUAA4GBABaX7TYfmSyVmzGCVbTFweUuPilo4wzy7z/w0x" +
        "y4uSaM/YMtixUdDPpTHOJNYDdeV85v+w9oezdL2ZYAaGn7tldC6k8ouq/6hOGGST+ziHJS" +
        "gTOD8UVBQPRPvWEwgmDIprnzrVRz8rG6uqslXNiBDnO9BMGpRo4dy8YpOmV6BPCD";
    public static final String Intermediate_Certificate_2_PP_01_08_crt = 
        "MIIClTCCAf6gAwIBAgIBWTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wMS4wODAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjAxLjA4MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC8nLZcMLHYKxVqbhwJiqQbAYhf7S6ck2O9AhNor935" +
        "Bfm7/8qVZbBAotQy1PoCjSW0UYdknDolWvi8aAtO0f9XVrAv6BZVVW9j3osIGN/XUThaN+" +
        "9dZ83kGpyjeoitpGK4wbFNDteuBFYp+8gFNupnX7JQwUK3aGwBUucbe7puRQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIL0xyFYBk4OcwEwYDVR0jBAwwCoAIXGv2+AXfV8owDQYJKoZI" +
        "hvcNAQEFBQADgYEAPk+Lys0Ueoyhp544EH9Hqy9+gY+l/+N99v7KvBlZWKuhkwZDE+qAYT" +
        "P/SOPsWe8ADZE2iQ4pOlpK8jSqtJSdK69RgGL9omLnR04L9c/zKLArBE+VmoV7mohcQp8x" +
        "aB4q/g3QnAqwfFYDjIWW3H6gRAeQ5MOtKdz/4042fJxc5L8=";
    public static final String Intermediate_Certificate_3_PP_01_08_crt = 
        "MIIClTCCAf6gAwIBAgIBWjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wMS4wODAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EzLVBQLjAxLjA4MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCvy6bNOyVaP8JTwiySFa3Sj+rdSqzkalK5gA7DLk4q" +
        "AyvnAK64HgbCsb8dpnSi94WBDsocrQ4C1Ltoahc/AZyRVLA/REsAh1r3/0FALZgYiIxvSF" +
        "m3ihKb3P9URBbotzhl1ahRZPSrcxKwNXEmxB0gjixGW7GZTARq3Il5ressRwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwAjARBgNVHQ4ECgQIwFtfZBe/KqUwEwYDVR0jBAwwCoAIL0xyFYBk4OcwDQYJKoZI" +
        "hvcNAQEFBQADgYEAeZhpIDEYyV/LkOtUf1TryemJExQ1jdfirJ3AUtoFIoWz1p9aqnV6Po" +
        "GAMozjtdyotfSA2O8c065DwD+CvUXPmdD+2vWpX/2hJPj+x++UvvntAokD2UE9HCeEvBHK" +
        "rr59hvKKd6GChyhAjLris202eTLIiMEoyZy9X/Wt1nXF8/g=";
    public static final String Intermediate_CRL_1_PP_01_08_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wMS4wOBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIXGv2+AXfV8owDQYJKoZIhvcNAQEFBQADgYEAhkwT" +
        "E/EGAe32J883qVrh1wG5xQzO/GGfp/zuDYGL2k1zZ2zq7MajKfzBoXXQ3WPh5dTK1sy5o5" +
        "boPHG0pge0B4/2JvuDVS539+9HAPansUNsrMXzOblg1acjdKtuk4oS8PIYkM/lbA6yJl6F" +
        "QMbdIthWqa2gjaWKll3R8fVUjxI=";
    public static final String Intermediate_CRL_2_PP_01_08_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wMS4wOBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIL0xyFYBk4OcwDQYJKoZIhvcNAQEFBQADgYEAN6BQ" +
        "sEQT5YCvs9vlUSdG4gjTgNkyQTCdmSIcufpK4MG/AoW/Fn5zJXxiMyHmvT/dkk/UOf82/s" +
        "41YI/Inz4qRmGF4IL7jo+l7V+OI1n+Vf4ClgZU6ocb9d1dFoBkJu3xI9dcWK6ExpzaBUXw" +
        "rPJilV4M5luGbszdDCs9cLjmiRA=";
    public static final String Intermediate_CRL_3_PP_01_08_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QUC4wMS4wOBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIwFtfZBe/KqUwDQYJKoZIhvcNAQEFBQADgYEAkmDx" +
        "t+r59llppKmm9mSTof9/BX2rNyG9LfIH7wweoDi9be2vYOLy0NU1kJ8f3/muEw2v7hWDri" +
        "k9ROLDFnb/S8MYVT0l4rymRhpshPF1uMTOZmfJUCfTX9jIaShztSScqcGSP0a3EUfDD14R" +
        "1yMu2pdlMM35llE0lV3uf/eUNr0=";
    public static final String End_Certificate_PP_01_08_crt = 
        "MIIClTCCAf6gAwIBAgIBWzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMy1QUC4wMS4wODAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0E0LVBQLjAxLjA4MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDTWNp6Oz39wwU8AFDzYVs3UfVvXg+t6j/qFavnvllI" +
        "NO6aU1o4Hnk1wfmTPZPErc00/MfizMSumTYYRl21hEZWhjNO5uQIHrF9V/4OToo2iOfsPd" +
        "gxwpSokwxcl7CJyadwUxhRDYCLhSORXoCK1CPQZjwb+uQz799O5ozb0WVNYQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwAjARBgNVHQ4ECgQIO1TNJtWwaiIwEwYDVR0jBAwwCoAIwFtfZBe/KqUwDQYJKoZI" +
        "hvcNAQEFBQADgYEANmP9hyFnYvi8gdtRe8ERoEG90NwoyPTsB8sXd40f+Sm1QxKqMPzKPL" +
        "7bOtY12JGwZ55a6HFVgpw4PnU+0iOcCMHS5OQQLtyirxX2HfioiXEmcmRJT6FvLHrGIHGv" +
        "KNcfc3rUiksdOb6+j2k8x4IwQ6pBEHQwY8U4Y4DgqALlqM0=";
    public static final String[] TEST_41_DATA = new String[] {
        Intermediate_Certificate_1_PP_01_08_crt,
        Intermediate_Certificate_2_PP_01_08_crt,
        Intermediate_Certificate_3_PP_01_08_crt,
        Intermediate_CRL_1_PP_01_08_crl,
        Intermediate_CRL_2_PP_01_08_crl,
        Intermediate_CRL_3_PP_01_08_crl,
        End_Certificate_PP_01_08_crt
    };

    /*  
     *  test42
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_01_09_crt = 
        "MIICrzCCAhigAwIBAgIBXDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjAxLjA5MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDJqSSqGjgI3JUJfA/XkloAOg2QtZeAGp2nCq1Oiply" +
        "MTjJpMpEOSRYrEIgKMGnBPq33seP7X/obCT2jgexmbFT2TmPirM+h1aqbGQ7QAqsx80BdE" +
        "ofdcfiNosLbbzli9qFrbarO7fJfBhzraBFGDJj3N8nLi2YtP9IieFYJ/MhKwIDAQABo30w" +
        "ezAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAwBgNVHSAEKTAnMAsGCWCGSA" +
        "FlAwEwATALBglghkgBZQMBMAIwCwYJYIZIAWUDATADMBEGA1UdDgQKBAiVRMrZuHQ7VjAT" +
        "BgNVHSMEDDAKgAirmuv5wudUjzANBgkqhkiG9w0BAQUFAAOBgQCetZy9JMzUVveSPE2fQY" +
        "4fRVChyvIc9nCE4wbzhnRl3zduBGmAwTFr7dRWSFTnEq1c2b6B5nJtCzmt4Ovapf69sIlM" +
        "s3iV16eBB1WTNCY8YlAsnmZ7q/AR0t0vX+hh6QV6zN5xqulOM4Y8csZEx3RWJzV/LjE5w7" +
        "mKvofBEUoqQA==";
    public static final String Intermediate_Certificate_2_PP_01_09_crt = 
        "MIICojCCAgugAwIBAgIBXTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wMS4wOTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjAxLjA5MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDWUTlTieoi7aLGUYOAgqUC2J/6JarOWfv4vobpwjAA" +
        "DjvQGqg/GCZP7FgD/72Z4YefZKJEFZTDnYfmy2qh6iBYxcvLsJ+PJGzPCObNSmyq8gpeXy" +
        "KKEeCZtEev1tSywTT6E5Dhee4dX0QHE4ydZEliMMXGRW/8ffT6x54CPwVylQIDAQABo3Aw" +
        "bjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAjBgNVHSAEHDAaMAsGCWCGSA" +
        "FlAwEwATALBglghkgBZQMBMAIwEQYDVR0OBAoECAMhmGN8+qXoMBMGA1UdIwQMMAqACJVE" +
        "ytm4dDtWMA0GCSqGSIb3DQEBBQUAA4GBALNjokGrTnWsPn5KrlO+g3R8tAGM90JQDjfrap" +
        "xWM+nN+dUVVdGU6w2pAOAq2UhfySiP42qiFChnPK9oOqPF2Or7/kcmXZzBfZkE/FnJGNUA" +
        "gs9je1nZvTPQYsF094OqE7QdJi2k3seA1tqejA1kihMHpwQNmIp8bFpqn4dPO6ys";
    public static final String Intermediate_Certificate_3_PP_01_09_crt = 
        "MIIClTCCAf6gAwIBAgIBXjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wMS4wOTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EzLVBQLjAxLjA5MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDHUpHhF4ANNLOywnvpqyDgzLMtatW3ZxgLBBRYk6TE" +
        "jMgTVKmRasVRTA9uatGG4b2f70YWs9cOd4ylQDqPEDdKNZ47bqZdX6RAU3j1dO9LBwWDbp" +
        "NvZ3zuDBRDoCZClIcBESDYweaZ9nUgKl/WxTeCnMwqkfSJGYBBcHIonRPnGwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwAjARBgNVHQ4ECgQIyppef22OmjEwEwYDVR0jBAwwCoAIAyGYY3z6pegwDQYJKoZI" +
        "hvcNAQEFBQADgYEAOySUCY+PZxomhWgTRSKRodOIe/QSfCMSC+0iw24a2TuJzFLjN9pSm9" +
        "0C2PqWbfwD1uDjrteO1NK+1yhtIDySiptR9GmR/fhL7NJ+z7M4fEJBjjeeI9/aEIuHuBFT" +
        "TVHfwsJxnZtjujtOdl56B825LsKW8Otumd2A43N9wIgSyBg=";
    public static final String Intermediate_Certificate_4_PP_01_09_crt = 
        "MIIClTCCAf6gAwIBAgIBXzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMy1QUC4wMS4wOTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0E0LVBQLjAxLjA5MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDR8/c35YqAswoRMgQswlTbKB9oYEzrFSC0G4dt8ydP" +
        "O4PyQs+J8wUVrRVMiVDTLO9rUnzR1T3iA0dqM+SvWMIA8pMWKyNV58f73ZPJIejhxMmOZa" +
        "sSLHceMmmMRy1zyk38i3ZJP3YhvxffTjWyTZ9k2xSDX+6KNnkiKkJSKpl6nwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIpcWcVIIu63kwEwYDVR0jBAwwCoAIyppef22OmjEwDQYJKoZI" +
        "hvcNAQEFBQADgYEAckgV11ND/D1vfPEMUbDGUvtmsziHiSuEoDLJqSAhOmcX+evKWOfoVo" +
        "f7og+0ajuul7yuB+7YX1AakOw+33k++Rsgg4o+ImZq3+VScpgnIQ037OOhgH3umwFRC0r3" +
        "NpWqhmQuz+mHnKiK3X+IDsQOFkhnpNs06CQSZzmrzbYlQU0=";
    public static final String Intermediate_CRL_1_PP_01_09_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wMS4wORcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIlUTK2bh0O1YwDQYJKoZIhvcNAQEFBQADgYEAkEc6" +
        "qHGOWZXYTQ5fsWyJgEtuJyl8uJ+gMcikcMut5SIJTTtOz+q3wclYDevT8z1MM25kNdgwyg" +
        "b1bwHNAG8I72eIDtGfLrChFwU3qpvVMTG9gPYJb05Q8On56nsBu/PnnzJervzxjViaeOuv" +
        "kjwwfmWqGkyiK433WxzgPqE48eA=";
    public static final String Intermediate_CRL_2_PP_01_09_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wMS4wORcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIAyGYY3z6pegwDQYJKoZIhvcNAQEFBQADgYEAV9Md" +
        "8PaNoIlT7WIwnelqrbwsR66vAaT8w3gu8XDYXu+MOYThfyERUvtH6AUrHWfiRvWEzKljHH" +
        "3BQB0Zsa9Zz3U5cLzJcqtqDc1lH53aIA8MflrfMVrYSF684s28FikcukmA5Fw3+7S3TJ18" +
        "Hq7plHwTCidVD6yG35hsPwcjTrE=";
    public static final String Intermediate_CRL_3_PP_01_09_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QUC4wMS4wORcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIyppef22OmjEwDQYJKoZIhvcNAQEFBQADgYEAjBaP" +
        "V/TFQtDLxQFIBCbfqhlgpOfvJBatjNuvB0TuD2rsGS1eaLNfTfyVKlOLpxoKwKYMu36kIO" +
        "l/+KEPDq+ofy7uDZ6GLK3KZ/WiJyriqBQjFCvlhNTW1cjA7Ejk2lOM/A46mrUS9xC+aITh" +
        "d+/UYGt6O/e256cOwQCUaF2z328=";
    public static final String Intermediate_CRL_4_PP_01_09_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QUC4wMS4wORcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIpcWcVIIu63kwDQYJKoZIhvcNAQEFBQADgYEApZ1l" +
        "w5SJoU8zeKwX5jpVWiFFFomDgKsNlkkX5mF88l0B6MiYbGqJIowJRfeIlxvPOf20imN7Z8" +
        "l38DRXFacDQP4y5kxM420dp+ljQL5q9RsrC1+OS7I7TGgGwPoZTO4mHVk8nx9MyT+kW1OU" +
        "x9qRYWN0CLmP22kutYBndny222Y=";
    public static final String End_Certificate_PP_01_09_crt = 
        "MIIChjCCAe+gAwIBAgIBYDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBNC1QUC4wMS4wOTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDEuMDkwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALiOjwwwUk1HNwf2rdzPL2okKTgL+lMdzhC7cbq3" +
        "6A409EY7iipPCcsDsheo9EaTNOHV9xjWDqOhqjA38h4hGNkRUVOlTW2r8SoHISn3gDXfrh" +
        "aHbU3owscAmt1nuA7rzo7L1eBPsisIIxAY16uAmVN5RdiAAaP8VUdshcNI4/1jAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIGZIY3nffEXowEwYDVR0jBAwwCoAIpcWcVIIu63kwDQYJKoZIhvcNAQEFBQADgYEA0Svm" +
        "aqjaeQx/lnF223xlCTsU7XzOxbHetRWfeCTw0QrWQaTrKjWTS/TNyzLhGuPBFg+NTTvWML" +
        "gzteo/WWdF8+d2rOis9FVRCe/Euok6ZCL/xgzaE86ZSQg0jj6458TpuC2cszSaifRSlhL5" +
        "ogy4ADWgJxdVcBrgADo6QZXkXXw=";
    public static final String[] TEST_42_DATA = new String[] {
        Intermediate_Certificate_1_PP_01_09_crt,
        Intermediate_Certificate_2_PP_01_09_crt,
        Intermediate_Certificate_3_PP_01_09_crt,
        Intermediate_Certificate_4_PP_01_09_crt,
        Intermediate_CRL_1_PP_01_09_crl,
        Intermediate_CRL_2_PP_01_09_crl,
        Intermediate_CRL_3_PP_01_09_crl,
        Intermediate_CRL_4_PP_01_09_crl,
        End_Certificate_PP_01_09_crt
    };

    /*  
     *  test43
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_06_01_crt = 
        "MIICozCCAgygAwIBAgIBYTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjA2LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC4mu1oBHB9BeorCFJIuSw5tszmmYBD4bjTklsAfjrz" +
        "OknQsYxEoHfifpdgivh1fMUk+mK5YWUz0G8/edquKbJhPBTTWp8opsGzTATsTLSEzkKbVM" +
        "DQ84ttxrhJWlrVRlouZTnD5HoLUvujY4EdydmKsjj6UBt/tGL5EKodymcEtwIDAQABo3Ew" +
        "bzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATAMBgNVHSQEBTADgAEKMBEGA1UdDgQKBAiGRi8YRte8PzATBgNVHSMEDDAKgAir" +
        "muv5wudUjzANBgkqhkiG9w0BAQUFAAOBgQDHOaIki9TogVJn54FRPl+7FyzBJ2DnR4RTM/" +
        "q1K3COWRdtvmGqtBBtAccxWziQJ5TnAQn1XA0cFPoCgymGPRcUz+0+C+3VhJ/m9LggVP3/" +
        "pjJEG0fsmJtUYPyphUlXeUzf4qSj34SlJws3DIHTR8ozAR75HZmlMRnxyZBLl+jAng==";
    public static final String Intermediate_Certificate_2_PP_06_01_crt = 
        "MIIClTCCAf6gAwIBAgIBYjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wNi4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjA2LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC2rptuREzhGfEJ3U8ILPBq+z0s+aafMvBRHpqkipDq" +
        "bC7v9zpwg1K18F4MYiATpPAEfdEeprKs0mWfdusF93BoMBVm1y0zRgDRUNdyB5GFO8g8+2" +
        "yNEO6L37c1PwrMLnvJakaqwbbnwlcMcKtLHoX19fyveQQg5DNj8WcKZj397wIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIJPt6qKdFeYEwEwYDVR0jBAwwCoAIhkYvGEbXvD8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAkFJGNze9/6YX7Rv8FR9obFGACIJ7Om4YQQRW9WM9pEDgKls7g9b9El" +
        "dJxLKOlWoRoYZIrbEam19traE2O3dxqRevPoYvfAqkR089BkxH/cFYyfqw64IpjDG84dsY" +
        "XieajI/Ov/HjgF0VQKF3+Y1ZiDjb2OHNgMkqs9VmUHaE+94=";
    public static final String Intermediate_Certificate_3_PP_06_01_crt = 
        "MIIClTCCAf6gAwIBAgIBYzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wNi4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EzLVBQLjA2LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCzxfyi52gw/5tt6/9aNAXdY3wZYH1GifzGoN4cg8Mt" +
        "++5xmTdrc2A9/5biaTUVC0x/Ml6mm940NA9mM/EoEu4SdnP2crNCIFHWNlYz3cJtYJ68rE" +
        "rEU+S0gnYaYRiwNGhVpAjV+FPDr0Ghgp5rYQ61evAhmRuNAFwYocUw80G6JQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIZ9yMlboxCIEwEwYDVR0jBAwwCoAIJPt6qKdFeYEwDQYJKoZI" +
        "hvcNAQEFBQADgYEATNnRMQmvTxRcSMUL4pa5bejuX2Ixy/OfZIAlJWt9AfLW2tHmdAaGpD" +
        "GhTHKfyQQ+HrIMQ+lXau8Yu6nzWXAY8pKpKD1Hbd355VE4dYZ7aPvcAulZHeV0F2EFn09x" +
        "qQ1frHDRoCOc11B5qV5hnwgDE/ByZh1+OWUcR4tBQKyEF4g=";
    public static final String Intermediate_Certificate_4_PP_06_01_crt = 
        "MIIClTCCAf6gAwIBAgIBZDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMy1QUC4wNi4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0E0LVBQLjA2LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDB66hLZx1WGcCqmOxHK/rotXOpccJQOB2L3kpWP1M2" +
        "ZiWufUguLw45XShdqu31OgmGw0/w9ugwy96aRL+Tiluj4xjIAxJCav5cXF8Dt2Ex7hjIHm" +
        "XV0rHbJUiduHEh3fQphgtzlR4QxG6i/i4SbcsoJzsws8x3qOqRPaWDtyWs0QIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIyZsLNvyyIZEwEwYDVR0jBAwwCoAIZ9yMlboxCIEwDQYJKoZI" +
        "hvcNAQEFBQADgYEAc7G4BAUsQeqNp/Kv8TKJckfxWygz54PrkBICNw/eGuGamVJMRkYCP3" +
        "yJ8NW4jY/rfxzKKyjVB09XuNBLDwYdR5Z5UHSg6Ijes3j8tehZ+9DwEQrR+WQf/adHIsxn" +
        "/347MHrSQF7CJzE9tAu6AOu53lKxLeH6C/5YI611or2Ql1I=";
    public static final String Intermediate_CRL_1_PP_06_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wNi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIhkYvGEbXvD8wDQYJKoZIhvcNAQEFBQADgYEAC7ev" +
        "Pqe0veUX+zF51d/NiG6VwgEwOP1HlzD/saDn/FYXStTQDwoIyFjmZ9z0yLGIaVI1O9BWVD" +
        "CTU3bCU1dBg61Blo3rI3TlNqmGrYRUSJ857QM9c/G+/+V0XJ/HgId39Pufd9Tob150XNMs" +
        "9h0PvqjhYjG1bARMRa8JB4KTBU4=";
    public static final String Intermediate_CRL_2_PP_06_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wNi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIJPt6qKdFeYEwDQYJKoZIhvcNAQEFBQADgYEAiUbi" +
        "qQ3X/hTgjhpQGDZi/7EnZcqSgiAFMreV30/mav2NtXDITE9DqZzCS9x1vHBp4BBsQwYVvp" +
        "XvLVSgns4pFwR+0Whc+tPo2j9ScePq3sICsqleWTN1DvuoP9rBe8w7pDN4guA59Kbeku75" +
        "5CMA5YjiTUomK4UaqI3htwkBlWo=";
    public static final String Intermediate_CRL_3_PP_06_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QUC4wNi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIZ9yMlboxCIEwDQYJKoZIhvcNAQEFBQADgYEANowv" +
        "f/scWT6FFT393XEpWcTnA18hBT5Nkddw6mHjKBq7ndtBQkydMO8Wym1IeQ2qYbAqu3ifNZ" +
        "SKF3PfgJjYPBKImzJdHTKfcclMC5H8Y9JDN0voeyONr9NiXcoj+p24YNYjb+PFI6avRYo7" +
        "Xyrqvwnvng/IY9zLtc7SYYUIODk=";
    public static final String Intermediate_CRL_4_PP_06_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QUC4wNi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIyZsLNvyyIZEwDQYJKoZIhvcNAQEFBQADgYEAsnA9" +
        "ERwsi2mK540oPL45mLdOjGnet7+HhNk14q0hvALTYGB1vEjijc+Yvf6mHJGRbiG207BpJ1" +
        "DWeWBY8TLe4YJXlSrWwx1jD46rCt7gdqXAdLpMo+i35yfQ19ZqeWcRLkspmczoUJLJaJza" +
        "eLRrnjv62GLJ09KVKpZBGhV3SUM=";
    public static final String End_Certificate_PP_06_01_crt = 
        "MIICbjCCAdegAwIBAgIBZTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBNC1QUC4wNi4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDYuMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKrLB7XA0PKY0qtSC5lMBvvIvbyjBM8XmANrN9Wx" +
        "66QxEuloRAz0D5uAu7TnJBv6qNuIPGFl74yusKCSkjEkBMdVpBCfDvpG1/Tz3sALSlxmnz" +
        "xbK2ytOncbYuYrzvXttx6wkhLrBLlnfuwpZwGZOr/Pt6WwQJWjXxgTNJ6dcgXbAgMBAAGj" +
        "OjA4MA4GA1UdDwEB/wQEAwIF4DARBgNVHQ4ECgQIv0gg7LxDM+swEwYDVR0jBAwwCoAIyZ" +
        "sLNvyyIZEwDQYJKoZIhvcNAQEFBQADgYEAgzlxBGGOBvHw20eOzSswMqrHopNMcvwuEO+Z" +
        "Mr0h8U2/HIiRqKWQaxMyM8A0oULGJny3B/0WtkfVQ2EIibZGiKIjC1RPAB3QmL0vgSyUmF" +
        "s/LZbzugpJW6jvfov7N4O+u0J5rYniRxa4bgrXa89TY9kwDMbr6/z4oiI8bq3gEsw=";
    public static final String[] TEST_43_DATA = new String[] {
        Intermediate_Certificate_1_PP_06_01_crt,
        Intermediate_Certificate_2_PP_06_01_crt,
        Intermediate_Certificate_3_PP_06_01_crt,
        Intermediate_Certificate_4_PP_06_01_crt,
        Intermediate_CRL_1_PP_06_01_crl,
        Intermediate_CRL_2_PP_06_01_crl,
        Intermediate_CRL_3_PP_06_01_crl,
        Intermediate_CRL_4_PP_06_01_crl,
        End_Certificate_PP_06_01_crt
    };

    /*  
     *  test44
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_06_02_crt = 
        "MIICozCCAgygAwIBAgIBZjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjA2LjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDjg5+XWZwW1gLAOldsRshbCXmUCmt1Vs+oZsvyH+6d" +
        "2PwKs8ydrz+oD0/D8V7cRXucj7q7cJSLhEY1wJoTTgrWeRg1hQioAXzPW3ZkaZuzhpi+cC" +
        "qeZzN5nPvqK18GWvpffNbUUVfOuaHzzHmhmhgQyZaNG7JHwpWM10UMzMawOwIDAQABo3Ew" +
        "bzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATAMBgNVHSQEBTADgAEFMBEGA1UdDgQKBAh5am+tkndt5zATBgNVHSMEDDAKgAir" +
        "muv5wudUjzANBgkqhkiG9w0BAQUFAAOBgQAF0h1iaxxZUp43AjP5gSvbW6JfFRW/ugH9SU" +
        "n3e1B29LMH3F/ML0joVhPx5CIVpX4nfaYzdeje9+E2/bHMBGSCFeHz9S/KoBLLiI0GNhzh" +
        "I6MytvPMPRx7hkuROouQ69TnslJiGCcoo+MD0fA2YwO1bCtyLdeVHYhJZWQ2Sg8PHQ==";
    public static final String Intermediate_Certificate_2_PP_06_02_crt = 
        "MIIClTCCAf6gAwIBAgIBZzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wNi4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjA2LjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDF4KSKxo8HvQ59E77LcuLpZ7ujNDjb30KB+EbIuRmy" +
        "khXAkhq2Rp2Iqd3OhC0AXmhSF+enJq3h0dqyxNWP08SIuK5ia3OIeatl1UgEyukuAnrLuI" +
        "A7PFUQAGZmDG4OuHv28zza4n/SwfCaKfi8qatIwpwF/29ycB8wYBrHThQD0wIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIKFZV4vjfOOQwEwYDVR0jBAwwCoAIeWpvrZJ3becwDQYJKoZI" +
        "hvcNAQEFBQADgYEAuj8P5ga8Xv9eFjk4AdRMx/Fj/doRAOLZfs+OnrduRXPLe7CFKDxhFx" +
        "xYOma8In08cgXVVnRR+2nZ54h5qjCYpskGNx+yZRY8+HW3XXE3KpS7QgTnc/1XshUy9VGm" +
        "2qX0k661f2d3KnSKiKVKtM/y/j/nNyxPugDz1Yy50NtzQOE=";
    public static final String Intermediate_Certificate_3_PP_06_02_crt = 
        "MIIClTCCAf6gAwIBAgIBaDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wNi4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EzLVBQLjA2LjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCitrzXkbO4hAQpBRQE880MFBPq84umX9pyKbV3iMqK" +
        "Z7HBYwZOvEwGQxG+TX1PIj0Jz27oyvoqpLeMkbn9L3K0BuS0AZKlWIOGPPHWpYTDoQCCs9" +
        "Mba1evVT/1CMxESsv2kgf49YHMs/6TtxQX0qj5TQzXrkM6CMBc5zyPBDWORQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIxLES0WIVZQYwEwYDVR0jBAwwCoAIKFZV4vjfOOQwDQYJKoZI" +
        "hvcNAQEFBQADgYEAdQeDAOFys//2xUFwBilhqr32/jh4gT/ijxRjG0msKTYXmWcCQv9Tms" +
        "smtIMtiwwnByhjTdQAtOmEyDm/CFW0/NBnxlRvqZKt+PRtscpExVy7xnnm2MBITTa+9xkC" +
        "A361jSDPnRPEOZoKdMRRzNnW4f59m0huibeFNRYJ7y8BnHs=";
    public static final String Intermediate_Certificate_4_PP_06_02_crt = 
        "MIIClTCCAf6gAwIBAgIBaTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMy1QUC4wNi4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0E0LVBQLjA2LjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCg0yQG7oewLD2eFfPuj2DPBgT47iEri2IVeS/r5hUD" +
        "nZhxzT2/+UsQfiS+ufdC2Xq+QAcXFcAifPbvRs9xo2q0uLz26mwSq1TH8ilHLKatKwJ/Yf" +
        "hcRAfEWDwhLJGRhZ7YrKu8xczZgyxwaeu5m38lEaLIRyaVfVSrw8WhN4z4ewIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQI/dKmuI1u6I0wEwYDVR0jBAwwCoAIxLES0WIVZQYwDQYJKoZI" +
        "hvcNAQEFBQADgYEAOEcMpdSAVKUzQ1A7LJnWOh5Tul6yXw6qMsdZNGOZ3vYBXH3vHnSHvp" +
        "MqJQ1JIX/4XSiKF8En5dVI/ooNabgyORpPnLGDvrshvO/09iaDlQXxWRsoGAFhcIe7Ibp+" +
        "3g6hnBO5U+0pbInioKVYf/1VyZSUK1QQMutshMIye/8gyZw=";
    public static final String Intermediate_CRL_1_PP_06_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wNi4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIeWpvrZJ3becwDQYJKoZIhvcNAQEFBQADgYEAEJ28" +
        "g5iyw3ZOqs5ly7O2X0YWtgKK3BnPztxygCUWO1xVy/QbMM5ybAU/UPbJC2pUnkOZMX+h30" +
        "RYp/kV9w2o15V1hxj2M0tR8fQ0WXudwi20pZO56uHb+WSaETOmPVoNH5efeXsTvtbHQR5w" +
        "95L2vNeEzJEy1l7S/sasUUoQvqY=";
    public static final String Intermediate_CRL_2_PP_06_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wNi4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIKFZV4vjfOOQwDQYJKoZIhvcNAQEFBQADgYEApLIK" +
        "X/YJYhSfn7yLTAlKjnhpH1QDlFeaE6/+uj6j7ZgpK6HBjHOvfwbrjurl+L3ZTLrY1FCL4/" +
        "SUgXrJxbAyMANlg4Z8u6o73F9cur2gi3sgv5d6FjJ8VwuKYWY2dwZNeXwlWE/W0h01Vd9H" +
        "QVuctFxzQaJQdQBadw/XqzvLlyw=";
    public static final String Intermediate_CRL_3_PP_06_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QUC4wNi4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIxLES0WIVZQYwDQYJKoZIhvcNAQEFBQADgYEAE5J9" +
        "wJKAb3veF4GhHeoIgy6JvMsrjv7d7dhT+ZIKq+wPNk1909X/Zo1GXxJSjMaMgkLlXa0QN6" +
        "LtSJxbyMRCKSJfqTKOezFXirZ7MEQ04FT0z6Hp0m+E2Q7dGs52ZOV3YZBhQUlH+aQ8WNu2" +
        "6clf4VqBiUYgGhkE95PhN5AAnOU=";
    public static final String Intermediate_CRL_4_PP_06_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QUC4wNi4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI/dKmuI1u6I0wDQYJKoZIhvcNAQEFBQADgYEAKgk1" +
        "HJ7OW203z9H7jNGxoLCN9bGDKOFcWlWuruzXWOAn+AomjSZpqZkZU1qyKrFaKM320sfn8C" +
        "ZJPnVWaVMLBLNddDRWUjJrUHtNdnnZEuYPYlRVb0MmwaxHHR0ZBUIaniqoLuvtQIB9N++T" +
        "bu4cjx33mN6MX0oWr4Bbq7ovPnE=";
    public static final String End_Certificate_PP_06_02_crt = 
        "MIICbjCCAdegAwIBAgIBajANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBNC1QUC4wNi4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDYuMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBANAr4hFku3Y6jI+vD6JTRFc7ZLL9tIxT7Mq+QcDd" +
        "rRHgSEXhPL3MM//3ZFXca3w4rXOUVQyANQncywNM3uwl7T9jC0MD2kJ9PsNGQL2bQcSajX" +
        "jrxT403PVFsa6ZrLMU0hwomSO4nJBLCJj3i1rlX9esYbRNCqzep2OMWgAWRUsrAgMBAAGj" +
        "OjA4MA4GA1UdDwEB/wQEAwIF4DARBgNVHQ4ECgQIMBvQP4Q8w2UwEwYDVR0jBAwwCoAI/d" +
        "KmuI1u6I0wDQYJKoZIhvcNAQEFBQADgYEAnmNf+3jJp4mo4YDznASTMnrBBdXuskhnRXSQ" +
        "Gj5dNq6PxEXM+CmBhaNlnFYcr7UCtcD8XwampfyO52tvAZW5kWQKsxyowVtsxtwkAtj6/f" +
        "trIeulIM0B1xjyXJshmVST5u6gZ3OegsAyuqyAbo9B1IvkNFOldt624aEG43jq7ho=";
    public static final String[] TEST_44_DATA = new String[] {
        Intermediate_Certificate_1_PP_06_02_crt,
        Intermediate_Certificate_2_PP_06_02_crt,
        Intermediate_Certificate_3_PP_06_02_crt,
        Intermediate_Certificate_4_PP_06_02_crt,
        Intermediate_CRL_1_PP_06_02_crl,
        Intermediate_CRL_2_PP_06_02_crl,
        Intermediate_CRL_3_PP_06_02_crl,
        Intermediate_CRL_4_PP_06_02_crl,
        End_Certificate_PP_06_02_crt
    };

    /*  
     *  test45
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_06_03_crt = 
        "MIICozCCAgygAwIBAgIBazANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjA2LjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCrUMqMxZ4sSrH6sKv2y6nYKagLvUHaforCnf4z/5O1" +
        "PeldaW4ANtNPA8SkVBES/zoKgvrLJUmqRi4b+BGhCVqLU77PvWyiPOS40tpJfw7m9pPK53" +
        "aeaLC9M6rarjdOvF8MkdtytCMU/Ef1NsuJULwEP+XB90k4lHr9EzbgKhXvoQIDAQABo3Ew" +
        "bzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATAMBgNVHSQEBTADgAEEMBEGA1UdDgQKBAhF0iXZmlIKsTATBgNVHSMEDDAKgAir" +
        "muv5wudUjzANBgkqhkiG9w0BAQUFAAOBgQCmab7noekyx5TzxAqWoQiC9S/aZJtvLkuH1p" +
        "KiZnclMpRvIL1CVOukkzLTZXY0EcCHnXuVGjw+9vmiQWGGw8t6TGCXo/CtCo934HGBxOfQ" +
        "MVysEjst7L7TDQsqxk4j9O8cU/TFWsghW9Ihu7SVIn8RJmknKMB2xkIhcDe8S8dmxw==";
    public static final String Intermediate_Certificate_2_PP_06_03_crt = 
        "MIIClTCCAf6gAwIBAgIBbDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wNi4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjA2LjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCmT7wL9WwWBr1oY9bHIq4IrJOkbOARK3zOeyZSbBBB" +
        "zxcky5kjC9pamMpyZjga+q0CGd2rq9eUjQ2FXZsBSgf/X9B0/g9trNMebYgGnYmHHX2JK+" +
        "doyAX+h3afDbZzZ696S0Hw7yRx00+teQe/Gx4h4qKPwbJIW5Bep9SBysikJQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQInXHgY/+onu4wEwYDVR0jBAwwCoAIRdIl2ZpSCrEwDQYJKoZI" +
        "hvcNAQEFBQADgYEAhlboR5gzYWluWIaFM5R1Ko0/rprrv5BHONRiXjLfAPkzZmd7FLDE2j" +
        "BlU7s7IenICeST4c7HG5zqBigK1814GG75nq5htCGUnM6pn8/gvc58+ckKeWgbJxC5I/0u" +
        "olCCs8ORbWIEGWmghGg1USxeI1RQwXGgE8XwtabVibJOVBk=";
    public static final String Intermediate_Certificate_3_PP_06_03_crt = 
        "MIIClTCCAf6gAwIBAgIBbTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wNi4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EzLVBQLjA2LjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDEouRlqTFQiJQSwc+yhjpvA0dUIbRrNwLF+EPfUWq0" +
        "FV1UV0a5lb5BGPW4RGUEbFwsgGCHsfLiY7WmUpC1e6332PZPnrnoJbf28paeiZ8KqcAKZE" +
        "pGPWKCmFBwBW23q1w/v/CxcXJoBx5OC1yxG3fGH7CZSzc+4Z/+PxLk9yoASwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIc24GzUM6/LswEwYDVR0jBAwwCoAInXHgY/+onu4wDQYJKoZI" +
        "hvcNAQEFBQADgYEANLxcLvJqjyu94HN+X6tTxGcN1s43kQh8yRGotW2ptuA2jmGlAhI8QQ" +
        "sXHO0o0bFLBC/Uv0L0YlEJhK1w0ct7Awwn4UYgqupxug2f84yamcvFa1es3osIMJoi0GPz" +
        "1WDBM711efRtbzvK6t/4fJ01nG2BlMeEbctVqrehuAip4p4=";
    public static final String Intermediate_Certificate_4_PP_06_03_crt = 
        "MIIClTCCAf6gAwIBAgIBbjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMy1QUC4wNi4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0E0LVBQLjA2LjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDNuzSN3BiT84M3Dy6KeTQkMqWNuYGTENWPP8WvQ0Ot" +
        "ggue/lemC+IqYBtIEYtk3A30eKKnF28WIbPlB3oSykrPVV5dMhYGF9ysOtp4wyETHtzdv0" +
        "7HyqlMHOCPiFplbwjUSo0uEIRVgS3luBJi9onTpcn97/i0S7VsM2nooooaowIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIDjpr8w0dRq0wEwYDVR0jBAwwCoAIc24GzUM6/LswDQYJKoZI" +
        "hvcNAQEFBQADgYEArE6qUMnjXiB5eKiAFc9Elw1dYsQArtnDQAfFGtShDulxYKq9+pxory" +
        "4kTMUZZCJc7awEC11tdJp7xJGcpjCJl4I2wBcHiCcVcnwQijqM719PqoQKydXB9MSrXqmU" +
        "2CyakSzBpb82VooVNx0IZ3h0nXQSE3V0qSXXCaImJcOIGMo=";
    public static final String Intermediate_CRL_1_PP_06_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wNi4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIRdIl2ZpSCrEwDQYJKoZIhvcNAQEFBQADgYEAQrHK" +
        "VV2MJPJLNdPoEuqFXRTEclSmYhUWC5lthK0JnKUbCUj2cMAku2UdN5sRgVG0475dXV2nvn" +
        "huxy+IQVt5OJ+PNZ9MYZlC2CfYsBiW9DEYMA603XhVvX/bxx80MwxNby18oyo/V9ycSyJw" +
        "XzUmzYRUtohHk39r3eUSAt5H7zM=";
    public static final String Intermediate_CRL_2_PP_06_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wNi4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAInXHgY/+onu4wDQYJKoZIhvcNAQEFBQADgYEADOEh" +
        "jV8V8y17mFstkVwigOAKURbi7sD24RkLd1QG0Bn21JiwpkGY8Z4vetQps+VX586xKzz6v6" +
        "Sj+TJk3jfHCiEAk6a7PLxRcVCCi6y70mzEBCwn6fS5NDfxzxYYLgq+dlUiVwqXsHksEvUz" +
        "2Z5dpuLhbUGxHiqazNE9iq9pEEE=";
    public static final String Intermediate_CRL_3_PP_06_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QUC4wNi4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIc24GzUM6/LswDQYJKoZIhvcNAQEFBQADgYEAK/zi" +
        "r7ASgtWA0xGQVrqhHsXH9bdaj+FceW6ivoXo3z6xCFLvzu2uenEu5g849+YI0KMomHsDAY" +
        "tX8qO3XEaLGchbhIfywgRVDlSF8ytMKhJTS05R/vZSZAl+eoT3mC92Grihsd3wublyNZ7a" +
        "d925Py/oFp3J+geUkKJQK+RVu4M=";
    public static final String Intermediate_CRL_4_PP_06_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QUC4wNi4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIDjpr8w0dRq0wDQYJKoZIhvcNAQEFBQADgYEAcBag" +
        "81RFYMBAf8aRP5VXPcfu0OxgJvVE25ZHGLCkLD4TPKAXMjZMHWrf34+5FW7aigDO1YhGA+" +
        "2zVtVj8k71DichiCCGXQvH50AqFgeNXNQwn9WcpQ8rRkfmyhlccfeM+MzHI1giRw/RjvCN" +
        "0dfJL9g3c7peW+VCKn85REZ1ne4=";
    public static final String End_Certificate_PP_06_03_crt = 
        "MIICbjCCAdegAwIBAgIBbzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBNC1QUC4wNi4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDYuMDMwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKBSOacrUg5H5yuISkqmJuQcK2ao+Ib0FmIKCuek" +
        "8mm2HEiux+K5/yIAYsQnz9eDKzKWaS73exPniKOXABHaL6dxsptbdBqWB6II2kIl0BFz9P" +
        "82qjz6DMwpUhj5Pwfy5q0Bz8grTe31ZYP19y8AHgcWna+eiY4fNVXVkIEJOJ6tAgMBAAGj" +
        "OjA4MA4GA1UdDwEB/wQEAwIF4DARBgNVHQ4ECgQIaZQ3Q55so58wEwYDVR0jBAwwCoAIDj" +
        "pr8w0dRq0wDQYJKoZIhvcNAQEFBQADgYEAnNYKc2pSFZ9PtR4gQyVI3j+gQ97tcWu6Alxm" +
        "4T48fSb2KtFGuozJyCv0aYjtuZ9ava9r4v04lyFPoAjWYbALHC9F+vz7JLNr4VstuMdy5O" +
        "ax+PvJjKGACSXD7QjXJ48qvm+v8OnMbkzf8+rY3LoTJ2KhXo9Ey4+UmU/YuZ0PXuY=";
    public static final String[] TEST_45_DATA = new String[] {
        Intermediate_Certificate_1_PP_06_03_crt,
        Intermediate_Certificate_2_PP_06_03_crt,
        Intermediate_Certificate_3_PP_06_03_crt,
        Intermediate_Certificate_4_PP_06_03_crt,
        Intermediate_CRL_1_PP_06_03_crl,
        Intermediate_CRL_2_PP_06_03_crl,
        Intermediate_CRL_3_PP_06_03_crl,
        Intermediate_CRL_4_PP_06_03_crl,
        End_Certificate_PP_06_03_crt
    };

    /*  
     *  test46
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_06_04_crt = 
        "MIICozCCAgygAwIBAgIBcDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjA2LjA0MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDFoR/YTJlGYenu2IRsTiT6jwIA7yOnFbM9JXcqYIP5" +
        "jSgtn/wVztPHgVWP+582foXJ+oEcThQVZ+RBXYt6VU5o7eVCsGJjqMd0DbRzTO+poelVoY" +
        "1UEJMrKG0xSEex0T6XLQ+jPU9o5tlXoLYsXvpvbIrCJ0o8kuk4MWTzenDKJwIDAQABo3Ew" +
        "bzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATAMBgNVHSQEBTADgAEAMBEGA1UdDgQKBAgVwXynYDSYEDATBgNVHSMEDDAKgAir" +
        "muv5wudUjzANBgkqhkiG9w0BAQUFAAOBgQC6MnYM9cY3CNb7/KKZvoaSwF/Se5iZYnbdPn" +
        "WCnKydnN1AhlDN3kEw0gjTmZo/MkvPqku2aPzg5EiZ0eyeJaR6a4aiICU9z/Hiet19mBF6" +
        "BtAUdt0fJ7aL5WPAc4BKXUbONd6vkQNv8uLcBmsqZ4wXDj7ZVBMGKcuDq7uClb0xYw==";
    public static final String Intermediate_Certificate_2_PP_06_04_crt = 
        "MIIClTCCAf6gAwIBAgIBcTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wNi4wNDAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjA2LjA0MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDHqX/4IZpOCsHWgdJ6mICN94nXz/KqsXPNymadVdZA" +
        "nVU0fHdMcxehAvsBKju5d791Psly1Xyyda8KQ0BKPgGed6jNKb89JzuEtPBov0VMzskqwR" +
        "irjaDCwYKtibiDe+T/kEN9Sq5pbexHcaTbAIeQrAIoSUmGdQ/Up6PYplb0jwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQISKcQDqdBecUwEwYDVR0jBAwwCoAIFcF8p2A0mBAwDQYJKoZI" +
        "hvcNAQEFBQADgYEAkAQaOoZYAZOCk881Ro+SIclAj2lp+arAkWPP/gwN4/0lpH62eWqlmY" +
        "okWRBjk6+iwCgRxQ56uUjJhE08p5juZ5V32ie3RW+S1ZBPtL/T/+Tqp9HNQQ3GjW1yc/yI" +
        "sWQxrd7QKzTER37HBiOr5WjEjn+dzuWlJtClcQetqMLtMgM=";
    public static final String Intermediate_Certificate_3_PP_06_04_crt = 
        "MIIClTCCAf6gAwIBAgIBcjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wNi4wNDAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EzLVBQLjA2LjA0MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC2tnVj8KHGCm8XBPvDYWZMp3yOKQxuORze6a764qIC" +
        "hkdO7hQbgJ9YiuAF/y62W17FnbhKPX6ninaZG0N77bznKvivSC3+T1jIVhw+kpxRh9MRya" +
        "L2p+zHJEyO/9JaKWzJZiVi4kebW+hwNgSZc7FSYsAbW7lr4ujDei/yn/AJEwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIaAEiWf4JpfQwEwYDVR0jBAwwCoAISKcQDqdBecUwDQYJKoZI" +
        "hvcNAQEFBQADgYEAHNsZDCWtOqt741IJNA9OwpymTA4ES1BRJquEvGj5+4RH2pxi67bYd1" +
        "kWTPF1qFC2R1sugSNhbU0wOBMdKUJtKWNacPsK0HbD7CPqt4THOcMXFO36b/2gqHqy9rc/" +
        "slWuIwbtT/tEC+Mk67GEATWNPifoPT7TjWHM3RhsDnagZXw=";
    public static final String Intermediate_Certificate_4_PP_06_04_crt = 
        "MIIClTCCAf6gAwIBAgIBczANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMy1QUC4wNi4wNDAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0E0LVBQLjA2LjA0MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDgdk/smDJ5yZYJDH4SG7pIDCzGNZeLO9RI3ybOx4/B" +
        "M3YQu3DDFSOv8kq6PgL8ThC8Dk6t1jSbT8QVzaGgx0KMV3p6pIMdaVNkOjVjUb+L0nXVfr" +
        "XYpFLON6tZLgh8oIbiz4KznKmsxo6VdYwyUeHmkpGcL5y+8qLspCNdRJnDGwIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIgSY376EamQowEwYDVR0jBAwwCoAIaAEiWf4JpfQwDQYJKoZI" +
        "hvcNAQEFBQADgYEAEztvmGSVnDGGeNlIoR+wfRM8ndJogvUxLBZm4N96mDZ9Y+Nr99Dqvw" +
        "+mMI3BU0miA5kDO9aFrKIgow3cpruoedhnBUsxTfhrNaFEwp+ORUb3tWn7sSxLfnTim4Vq" +
        "y6j/EfUK2CS4ZAy7J5BADWSqDezPnrb5UaY1JFKMuLyGRac=";
    public static final String Intermediate_CRL_1_PP_06_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wNi4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIFcF8p2A0mBAwDQYJKoZIhvcNAQEFBQADgYEAPlIW" +
        "SxwW2LE8qxeD+M+HypNwai7j9XxUA2MhBbGVnsrhH+DKX5VeyP/nyZn2hBoGWhs05IpG2P" +
        "S0odnyhbgGSXSj+IOfkZkVT0BmuEJmqv75R15LBzeyONks+eSEhoOIGAaIN4WgJ5mzjSrI" +
        "ddDu3c4s6QO/OFVrNF1F6e4laSU=";
    public static final String Intermediate_CRL_2_PP_06_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wNi4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAISKcQDqdBecUwDQYJKoZIhvcNAQEFBQADgYEAE5wt" +
        "y3+jVnr8de/Yi0LV70v3JDHimwG2pQcuDRhR1NLPr4oC+2uxMqwxVzdHITDb3yI2ZT9pVh" +
        "PV3UvX85avMdA0/JyaMWSKNpbSah1eNfMwMBY2vzh1Q7f5n+7HYYM+I2kz7HARPvwsLP9d" +
        "j4mY7Kq7uiOFdnQzJ6LWjm8qEMs=";
    public static final String Intermediate_CRL_3_PP_06_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QUC4wNi4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIaAEiWf4JpfQwDQYJKoZIhvcNAQEFBQADgYEAOm2f" +
        "m3IdcDnIS915tEZzDmIbTFPBkIn0wjUreZKb9uNxE2a8Jixq+UP2uiyYWiWmXnRdVB1Gsb" +
        "ofc5f8ctNgSPVTSYB0U5apIauXjV0y7WMUrLNrDFa5m9lxLRhF9kvXVL8zPhVfMpujnXre" +
        "A8WS4UjDMuveyQL6yASGoZvB+Ps=";
    public static final String Intermediate_CRL_4_PP_06_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QUC4wNi4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIgSY376EamQowDQYJKoZIhvcNAQEFBQADgYEAznK9" +
        "ekskl4uWU+2Xqp3Pj14wvXuzfPAqFlHR0jl5By7T82JRiRa6LGX6T953vcwwJBsYG1hMqH" +
        "pgbnUGB8APQ6YNXN+7ZkudaG6fMVX6bCr8zT+nVSj7PHIK2VFsC1Jpm5SoQMHH6DFit/oH" +
        "tm4tdV8+nupMBQn1ZtxQHgUUF14=";
    public static final String End_Certificate_PP_06_04_crt = 
        "MIIChjCCAe+gAwIBAgIBdDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBNC1QUC4wNi4wNDAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDYuMDQwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOCVJmtrW8Z2WGGRNjEgyp2NJn1xaIVDwlxL4C0n" +
        "UAPpo1WM/rarQTYejT2Yo8H39TdRfiAlggF0Qsce0W//atey8WewGsFlUem6a4OFwg1X2h" +
        "CN/COL0eC4a6lwkdOKmqgxSyWNWeKxXRTM8+EYQIem78uY7A8XuzVUmOpzYWoLAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QION6UOZ2Eky4wEwYDVR0jBAwwCoAIgSY376EamQowDQYJKoZIhvcNAQEFBQADgYEAXota" +
        "1N1UrMxj2a/vdII92Wi8uEetcHo9vmiJVYxwPFkp+qo1q93Ww8Qnfp7xzaZwLgVoUOAF8U" +
        "TRUVnzqoSwmRrfyEMfrgej3eiBjcU+zS9mNlx9mUUSLmlY+xMeejyVDCntRn6YJWWLesVq" +
        "eFOjyNux97/XnGT3T1w0J+wShu4=";
    public static final String[] TEST_46_DATA = new String[] {
        Intermediate_Certificate_1_PP_06_04_crt,
        Intermediate_Certificate_2_PP_06_04_crt,
        Intermediate_Certificate_3_PP_06_04_crt,
        Intermediate_Certificate_4_PP_06_04_crt,
        Intermediate_CRL_1_PP_06_04_crl,
        Intermediate_CRL_2_PP_06_04_crl,
        Intermediate_CRL_3_PP_06_04_crl,
        Intermediate_CRL_4_PP_06_04_crl,
        End_Certificate_PP_06_04_crt
    };

    /*  
     *  test47
     *  
     */ 

    public static final String Intermediate_Certificate_1_PP_06_05_crt = 
        "MIICozCCAgygAwIBAgIBdTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjA2LjA1MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDMIUtQ/CgudxHAwAAn8jUsdAY8u7WDslOC4nNbWn5C" +
        "tILgZ2hGIZhEnhzP+VCV8ke8zLo1DX0hCRYAgzk5XTGAimExHFv/yDdhpJWEnqMRljkCHx" +
        "Hg3XE1439qutBdmWvGUlRF0hQrd9Q/Ubr+PjEzP3a0EUmXo7LYuQKMcFsC4wIDAQABo3Ew" +
        "bzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATAMBgNVHSQEBTADgAEHMBEGA1UdDgQKBAgha8GqGbO1nDATBgNVHSMEDDAKgAir" +
        "muv5wudUjzANBgkqhkiG9w0BAQUFAAOBgQAEG5C3P1A/MYpNJ0qvi26v04GGUWDQWRW1q9" +
        "1392XpAxDdv7kODf1FUMpfBpcUblagxrX7Npthv6/6W8poBTjvJuq5BfnnOMQrCwnsNfRy" +
        "Y7b1mAZIvcOBhWe+bFVqRLUqZ+JseWkw0YgZIGtX41Znwl0VcFQKJ4lNkuaBgXXdGw==";
    public static final String Intermediate_Certificate_2_PP_06_05_crt = 
        "MIICozCCAgygAwIBAgIBdjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wNi4wNTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EyLVBQLjA2LjA1MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQC36j0YkXZZSw3qQaxD0g2BfrKYperkGjVAfLwOtOxB" +
        "0A3Ufx2ECl/MqNOvi/QWlTkKwnrqw0aEnD25iS1DFM4jMZBmdfJg80oa+y6TJoZcIb+3bv" +
        "SK5o3ArCFWkhTHHggIIY3H9dQOgAeYQF57Vb0iu59GPfnYJO8y8ZpxGIYcjQIDAQABo3Ew" +
        "bzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATAMBgNVHSQEBTADgAECMBEGA1UdDgQKBAhUpoGZzfV7EjATBgNVHSMEDDAKgAgh" +
        "a8GqGbO1nDANBgkqhkiG9w0BAQUFAAOBgQAjrFHzC1FLvssJTfV5YsGfw7Luj4EqLDQd6b" +
        "MgtBSwPnXqMTUAZpDETyeYvcgM+L2tasB26MSy6IttSKsaJpHPCP+BIs0jji5xosuCX6Cs" +
        "wI2gE/LjF85rjZnldrlDShw01DlcmWlWwudit/ieO71Xc8i0F4EhSaTUJX12po5Xkg==";
    public static final String Intermediate_Certificate_3_PP_06_05_crt = 
        "MIICozCCAgygAwIBAgIBdzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMi1QUC4wNi4wNTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0EzLVBQLjA2LjA1MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDFWhChPQNFYQpLBmVmXSGF2py1wcfhZgZurv0E5AgE" +
        "BZwBo2bxSeC36lBQyR3OABGI4nQoEegSQWwuS2Pk3+emG2MZ8R5QINAkMlAKTp5Gj7KTlm" +
        "3VVJRx7/VduoFx8sZPjkpvF1bSL+KOH4UZny1xqqTj4bJ+oGu58INeSNVa+wIDAQABo3Ew" +
        "bzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATAMBgNVHSQEBTADgAEEMBEGA1UdDgQKBAjN4PvsHY9+YzATBgNVHSMEDDAKgAhU" +
        "poGZzfV7EjANBgkqhkiG9w0BAQUFAAOBgQA8KmWbAQOnM59zry9TNtLbA2P5y8R/sO771S" +
        "yQYcu6undt9t7UEiOepDp/z3CGsITm9RdtXAobZ5ZqhW+3Ll+UnML1itiCytOPbfC7iiUO" +
        "S5jviQnpgJncZD2Lp65yNAB7lMmMleFO15Bsk8VNmzMDMsFtzo508Bs6T33ZW69/vg==";
    public static final String Intermediate_Certificate_4_PP_06_05_crt = 
        "MIIClTCCAf6gAwIBAgIBeDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMy1QUC4wNi4wNTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0E0LVBQLjA2LjA1MIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDxx57R4j64xdbjpTl7reLby/T2ym4rESC90aBkC2/E" +
        "/YUSjsuGG9GiHEVgoGzoQGQNQV0v9ZMIvuoI6q7Fd6VZhIVGE0MGzTFNA9QEEDGPc10ZxC" +
        "Gyh9mZYp77PMuhQ12Iv3aDW9KNTr09+HyhK7d3Se7toXLwjE5pKt+A4ZvBFQIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIwmq0fugIX0kwEwYDVR0jBAwwCoAIzeD77B2PfmMwDQYJKoZI" +
        "hvcNAQEFBQADgYEAbAbRorTyh6zfAmdg0lfeZyCyW9k4NWfhUs46iSOl6lkZH8c1eoAF5/" +
        "q0pOF+CtI3F9VMhfUXChEbVj7QENctU7kDiFe8300OWD5h1VUi+WTK4CG7B36/BjkrVOuG" +
        "Os76P9l1WaC+/WRZdcqgFMfPjpn3R179dImBDwZiCMMbVqc=";
    public static final String Intermediate_CRL_1_PP_06_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wNi4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIIWvBqhmztZwwDQYJKoZIhvcNAQEFBQADgYEADX3u" +
        "wxpN+p8N2HqmhFw8w9LCeoR3Xa/uaqgqh4i/VkDuAC4Bi7VbIO6rcxDO2uAdZgNhb/hnRq" +
        "cvKLcy0vrovCa2EPHcFo7dJl7si2q09EeuHT4+lZt/Ek/VOkwHhvh2o6yEvKOGXCnF9hZr" +
        "8YbOIknboEz+tRfxoJArRBwpJkE=";
    public static final String Intermediate_CRL_2_PP_06_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QUC4wNi4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIVKaBmc31exIwDQYJKoZIhvcNAQEFBQADgYEAQz7u" +
        "dfU4yAHFLH5BgeZkYh0l2lZ95af+E/67MSCjQSF7RWWWTffbDMc4HmiRlZLvQdltyGCKmi" +
        "kuzcPP8vyYOBQmoIKQ6c2LItBjXVavLdpe91yCOhCWXVVlnMFq5ztrvBEpfO0GVUOnPWfG" +
        "1Ugit3SEd4DbhYFTBYHbbOKRWsU=";
    public static final String Intermediate_CRL_3_PP_06_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QUC4wNi4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIzeD77B2PfmMwDQYJKoZIhvcNAQEFBQADgYEAkiW6" +
        "h9a8v+IITd+p0jxukj2FYfmED59ZXAlYhQdQAGlPE71rOXn6ZPURYoGf7qlmBwQffpksOb" +
        "Byb+PX+CBTUNXzhgTzD7ifM9xOhCEKVKai9acQfvokU56OHwfq5AnkRykLZ7IdvdYCP57k" +
        "ynrNNV35dsMZXg23/PpreumlOkE=";
    public static final String Intermediate_CRL_4_PP_06_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QUC4wNi4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIwmq0fugIX0kwDQYJKoZIhvcNAQEFBQADgYEAnTbS" +
        "MBWyoPaslaLpAMmJ+D6kmmKAdRYurA0okU/QP+0W+YNPV4DducAQUDy8Cg3RkpRK2ze0ad" +
        "l6TUW8g83hj9TXSBp+XZuVvzerMCjOeBqhskZN4Ly8101ZZmMmdYdSc3PEhqkme6iZzjwB" +
        "ZooAN2dIYjuBj1c1/t5qH80CMAI=";
    public static final String End_Certificate_PP_06_05_crt = 
        "MIICbjCCAdegAwIBAgIBeTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBNC1QUC4wNi4wNTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDYuMDUwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALyVMklPv3uwTPzLG70sXIwKSEt65yiU71ibHyhH" +
        "wJ/6dXy3HK2UETkRBK7UVSOYq005EbO9s/3oR3zt7QTFifvRTsIjl1L4TCLC2a8ApBr3BH" +
        "xmBWcJDf427Pk1fm5qDdEmZnpyIlpKaKIiBcdtwZfjr0lROL8RNcvgtJPdu/ndAgMBAAGj" +
        "OjA4MA4GA1UdDwEB/wQEAwIF4DARBgNVHQ4ECgQISjAUfyAwSA0wEwYDVR0jBAwwCoAIwm" +
        "q0fugIX0kwDQYJKoZIhvcNAQEFBQADgYEAC6Af3cJUh/IQgWdbC2Vmk96sYjDlAsbA2keY" +
        "J0bgBcNaIVoJ/W0B3rSawqSU+Vv64p7kcuAl6cbvIXPB++19V23jj6HUs1JxtPJZ9IWkS/" +
        "FRakv6lD7+j1OdzJvDR8AMZWmPFHJdQnJwQ+I1YOU/O/ShawOnGCmihpIULUINFhk=";
    public static final String[] TEST_47_DATA = new String[] {
        Intermediate_Certificate_1_PP_06_05_crt,
        Intermediate_Certificate_2_PP_06_05_crt,
        Intermediate_Certificate_3_PP_06_05_crt,
        Intermediate_Certificate_4_PP_06_05_crt,
        Intermediate_CRL_1_PP_06_05_crl,
        Intermediate_CRL_2_PP_06_05_crl,
        Intermediate_CRL_3_PP_06_05_crl,
        Intermediate_CRL_4_PP_06_05_crl,
        End_Certificate_PP_06_05_crt
    };

    /*  
     *  test48
     *  
     */ 

    public static final String Intermediate_Certificate_PP_08_01_crt = 
        "MIIClTCCAf6gAwIBAgIBejANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjA4LjAxMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCp2vHVX08nyKe+S8NPkNJOZ9Xng22TbYXhUHtXw9yv" +
        "ZmPkRhwDrZfBLXZcdZFixidkky3kCzv8Q3aPyPByM2ozH+AHJzEMbwifhyvUbANcS+Jts3" +
        "lsZHarN7VyiXO+8J2OtYqX9qzmrAOHGleB2cJopEcmAMdrzgt1JIo98SUs4wIDAQABo2Mw" +
        "YTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSAEDzANMAsGCWCGSA" +
        "FlAwEwATARBgNVHQ4ECgQIoRYqHNcbLacwEwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZI" +
        "hvcNAQEFBQADgYEAXchRFC94Pl25d3Kl4wBcueQLyWPRuH9zS0ZPLAqKLcWVdcg3fYMuJ5" +
        "SypMMpxLaVjN7xq0KjML1gLiPQPk18iA2TOAUMblvjUl1uFzDdD6SqQidEZh2h3wxFtbLP" +
        "U7qBBki7i1+Xn072Bpn2paw/vlh4K+ut0tFQ2BAhqVnQGJ8=";
    public static final String Intermediate_CRL_PP_08_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wOC4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIoRYqHNcbLacwDQYJKoZIhvcNAQEFBQADgYEARyX9" +
        "2+LoXD2fIAACBMPDgds6m3Equ+Aawlr0kuppPO4ydCU4kiEgtVGK+kY5GzP6fUpAKjC8mh" +
        "BrozojhAbkJekDoN0BIJ42Iab70VmdWXRQhPsUDhQwEt+9eSgy+HfiFfpcL1VJx8uY4XMh" +
        "VB3hmapIe99P/T2QkZ+Pl8j0MgY=";
    public static final String End_Certificate_PP_08_01_crt = 
        "MIIChjCCAe+gAwIBAgIBezANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wOC4wMTAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDguMDEwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBANYtrtpgxNl+9jF3TN1B9bSEGQci+cQOKpFsmrtF" +
        "AyiGBxKONgGSgSFFuFIhyBKZF5ROaKX1P8lsQkrpnuybUi+Z9ADdyoaLUDD/z/kp5sebAZ" +
        "ujmF8HVlqHYj5Ls2smS9EdSN1zgPTXIOTeZd/lv1iFppRZv6cBqlaoapQJsb1JAgMBAAGj" +
        "UjBQMA4GA1UdDwEB/wQEAwIF4DAWBgNVHSAEDzANMAsGCWCGSAFlAwEwATARBgNVHQ4ECg" +
        "QIZjcOdw0ZTCYwEwYDVR0jBAwwCoAIoRYqHNcbLacwDQYJKoZIhvcNAQEFBQADgYEAarsn" +
        "13/g0vOKxy0okOp2JXEsPdsP7aWnCfR8N4+7gFD6dVnkgCIyc5Kbs7MbhB9gtIxYhHOV9W" +
        "MaW9QAcBH+eXciFDfQBfaMBkL34ssE/TsZ92r/bhBwKRcH54f96G0QWUnoNMt4U/1j2mKn" +
        "faFirltqEPUu9mv4FiQ0pNT9yH0=";
    public static final String[] TEST_48_DATA = new String[] {
        Intermediate_Certificate_PP_08_01_crt,
        Intermediate_CRL_PP_08_01_crl,
        End_Certificate_PP_08_01_crt
    };

    /*  
     *  test49
     *  
     */ 

    public static final String Intermediate_Certificate_PP_08_02_crt = 
        "MIICojCCAgugAwIBAgIBfDANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjA4LjAyMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQCmAgNA68ABUEppM9Oo3guiGvguvtrWQzsQIJfMBrE4" +
        "/Scwc4SPK4PiJD+kVwtXinXpVclBMQge10uZ48lSJTihfZscJw3RSHt70H4CpPQm44QS7P" +
        "7fQqpcZKZvMWmY6A8jju3Phbuq2WgJCIxxVw886GNIAXW8C4ZFmXCjwiGGHwIDAQABo3Aw" +
        "bjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAjBgNVHSAEHDAaMAsGCWCGSA" +
        "FlAwEwATALBglghkgBZQMBMAIwEQYDVR0OBAoECOhZ4RAlqGGcMBMGA1UdIwQMMAqACKua" +
        "6/nC51SPMA0GCSqGSIb3DQEBBQUAA4GBAGEVSOcNaUu50f6AgGBtz1MDdRiHe08W/nzCNn" +
        "0K1/UqrIXVJ7IYgbOLkL3cdHy4PdngCyEblzl5Cwp9chh2zL0PTUbV1uJIBW32ks1HuAVQ" +
        "FTZqx0iuopY5AqRCJVDJt4HB5PKObwnmLPNWicI4Juap13j/Tcnw1EP7E7n6OejC";
    public static final String Intermediate_CRL_PP_08_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wOC4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI6FnhECWoYZwwDQYJKoZIhvcNAQEFBQADgYEACLHw" +
        "iDARFoF4GauIHnoZlfj6nlOHAFfNSXq06Vvl713bsoAiOSV+2goZjRG62uxhampE+gCdXx" +
        "1nwhKQ5R5jOGGOxgLtBFNZwKmD0KiDOSvfIVJ0kYCcaB4mSm0a/7pcCPrrE5ofvkmTW6Wx" +
        "k/YIuBZdDoqZC91v4tnu0fSch9Q=";
    public static final String End_Certificate_PP_08_02_crt = 
        "MIICkzCCAfygAwIBAgIBfTANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wOC4wMjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDguMDIwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOJsz8ys71e8UB+VDTBAocVQvADiqh0LjdML3pET" +
        "B6VvikiHgbB1PJufxDses+v0WD74ChZEa/octNcMFqMgBlhVBEfvbyGTjiN97LzdZ7SPyd" +
        "DsDulqwBG9sACryUGHqwHYnUbjOqsThOXFB8Sg/CGGawpZAosm2AuH2gqNvNuJAgMBAAGj" +
        "XzBdMA4GA1UdDwEB/wQEAwIF4DAjBgNVHSAEHDAaMAsGCWCGSAFlAwEwATALBglghkgBZQ" +
        "MBMAIwEQYDVR0OBAoECOiMLE2l5u16MBMGA1UdIwQMMAqACOhZ4RAlqGGcMA0GCSqGSIb3" +
        "DQEBBQUAA4GBAFf4BCbNtduwn5InkfdtFbQOqhPLAn/5eIhxhVhUu7TekWT7ktdaVQFzGF" +
        "G2h1+gXgFP+YKjJy7kGzEVQjlWtuC0l74EwybNHnYAoDg4itKe+0OSNNXdyOmn+i0tE0nx" +
        "sWN19VvhLGFC8p38gd0oDr1ziYdg0z2Mx4IlMDxl7QhT";
    public static final String[] TEST_49_DATA = new String[] {
        Intermediate_Certificate_PP_08_02_crt,
        Intermediate_CRL_PP_08_02_crl,
        End_Certificate_PP_08_02_crt
    };

    /*  
     *  test50
     *  
     */ 

    public static final String Intermediate_Certificate_PP_08_03_crt = 
        "MIICkDCCAfmgAwIBAgIBfjANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDFRydXN0IEFuY2hvcjAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMF4xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvZDEQMA4GA1UECxMHVGVzdGluZzEVMBMGA1UEAxMMQ0ExLVBQLjA4LjAzMIGfMA0GCS" +
        "qGSIb3DQEBAQUAA4GNADCBiQKBgQDKZDgBum5Ud5i8HWlCKInJ1x9goZ7TQJ+LdfA9iGU1" +
        "47xJL5eFcERWy4dr5wM5GNRW/DHXlnA/qsRVE29EuRh6qAVgcPGAfmJxz7s5yhmErfmiQ3" +
        "0rh6+pma/EhcjntXqwIqnk1qt6mEk7x9UKO3ksFCVsDEA67/dvownjcZB59wIDAQABo14w" +
        "XDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjARBgNVHSAECjAIMAYGBFUdIA" +
        "AwEQYDVR0OBAoECGtTrZIwYYHbMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqGSIb3DQEB" +
        "BQUAA4GBAM3t13xJJraRiJDAwZFxhTNR570wMdSRiF3yWSRtOjEv8NTVFj/T1oJJ8h9Gqh" +
        "hMpTTHU7uGCyVB9S1HCelmS+1zteKr0B+WVzBl9yuhvku3farz6zgIVK3v5hQ6xC4H4Lac" +
        "NDhTTKBkRfDf9KskFoxJ/AGxPdZtIEC92DFSblQB";
    public static final String Intermediate_CRL_PP_08_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wOC4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIa1OtkjBhgdswDQYJKoZIhvcNAQEFBQADgYEAcUHo" +
        "D00X/pd3D5KGa5C6dY18RsnUovkjUkegGTpbhQfmYZIdBatj7Kv75FeUJ9UpqCUjxHgdiE" +
        "EVy60NLVGP2VRuJ1m8vfDz8hu5PaiVjneQoRw2M9ieBnz3PjSETDdBGJLWHyCBZbp/W2+0" +
        "iqcZK7Fm9O5EL4PUO6QIwuH76q0=";
    public static final String End_Certificate_PP_08_03_crt = 
        "MIICgTCCAeqgAwIBAgIBfzANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1" +
        "UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3Rpbmcx" +
        "FTATBgNVBAMTDENBMS1QUC4wOC4wMzAeFw05ODAxMDExMjAxMDBaFw00ODAxMDExMjAxMD" +
        "BaMGAxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsT" +
        "A0RvRDEQMA4GA1UECxMHVGVzdGluZzEXMBUGA1UEAxMOVXNlcjEtUFAuMDguMDMwgZ8wDQ" +
        "YJKoZIhvcNAQEBBQADgY0AMIGJAoGBALsXEPrCg91CObTl5OrHIB5GshIDXgqBmjzxfWPK" +
        "ih4STWeBe2eIFO9pONXcM5lstEu2XLBPP6QBMUMWOrphJejrJ3eDQHs404bBnt95O/x17i" +
        "665CZtg1jUqoO1kOBOComx2AJGZ46RdBExbfd0tTtdHWtRhMsnQchI+WtEyotdAgMBAAGj" +
        "TTBLMA4GA1UdDwEB/wQEAwIF4DARBgNVHSAECjAIMAYGBFUdIAAwEQYDVR0OBAoECEWZkJ" +
        "TYQ3z5MBMGA1UdIwQMMAqACGtTrZIwYYHbMA0GCSqGSIb3DQEBBQUAA4GBAHki/TrpHiKW" +
        "gvERhguQ/uOqHHZNXsog+fgGVFFMOWwJ9bq4aHKd1fDZpyZF4vBxW7llbhuSt+ob2TNlkR" +
        "wkqzfGL+3xOTKNRgzDwJcil8akC1N5uBftrQk+eL7rM1PezWRM7fIbpmv5ZieIVswtTPF5" +
        "1Rl3G+JXUBy9E95espls";
    public static final String[] TEST_50_DATA = new String[] {
        Intermediate_Certificate_PP_08_03_crt,
        Intermediate_CRL_PP_08_03_crl,
        End_Certificate_PP_08_03_crt
    };

    /*  
     *  test51
     *  
     */ 

    public static final String Intermediate_Certificate_PP_08_04_crt = 
        "MIICljCCAf+gAwIBAgICAIAwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QUC4wOC4wNDCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsrM3A06j1zDz6VuZh+O2UrAPcKtwSA6KxTShUpgr" +
        "t9UB5iIAEvxcDTwDlubEv/cJjDcFj9N57otzW4ppnuT2ztE4ROmkNb0xL6u00deS1yGjXB" +
        "wy1G9g8bYDdAXOJlv0tjHOBqXlyKoMny82BOBL2vsCstiqxl14Q3/wBD1w29MCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAMwEQYDVR0OBAoECJiAkexK6/c7MBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAL4xwcpXZQPTTPYIQ8CMoVla/5P1x6BPmPqSkvh1D/o4ds9Ll9kHBz" +
        "//X1ZM8SzYcEO+1r75JUzoHsvDw9yYAk2oclLsCORAPqD8Owhv3jv0QQtYSmf0Sxt5FLx0" +
        "MRP9keY/DURRf9KitO4glOawtRtYMq2BeeJk1xusY0KqEnQr";
    public static final String Intermediate_CRL_PP_08_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wOC4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAImICR7Err9zswDQYJKoZIhvcNAQEFBQADgYEAcN3a" +
        "jIEcXsQatb0fvVcFnO7d7lzNtgbqL3MtaqJ/PjkRJ/rO7JAXQRwdajUZF4ECHylZKE2HUG" +
        "Dk+vidV98T8mNmb0TEuuLV+J1G0q8ezMXRJtDt/2m3y1VBireXlEMd1DdgpsDdCQ4va+XJ" +
        "qv0TvVhfxWry+LrVb6Bf5ItexXg=";
    public static final String End_Certificate_PP_08_04_crt = 
        "MIIChzCCAfCgAwIBAgICAIEwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUFAuMDguMDQwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVBQLjA4LjA0MIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPJWa/cB7WW7tkGxFhcwxqE+BycXe3Ru2qGbun" +
        "NPQZ/j44UT2C6rl1wZwugCY0sR6mXR/P/NR7czZvg4Tt6lwcNtc8PeafFMUeu0u0Kg9uWn" +
        "fzQQKeIgRVcEzGTGMPGWXS0ed6X/1+Dj8A+T/tqXKUtM3Jpe0pCmm9CIrYCXLPRQIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAQwEQYDVR0OBA" +
        "oECKm9IOyOM1h+MBMGA1UdIwQMMAqACJiAkexK6/c7MA0GCSqGSIb3DQEBBQUAA4GBAEXy" +
        "dlTkkZaYK6sUJCiPeCPxfj5cdo/G4RGBImMJbTeDyVTvXSH9G2yWUMqBGnYLrwdJJeXjF3" +
        "89miJgnJ+1r/r3r2/NeAUuJDsOHRMFh0KXFmgubyw/kGsZBe3279hDnND8ZjfQBmKQD17f" +
        "PycWTTAC5p6GM8tGERiDSnMc5rmm";
    public static final String[] TEST_51_DATA = new String[] {
        Intermediate_Certificate_PP_08_04_crt,
        Intermediate_CRL_PP_08_04_crl,
        End_Certificate_PP_08_04_crt
    };

    /*  
     *  test52
     *  
     */ 

    public static final String Intermediate_Certificate_PP_08_05_crt = 
        "MIICljCCAf+gAwIBAgICAIIwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QUC4wOC4wNTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwH2d+D0pH8y4QJAPpE0s2oWucV1jlE4pBMGNNPJ5" +
        "FIRmyRCt90IpzmK/EuqT6iSZYd9hIB9wa180ByN67PK1z4loLFMUL2RmbWeAFlGy5eEFOy" +
        "4d479qfy6JCOzt0TKhYzhukLUqGLa4DDTzvnnUx0o86aLvGq0K5s6DRlNyc08CAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAMwEQYDVR0OBAoECDSeuxr4EVgaMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAKoGi6qlODB8Lc86PtGXfBhW769jB8xzgmENE59sqNBEvYa/oK9Xxm" +
        "1JX1OGEQMq/mqwZXg6hSczpexCIO4tUH8QKTU68yvqcZoZCDV8FLM8aEUPtUoPIpluhAtN" +
        "scGfb3uXoV9fg7q1Pi5YlKMnNrDIq1tH1CAGKMDRrjW63Q8C";
    public static final String Intermediate_CRL_PP_08_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wOC4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAINJ67GvgRWBowDQYJKoZIhvcNAQEFBQADgYEAv5Hs" +
        "nYPZO1fGC/Z2lIbbUKjIv0+BrR9HbG+b76wXeJTVxfXMlZe0cpOR/KD29DyxI3G4IedHRy" +
        "zL8iCDWYbA86arJzl5GZJ1MC2A586vNn/6wiiT6nP3iMj2z/nyvan8L30KNBm9IDXQExOu" +
        "PNE/wOWYBxxCjg551fpXfJKqDIo=";
    public static final String End_Certificate_PP_08_05_crt = 
        "MIIChzCCAfCgAwIBAgICAIMwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUFAuMDguMDUwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVBQLjA4LjA1MIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4BZFTwOqI+71v8CdiYbe7x0qYveN524h6+iLh" +
        "oEqvzuVKVqvQgVSaSLPcMhoCGDv3nqyP57Znl/3I09vLU6F4HKLtjO9E0PZu8EXOKLjeWP" +
        "XmJQkdHfODj/TrrWSsrdorl7s7gdWEUFlbiWvUVUtkqLNbGLJZ5Q1xZvBRLS7loQIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAMwEQYDVR0OBA" +
        "oECBDaTXbN11BBMBMGA1UdIwQMMAqACDSeuxr4EVgaMA0GCSqGSIb3DQEBBQUAA4GBAGVa" +
        "QNtd4LgoVZQ+Uy1lSr6sog4fsGaoQJCZcvrMJwGpMF0FJsGtOb0R2mfwHi1YXqPF5qZY2I" +
        "7cVbwVtRQzbXunk1z12k0iIesMtYUncxb/SBstC7VNS8HNZm9ese+YM6Ac8mGT+IUZsPcP" +
        "gI9fQ1L/2u+/3L4fweca1R45xm5M";
    public static final String[] TEST_52_DATA = new String[] {
        Intermediate_Certificate_PP_08_05_crt,
        Intermediate_CRL_PP_08_05_crl,
        End_Certificate_PP_08_05_crt
    };

    /*  
     *  test53
     *  
     */ 

    public static final String Intermediate_Certificate_PP_08_06_crt = 
        "MIICsDCCAhmgAwIBAgICAIQwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QUC4wOC4wNjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAlSIH/+6DEL1P9tkgbsI2PcW0w9dmqMTLP3jKYPsr" +
        "sSWI5bcv55sk6RItVr3hGgkaskZoHeamUBAiGPksVyrqmRwSCJzQDLnLdMnjjudvPjp1ZZ" +
        "9UCufTtMPFvnEuVBx5e8A13AQ4OyHqaJgWRVoRJd6vwTa5jzfYCCMJZHHKpcUCAwEAAaN9" +
        "MHswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwMAYDVR0gBCkwJzALBglghk" +
        "gBZQMBMAEwCwYJYIZIAWUDATACMAsGCWCGSAFlAwEwAzARBgNVHQ4ECgQI8837JGF7vMAw" +
        "EwYDVR0jBAwwCoAIq5rr+cLnVI8wDQYJKoZIhvcNAQEFBQADgYEAKmgbxzWI6V2twYDp65" +
        "Gu8zn883CnI08s2FEVupvrKduxYmg+ZDkTBE3ZJFxcOuxJf58MRfDWy8C4jJhLnT3JSSSg" +
        "sY3n93jzc0s2h5y2wd1bUTDLqhqWCshisDG/88rpv938O8luiUEwltolzKTa+ScA6nXSQt" +
        "LT4I6O3vbTx2g=";
    public static final String Intermediate_CRL_PP_08_06_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QUC4wOC4wNhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI8837JGF7vMAwDQYJKoZIhvcNAQEFBQADgYEAHua+" +
        "lC3wP4G6796jjr6wuu7xEQqY1azsLVsGtL7YL8fm42rl7hgU40SuFIc7Kc+A7oEEkKgvmu" +
        "SLMIv7q5O8J26fQOuduGWQAncPYB8w7sNWjCZbdjVbjp1XIApcAL3djCbLZ8/NYsCoOuwx" +
        "hRQKX1hIn+rNDi1DMD4H99QdDGE=";
    public static final String End_Certificate_PP_08_06_crt = 
        "MIICoTCCAgqgAwIBAgICAIUwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUFAuMDguMDYwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVBQLjA4LjA2MIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDnaYU/lu+u+LmLQwyACSsRyxQEEvgriE7ApmHj" +
        "sNBcd3lovFQMfw9MyOOMsInOgQZU8p/invnhx11/pwi77ViQQ780unhHt5H/tteaYwcsDR" +
        "cUxR/8jK0DBnbVWvm8S/NGb8BxfbRmDHBTWGZ70hDSCJypWRfHQj0I/SAqAW/VuwIDAQAB" +
        "o2wwajAOBgNVHQ8BAf8EBAMCBeAwMAYDVR0gBCkwJzALBglghkgBZQMBMAEwCwYJYIZIAW" +
        "UDATACMAsGCWCGSAFlAwEwAzARBgNVHQ4ECgQIhh/KikcKA7EwEwYDVR0jBAwwCoAI8837" +
        "JGF7vMAwDQYJKoZIhvcNAQEFBQADgYEAbHK3lkqbGy61lu9d22uO2H3hzwvjmlccZo8pro" +
        "ord45d2nRIxw2ag4dS1YRFrefVdxZtKeR9+5o+tQtvmTcDOer4u6NZ/sVVElTb1d6axtL0" +
        "i4cmqv6bGWYECEwtwmPGqAavp9pPZjNRbkBGy9qhVNTXfDQYpA8yzXWO/xUrwNU=";
    public static final String[] TEST_53_DATA = new String[] {
        Intermediate_Certificate_PP_08_06_crt,
        Intermediate_CRL_PP_08_06_crl,
        End_Certificate_PP_08_06_crt
    };

    /*  
     *  test54
     *  
     */ 

    public static final String Intermediate_Certificate_1_PL_01_01_crt = 
        "MIICmTCCAgKgAwIBAgICAIYwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAxDV2d7qXbpCvOzBimskBLsgexpEYaHv0s7gOaqhC" +
        "4A3K8sxdjyW6QdGZhKX8tCMqnlPp9CNbpY4tQQ5oTSk5pj6HwAsTfGcDwXJnjKWx1FJ7rD" +
        "meZZ8c2K7a8voBl6FoPGn8CMhO0WmM9Eyb/vDUPdCZzScb+z/BxTcV1BPFdq0CAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECBpj0+Gcq32oMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAB/9veHrkLeu8jkwXggJtwqPTmkrIBcX+pz85BTSETYeLOzF46" +
        "onk+qt+IHptlrm3D7ny2Y5M0dQQ6tPzhGZxCEg9RoDibZGtsx+qeAh1ZjeEpEcQyp/idWY" +
        "asH+EIuEIOZA9c1ySxI/3v3ZfzaSGS8jsgSDkLB4JumrE9ZkLNd1";
    public static final String Intermediate_Certificate_2_PL_01_01_crt = 
        "MIICljCCAf+gAwIBAgICAIcwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1QTC4wMS4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3B3UKG3tEL6FQz6dL6iqSvzgGsm1Fg5uzK8npkEq" +
        "g2caUM7huYFfXeur1mu6iKiROcGX8ZYxrPi9Orh39YVrSu2EUWvqQui4QScf4dIlzAOunv" +
        "0gAa/lIVTHgZhIomKND6/tZLU251dJiFhoV6bXx2tor83vWFVPx2oVd5LL5S0CAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECJmK3jFTIl6lMBMGA1UdIwQMMAqACBpj0+Gcq32oMA0GCSqG" +
        "SIb3DQEBBQUAA4GBADkYLTg4RncTpAFmpUy7WGOMvoFV15nDoi91OMxhxVkbGSE0DJFxi3" +
        "hPKcfUNvzy0bEUUTaqOXdbIkoLTG77NTckJxurSRyam0jA0+6SUYZ6F9fVotwMul2EiVl9" +
        "XP5oCt7LkgqVgMASuwfzMnQozB6Oi/YP2OdSPXLipI6rl2dx";
    public static final String Intermediate_CRL_1_PL_01_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIGmPT4ZyrfagwDQYJKoZIhvcNAQEFBQADgYEAd8YZ" +
        "8jibr8yjcGYSDicJuyUvHBZntTVQ1sP5XVmtCZcYcQCVjbC0auYTEP5snXbGPW5qeEaaXB" +
        "MhekMr776hP4Kl3g4AjguFl3XQGcURlgNd8LsTpMMdNWC7XwooOF2FzFjD1ru0BSEWabzW" +
        "NNaVeuMMbu2N0lc6NDJvRC8LkhA=";
    public static final String Intermediate_CRL_2_PL_01_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QTC4wMS4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAImYreMVMiXqUwDQYJKoZIhvcNAQEFBQADgYEAZFec" +
        "GtjOfp8pT0n1dMF/x9n8y5tM+G3LLnZvDJspLc/sqP3E3B/sHBiis81caEkQQAOTBU5goJ" +
        "0KOFAUOfEq+IX5uvNhuPuinx0OsSak+2Annvi12zodMQKPNm1uMVt2bMHHHZVEVTqcv36g" +
        "xgdbp0YKTmuvSy6s8NtGFpkNmnU=";
    public static final String End_Certificate_PL_01_01_crt = 
        "MIIChzCCAfCgAwIBAgICAIgwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUEwuMDEuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVBMLjAxLjAxMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCAUPp5j4V5XTA44Ra1EWkp9HgS4w3uXJ7/Vhi" +
        "K5bARFrDOOxjV8nmr5hoUYr4jwdi2Rl+60TQK/F08gdcGxdyc9p/yiU5HyAP6i+4iqmvaW" +
        "9b2egNyZ5tOmpl/Q9FSFWa9d/PYBKM5Sj/r73RtA+/chc4uq3uyLekSRQGh1MieQIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECAiL3A4CkaFyMBMGA1UdIwQMMAqACJmK3jFTIl6lMA0GCSqGSIb3DQEBBQUAA4GBAJtH" +
        "mNNvCt/0uFbHdvUvCuBeZ9cggfpTyUS4X8zgcLDPFbw6VvX65umOZpceZI6hwcre+LZahi" +
        "gUEPvXppncEObkeVTcYdOTSDoxh5tZyee1P4sbD9H+suGWeewqUDvFs2ymHtxlkpOttitR" +
        "xQc2U6VlCuZ4XU8SwucyhW0z51e4";
    public static final String[] TEST_54_DATA = new String[] {
        Intermediate_Certificate_1_PL_01_01_crt,
        Intermediate_Certificate_2_PL_01_01_crt,
        Intermediate_CRL_1_PL_01_01_crl,
        Intermediate_CRL_2_PL_01_01_crl,
        End_Certificate_PL_01_01_crt
    };

    /*  
     *  test55
     *  
     */ 

    public static final String Intermediate_Certificate_1_PL_01_02_crt = 
        "MIICmTCCAgKgAwIBAgICAIkwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4wMjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4QmGXEeVKCn1aQx27r+EBuQqfi8fP7gyV5JLkaSu" +
        "DOUrqXg8dQxHsBNCf3XilGIvjNFZjVUPdS8FNqC+if9D164VyGQlv/JUor/GlvwVfyotUO" +
        "U1PqSzFrAALYTmfm/ZqhMvGYloStSDxlzjDmyKadskzOxZZDNSe5s8dvUpYn0CAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECGk7qDbbBgRbMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAD+eI+jg4jmeC3pJRGEF/hbPPYvL6aocjqqbZyNKN5FWItccQo" +
        "PWg/GK1GpusDZadesZBDo6fLIUJzL+OumrIYJLB3HxQsmyOXB1gRg1hcva71RWFJYzx01U" +
        "eB8lCbk8Zu24HzLzqjfVuwKOFFELWDEq7bd6Re/aKSHtNnDbsgSE";
    public static final String Intermediate_Certificate_2_PL_01_02_crt = 
        "MIICljCCAf+gAwIBAgICAIowDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMDIwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1QTC4wMS4wMjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAl/HiHoos7eHaDIFhMmvIPk63UT33Z+0iiCIuKLW7" +
        "tgkT8ia1Yg++np1pC3oqYVeKkXqMcjgonPGQhcek12vLt3/+2PYyYirOTVZaiO9pKQ5An8" +
        "ZMWXIJmCEAMHabPO1RnetvRv5JZFxZY9jIUnD2fUADzzUh/eHN6Pur0DDrI6sCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECPk0C10KQLZuMBMGA1UdIwQMMAqACGk7qDbbBgRbMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAMJ4+BZQxpxWhNbo8bpGkbbcKT3kfKYrHjHsZADC+/gAJSVL854b1W" +
        "VKsGr1YcCX10V1Gcqb6Jgziy+AzRLhcJngszcz0A7LxrMH+FIyWEPgZnOyQCa8B/9bnsh9" +
        "bC1gEmXGOVtWboIFOEdGghEbm/ENnQyj+HbIk3jhF3QYbXhw";
    public static final String Intermediate_CRL_1_PL_01_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIaTuoNtsGBFswDQYJKoZIhvcNAQEFBQADgYEAZEt+" +
        "FjRuXgnOZg70geqS4hVsF1VWWawlAVGmjPsbRH7rADXPUE2bYL54wLdwt/6QYwHqy2KwCf" +
        "d4OkWkwn9xwGS4j+XBCw9Y4nbWI+wrsZ9W7vgbeIaVUUUZu6hoin1GxrGDcfbM+bhYzQAA" +
        "gNmKIWdlJ4tKD2KNgg0KmZPoj/k=";
    public static final String Intermediate_CRL_2_PL_01_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QTC4wMS4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI+TQLXQpAtm4wDQYJKoZIhvcNAQEFBQADgYEAXwZO" +
        "wr9mrO6yUOoopNjcIcDssCUksYco1PFgWx9O/hGq9ktdoGoGcECGhdkHTLe2ab3WFl9jzW" +
        "1/lkysD9Jl3VjbnbRB3dPQlrSfiv7cYBLnfKvyF/CxQg/wCtWo46GJJQgOx/WHzi9aF08m" +
        "tQuJEtl7RgoByUSvLtmvKjQWEnc=";
    public static final String End_Certificate_PL_01_02_crt = 
        "MIICljCCAf+gAwIBAgICAIswDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUEwuMDEuMDIwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMy1QTC4wMS4wMjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA0/rXOZwUebRaHcPPFeKTB2OWIzIAgavqb5HerPAe" +
        "c3sJCdNOSLc0OX0dFblso97WR8uueF9I7QeGg3ayQjzDVqm5Tu77ZaCuyb6UU8+fY2eqwD" +
        "5lCVuLfJr9U2JD5b2TcdvAD9RqfhefclVjDj9rObLjvzLg3AefO3drsfBtAIMCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAeYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECDBWCFTOp3evMBMGA1UdIwQMMAqACPk0C10KQLZuMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAI/JpU3gHo8Izsbjlx6bkQo/e/hD634N5lSMtVHIGnoVLu99dvroRu" +
        "2DO8Fhnv6VZpMvYoAc5oEgUqx9hw3bfS/XN9GXaeMssjwN/qM6lzCsvMG7DA9sf59xjf4Y" +
        "2+u4KTye4PdpmWaseDDJ1wAihTHEaofnQdaoUffxQgw5UcAf";
    public static final String[] TEST_55_DATA = new String[] {
        Intermediate_Certificate_1_PL_01_02_crt,
        Intermediate_Certificate_2_PL_01_02_crt,
        Intermediate_CRL_1_PL_01_02_crl,
        Intermediate_CRL_2_PL_01_02_crl,
        End_Certificate_PL_01_02_crt
    };

    /*  
     *  test56
     *  
     */ 

    public static final String Intermediate_Certificate_PL_01_03_crt = 
        "MIICmTCCAgKgAwIBAgICAIwwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4wMzCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA60y6V2WkNCB34dcGfu+Jo3YHQZXzgp76+HgnyFmP" +
        "DLj9DjZHqifD3gW8Zk7L+yK4PfLDSHjbrXM9GY1ser6XwhaJQDPUBBYW5X3XTOmDWmV63J" +
        "YeRF5r7cfF2h3eEZ460GRLK5tt0Zr8V+hA9oOvwqynrIhDYC/tCzE28ciqA+sCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECPE2FCetVerZMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBABUOUWwyfyrRIw7dRIVfLlWyp5R1I+Kmq5e8st0AEMVpPAmLoy" +
        "0s+46Xf+THXZy5em1P3bSVTSUhTs+XD6tbFFUcTrX0mQJlshR7yD/A0siMDUNzzt9LJQvP" +
        "dwNjQSA2keOrV9q/2CAGce4daL4Wz54jfh33YVqJ8sHT4E8CxQb7";
    public static final String Intermediate_CRL_PL_01_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI8TYUJ61V6tkwDQYJKoZIhvcNAQEFBQADgYEA6FnB" +
        "LXWt4B/3oP0PXERYh7ZV39yu/tm9DHBQGcGDF8JIspU7F+mH/+37U/lT6BQxpKOpgOgGeP" +
        "nTQeQzN9sRsXxFO22SkHbdPCao84qvv485epgzqFcVsCRBwBBLcnNLMg891q0EYsTW9vSw" +
        "Dx7V4CawyYAYGz1MqYuY6SSs6Q0=";
    public static final String End_Certificate_PL_01_03_crt = 
        "MIIChzCCAfCgAwIBAgICAI0wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMDMwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVBMLjAxLjAzMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwt6B9gpDz/x/vnowXf1MdkAPeaCWZ3pYikgxE" +
        "ZLrMuulFaI1UDnAzgSuSvoHE80VKGKjSkrzIX9OFfeilW5rNZAXoZrjtkaJd1Q8l5AtjFn" +
        "0tlLytDzIMYo5Tiq/n3IiTdbEzGYzEOCcSyVaQdB7K1WgYI/z/UAaWV/GbqCX1zQIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECMQHLiufEm0IMBMGA1UdIwQMMAqACPE2FCetVerZMA0GCSqGSIb3DQEBBQUAA4GBAD5/" +
        "vGn/rpoHvny/mfh6n2zVNNQLTEBiddfAdCWpeBFcwxS5lpxfm4dAWgHhprZTMirF9yS+wO" +
        "wWQ4G9/wiqfAtoaNN1qkHMlUMOAPsOSff6ClgP+1uzKVqQa9NTd5HAeMdYfYjMa/fcF/37" +
        "plCs5ZsJjb9lhEjNd/tq4/aALQmt";
    public static final String[] TEST_56_DATA = new String[] {
        Intermediate_Certificate_PL_01_03_crt,
        Intermediate_CRL_PL_01_03_crl,
        End_Certificate_PL_01_03_crt
    };

    /*  
     *  test57
     *  
     */ 

    public static final String Intermediate_Certificate_PL_01_04_crt = 
        "MIICmTCCAgKgAwIBAgICAI4wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4wNDCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA06yd2NQEAgpv0kQQEOzhHHU4YqHgtvJgkdLYxb2W" +
        "Zordrm4b/43UDnLmsI0790V76y9Aa+Y8SIMBBRBJgnlppFJrFsPaOMO98M3/mXkQotVbY1" +
        "59P/AjWMxpzP9h8Bs8KuoPqnl5jN0UZAF4kRoNXHzyS445VBp4DtWz/jcCPm8CAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECHxLORDZ1KKNMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBACHmDOaoC0Hr2cmfuQvdyGDF7/RlvTUJ7cvGypCa724SwAZGZk" +
        "Tf5GwxgjVcLHY5RlX2kDm9vjneDzP88U3587qA2ZRwxhheK0RGp1kudNQ5y2gAGKZ7YSc0" +
        "SENMDxUAa6HUkn9Rfo4rf5ULuGNJZXQZ3DtP+lZSwzkUeCVjKhyQ";
    public static final String Intermediate_CRL_PL_01_04_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4wNBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIfEs5ENnUoo0wDQYJKoZIhvcNAQEFBQADgYEAb8lX" +
        "19SlVNRkc9SKNpRLZQom67djZfMSIPIDkBALfMepdevbquzgO7AufTuiDn5Zqe6J6odTv6" +
        "RrQReo64XB4+Lx2pXOe8bZEbzZk0HvzLl9DjN7zxyNglNK+Hd2xS4yT4ps4fBdvXvWAXEx" +
        "6DfvWHbGFDoH2auomCKJtCVXxCI=";
    public static final String End_Certificate_PL_01_04_crt = 
        "MIICljCCAf+gAwIBAgICAI8wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMDQwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1QTC4wMS4wNDCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA14bXc39XiWvb4r1jzbADzrpfbg2Y9sGBkefSQHsM" +
        "QZ1SRLR7uexWD7MuDYh4ZYBL+WPhaJJr3a1jnAIp54h68m8mwS13DgrxBF2/hrVKEm9IRG" +
        "s13hoM4Mjjogn/Lvc1xLvB5lctHjZrNRZjyrt+PqDDmqZqgCOmcD61PhrfAoECAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAeYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECB9hXgJfzBvTMBMGA1UdIwQMMAqACHxLORDZ1KKNMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAB0HgiURRd/REVfc5DenIPhMu8riVcwVgTUwatsCWragUhXpCtvJmf" +
        "z4vGo1rKYai2dltVX6am+NDvN5tROcM0bvC8lOCc/iPfI5eWTy9SJ2nxvs1+q809Rj0rno" +
        "zS77TIE8rD7Q8ZUd3qNUiBwdjBoc9misgyN7zUulg4Ueebvv";
    public static final String[] TEST_57_DATA = new String[] {
        Intermediate_Certificate_PL_01_04_crt,
        Intermediate_CRL_PL_01_04_crl,
        End_Certificate_PL_01_04_crt
    };

    /*  
     *  test58
     *  
     */ 

    public static final String Intermediate_Certificate_1_PL_01_05_crt = 
        "MIICmTCCAgKgAwIBAgICAJAwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4wNTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA/rVBEGZ4jibDhREeRGV3jPnv05esRL8/En1Bu35y" +
        "QrAHi32+kBu42vwwDbeuiTZd/B90bn5srJZoW83rxXxNnpxqbnjN3GgIcRiUVyaVRTp9/U" +
        "IT8B9h09b9yT8gpQ5qR0+JDcOHCfJwpogAsyJJa6AM5p/q3TeF39ugfVOWt/cCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBBjAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECJ7/mkuLuEIGMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBADC0A2KMMSSmGI9p85WG7XZVMBX/xdDYOHO0e3ORTRFS3kj9rK" +
        "a0yUjc1X+p22AA8kUyOLpYIulfDjPrLKN2E/hWSf3+XWMiC7JfX01F+BBl/avEZoymaZB4" +
        "dkH1Hym4IMJoSaEOgf5HFKBnFEA6aUcr+oDYGUP+Sc1dmJMjBW72";
    public static final String Intermediate_Certificate_2_PL_01_05_crt = 
        "MIICmTCCAgKgAwIBAgICAJEwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMDUwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1QTC4wMS4wNTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEArir4GaS6r0Tv9PMbaOXYdPKADNpVbJe79G5t/F6x" +
        "7Tz1rwUR+m10E+Jq9RsV+fU/nUzzjJXHbPLZnfodUVVmrXgzvQ8+B2N4jJtdNLG66j2PZG" +
        "+P8GQzVK9drDh54VHXdvxAYCXs7GaIprWmCQsxZOKjhFU3YDiRRK8qJGpBG/cCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECMmrFr30fUzZMBMGA1UdIwQMMAqACJ7/mkuLuEIGMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAI4qJF6STCi+elUbpZIP7YmcaQsS0PE4G3+LJoMg1LT3rSeobK" +
        "Aj/yUetmA7y0B5i0svKjRChLOpfClNPVPCx/+mc75+LG+dh1eVG/qk2UH/lrqLN0XLl8tA" +
        "IwZeoPaegBQAIp9oEjhDN1fWtKIkOe6A6wYdH2VPvsqC8g02VcwD";
    public static final String Intermediate_Certificate_3_PL_01_05_crt = 
        "MIICmTCCAgKgAwIBAgICAJIwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUEwuMDEuMDUwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMy1QTC4wMS4wNTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtRC2/PDG3kx8LpzfWC0yJph5h3LXZJZW0W2voss1" +
        "HYPP1/MBoQY067dfbALilVRh9asCNL4F45uu0lT24qS9vjW8SzBOLA18GsVYRmWO7EP+Cd" +
        "9f3mgPIMJ5n+UjW+yhBwh0Z2pzVElkX9CxECrs1Mt2ulyuwWA1lR8nRMaTUeMCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECAlV3mzXYPyuMBMGA1UdIwQMMAqACMmrFr30fUzZMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAG28iHdlA+nTs/b9pi+m9eMy7niELjIWL9fMgn1r4iXQ0TsPYi" +
        "tgpoip+BB4G/jz7MPx/N4nwyAPV+C9wN8cAHALf/ka2MxAORYFVFI+5PDgXzm78ILqj91f" +
        "vOFN4jemizTES4/dHxfmdctnsTRpU9ALQgfJLhxEQISOPwuemKB0";
    public static final String Intermediate_CRL_1_PL_01_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAInv+aS4u4QgYwDQYJKoZIhvcNAQEFBQADgYEA5i45" +
        "gETFAw6l9Awex9IAVIqYTA1dnbDyrUYDRdzd0x6OxSPODvNfQCwqwlTJXrHidCPO8jRhMS" +
        "Zcdn/MTlIeHa6OERFcjOiwOpeTgtchvpTdDchs5ve8Ik+myue+cfgpEVKOE+ZQ2T2tcyz/" +
        "+DbeMptECfJ0lVfCKIY7ZOzBPaQ=";
    public static final String Intermediate_CRL_2_PL_01_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QTC4wMS4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIyasWvfR9TNkwDQYJKoZIhvcNAQEFBQADgYEAdsNe" +
        "ugM8sd8bmIDkYXce2WmS5Zx6QUQ0yT6Ij4OR5/F4CG4Vl+k3JkNPuAiNSs2Z9HeML+F/W8" +
        "3yEPe/mdLV4nLw4B/b1/8DmgZN4r1ojaWuHAg+KrA3Zz3Rc/hwQfvBy49mf4NGtY4ArbeB" +
        "DYKz5sVlrwR+gOCR5jm4IC7WEDs=";
    public static final String Intermediate_CRL_3_PL_01_05_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QTC4wMS4wNRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAICVXebNdg/K4wDQYJKoZIhvcNAQEFBQADgYEAqYex" +
        "FaIykZo17O2URpofe8x04L/VsfA9jV28zUgNFruAGld/kUh4rYvgwrdbNZ8NmEFDp9J9aL" +
        "93af3bzoNvWCik2VrQLd5nccCFiC04B+LUH9Y2p+7vV2ojrtBks5SMW0q4HaNyPSQu8Fst" +
        "4mYVf+QIYZC3iVAF4rsKnaxwzIU=";
    public static final String End_Certificate_PL_01_05_crt = 
        "MIIChzCCAfCgAwIBAgICAJMwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTMtUEwuMDEuMDUwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVBMLjAxLjA1MIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCXJjzKGcLyONTyOa6sQHvIKZIAh0pWdteUiXf" +
        "b7yjCn6Z52SCHxB9GZERHwR7fbJpoE3oDcYUY+8pH65bIVm1p3zr5deo4v85DEZQ50cU9a" +
        "WEUAO/5X57P7pYb9/47abu0cdsLIWeE+O94HpZS8vz8mxRQKLj27gPY1KzzTbrZQIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECG8ILlM9oqZwMBMGA1UdIwQMMAqACAlV3mzXYPyuMA0GCSqGSIb3DQEBBQUAA4GBAF6S" +
        "x3aunfgnDmo42aPOzDh536WSkTTbX9bmUNyg3IQHl/3xhVqjS76bMqreYhx5nh4VNx/Z3N" +
        "LD0W75XmASCk0wtW9S1MoxzJMFIozRruaE3oykrbyMMOt0Br5CV12ofUd0WybDkXfNAIze" +
        "IRgps3nORHWjV1GwXe8uNoUn6/z7";
    public static final String[] TEST_58_DATA = new String[] {
        Intermediate_Certificate_1_PL_01_05_crt,
        Intermediate_Certificate_2_PL_01_05_crt,
        Intermediate_Certificate_3_PL_01_05_crt,
        Intermediate_CRL_1_PL_01_05_crl,
        Intermediate_CRL_2_PL_01_05_crl,
        Intermediate_CRL_3_PL_01_05_crl,
        End_Certificate_PL_01_05_crt
    };

    /*  
     *  test59
     *  
     */ 

    public static final String Intermediate_Certificate_1_PL_01_06_crt = 
        "MIICmTCCAgKgAwIBAgICAJQwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4wNjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAweCAiEGMLycmodjrUMIWEEFshkvhX2r90wGl+/pU" +
        "Ia9NSdT23zYzE4Uo8Is1ywyV+YfvgR22j/RXF6j8OK+XZ8jlgfjVTAhjCnTWY9LDR7qAyk" +
        "8zuuITxJrYpiPoxqZs9BXLfGkDbye5VpVJXvQdbJNxgKO0hkBBDfe+T9+qw6ECAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBBjAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECG1DiuoAwV6aMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAMFvtFiMDMP6n3CrqQLSzhpK5Qu0uxa56ARXIKSIqi0OUZAu9v" +
        "sCXxMvaG/R5bElwi7ybYZ5KUSN+PnDmlUxWWL5Ib5RZdXgj7L83oyLTQmbDMvka6rSWHgw" +
        "Jq8qHVslhh+l+YNOb4fzs8x9ctCrs/BgjX8wkORpQbigU0BUJ9sX";
    public static final String Intermediate_Certificate_2_PL_01_06_crt = 
        "MIICmTCCAgKgAwIBAgICAJUwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMDYwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1QTC4wMS4wNjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwf6Nf0+r7JvE6BO4MbDbS1T1SCzn78haBAmqGZLS" +
        "Ac4xQTydvmzr9PwiWlU0xjFfKItqRMt7rfzTTPfvvnwxsAfQNPtxKzi30yCNq/VotMA7j5" +
        "iQYaVe2OWVHu13agbXLEZ0pL/ZkmQ3Gvo6UhF4dRmCnjFbd5cMTxQVHUrwgyECAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECE3tS4AYmwZDMBMGA1UdIwQMMAqACG1DiuoAwV6aMA0G" +
        "CSqGSIb3DQEBBQUAA4GBADcBTKbhx8PCunjRVJkcLBCcVGHs9HfkChDafwBO51fe5uhHE2" +
        "QBpW3J8ZsevuFQiEZvuy2RVFktE6ZoKD8wxwBFhs+OIxe2mergQPy6jHuxoSUiPzr3CVXZ" +
        "UsNxe7j3IcJLqbJ15UqGFH5yph7Sa4Ym6x747miF6W9knNkjcx3K";
    public static final String Intermediate_Certificate_3_PL_01_06_crt = 
        "MIICmTCCAgKgAwIBAgICAJYwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUEwuMDEuMDYwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMy1QTC4wMS4wNjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwq2YlDLHX4KktKnzLCYjnk079IDgXENrkRBuZHTB" +
        "IQyZoiBH4ZWHreZKs3LvznP8uSd8eEL8keNw4PwZ6aT1LF/Jr/UlrFQNnpLzQVXwGGAuzh" +
        "tFJYRlOfI5cCZYAcpjnyUV4GW+MuwBdoqDycMjmqIv/8A8vupjahffcmBAassCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECB+qYFJjEkJ5MBMGA1UdIwQMMAqACE3tS4AYmwZDMA0G" +
        "CSqGSIb3DQEBBQUAA4GBADiXredACtRQTV2TKgu5SDdPlczj7cZZUARJiJKiRfjmxHCc1q" +
        "m/Oh7sHkqRvlHqjoX8qp4iSchoZWdOAE5O/q4Ef6rViejDFVyN2ZmlhP6KIiRxznrvYfF1" +
        "n08K7CHgHWvDaumm4pNmWeF03nuasHrY0W9h1uk5poVuzaWDpx3A";
    public static final String Intermediate_CRL_1_PL_01_06_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4wNhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIbUOK6gDBXpowDQYJKoZIhvcNAQEFBQADgYEAiHM1" +
        "xFuYt6tDscqzwj0mLHPHULnR44/vNyPUg0KnV03Dd4XbFHz0FtwDKgVTBZ8x7ybp83ubJH" +
        "tE/p8nPW5kN25WQOlYkZoAcMpEXjTzlo9evU0W3nyzJjmlT8YEI7vnmWFz/ahzy6WFwPue" +
        "h862EKh2zVO4hoqZYEuDQI33fOc=";
    public static final String Intermediate_CRL_2_PL_01_06_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QTC4wMS4wNhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAITe1LgBibBkMwDQYJKoZIhvcNAQEFBQADgYEAuDSF" +
        "W1KOc4x41HGvdRaw/NtipD2y6zSh3mtRoo7Q6J2BvJvunymZNEziozBOiUgT8zMgbdbm4a" +
        "PEwlHRaoJP8+yxJIlKaHa9Hc7Yz4SOwSrLicf7EnBSct3Mze0b48UYqbn1q+lf/zKaUGrP" +
        "M6oqtE8Fam06T+WUfutU53zTtSs=";
    public static final String Intermediate_CRL_3_PL_01_06_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QTC4wMS4wNhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIH6pgUmMSQnkwDQYJKoZIhvcNAQEFBQADgYEAcPfO" +
        "+Rj2KmO1CxjuKLEiOUAIq5YmR4U06IcCBGMxlrdHVXHM3vepBKUlMDaT4UGcleABMPX9Iz" +
        "/31ofyXlZ/fQJOoTZt0CI7SOPQE5ZkUsR3BDuUqf1+sWwBYyBHkrC95JhJkM4LfGS5K19p" +
        "fp0j0bguzNCXSBRTfjSZhy80tcs=";
    public static final String End_Certificate_PL_01_06_crt = 
        "MIICljCCAf+gAwIBAgICAJcwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTMtUEwuMDEuMDYwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBNC1QTC4wMS4wNjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3asAqJcjXngEuyM/W3+TAE+Qr4JtNUdwBtmrpGlo" +
        "fAvJdmXHARyiN/Zn6Si8bGI8Wz8J4Y+Ll7zLdaMU4MCZo6hwZiaQwkh9a+ZecCpLpjs4mz" +
        "MSf5zHSwTYiXKMazlmnGEITVyKLmAiLSyGeeJvOJVqVo/NZXRGVlmnPxZFfgsCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAeYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECLZuS770NcDsMBMGA1UdIwQMMAqACB+qYFJjEkJ5MA0GCSqG" +
        "SIb3DQEBBQUAA4GBAGM18aR2i8vSywsWhcLrRN1Xckl/HiBPNphobfKoER4NG29cFjUPQX" +
        "zukjQcJl2clAXNCVtcsKCoYRP3YUyAB6At+yskuuJXtES7FIzM3rt/UpDS5ktVC3gh+jgE" +
        "pPhMILYIXFzYY1hifkpagfO+mkcr7RqHU3tHAr6LCWjqrB9g";
    public static final String[] TEST_59_DATA = new String[] {
        Intermediate_Certificate_1_PL_01_06_crt,
        Intermediate_Certificate_2_PL_01_06_crt,
        Intermediate_Certificate_3_PL_01_06_crt,
        Intermediate_CRL_1_PL_01_06_crl,
        Intermediate_CRL_2_PL_01_06_crl,
        Intermediate_CRL_3_PL_01_06_crl,
        End_Certificate_PL_01_06_crt
    };

    /*  
     *  test60
     *  
     */ 

    public static final String Intermediate_Certificate_1_PL_01_07_crt = 
        "MIICmTCCAgKgAwIBAgICAJgwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4wNzCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA5HkS45NLuqq9ZwF79+pTGtQnGWO7DFdetYeQTbeD" +
        "sisjZMsK0sCCR5xAKYQsJSS4v/8LQUdxlQR30LMV0SQUKFMJyFsMiSsO8subb6sVINWn8A" +
        "tL4zcQK0WiASUZOEkybAFJtP31PahzI5wfD1cikE1M4BlDij5WeaIjt/RTHKUCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBBjAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECLSUEn5d8YywMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBANLO+kEiswkGzEh4ZcF5LtfnPZlnG4gTPSNugeWJc+Xedqmttp" +
        "jZ35fr1hiRe2Q1UcyTd4ThkPknawwZednbsZVPqw8u1mo7kuAeL9KrCk199vL4bV8Ag/kj" +
        "HJ8TAy40UDB6hMm7l4j8mEKwV03THVrz1Vvz59CQXj+iseH6yUNO";
    public static final String Intermediate_Certificate_2_PL_01_07_crt = 
        "MIICmTCCAgKgAwIBAgICAJkwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMDcwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1QTC4wMS4wNzCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAu78gmT5HwmBHEe+K8fLLgGaPpcv13ZjrgL4twTBS" +
        "OkZn5LL9GcfkPuA5WIAZkVYfCWSDPqcAGoOWUIDADfBfdcyLteUH+xI01rHKiLDVexMvU9" +
        "vqCmcBKhxK3S6wraW5YhOO0bx4oPrZXVIjyG8fh4e5WTEykzvUWJ8ZbzSJ9JsCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECCT+fDEaN7GaMBMGA1UdIwQMMAqACLSUEn5d8YywMA0G" +
        "CSqGSIb3DQEBBQUAA4GBANpKr98PiXAdcXlbgSgif0213H+tg3WwUNKZTw8MpqPyrN2/DZ" +
        "HBi6e2KWXLTxttV9AZBRvcKwsveS6oc31eulMe8nHxRNRfadvF6dL3Tsig6HAQkartcJMI" +
        "yfW4V3EhXbCdziQkre7XcR9WK5bpQoX04HWeew6YTxjG/cL9MIJR";
    public static final String Intermediate_Certificate_3_PL_01_07_crt = 
        "MIICmTCCAgKgAwIBAgICAJowDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUEwuMDEuMDcwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMy1QTC4wMS4wNzCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAr7YezMXvnkSuNCdXch2HRAEVuCqfzpVRCj6laJI9" +
        "Q+NxgXwzaOwnImvwER3Hblh1l0MAt5/I/9hhqCN+918ueME50MkoM1wPbcmrRIlwWLGSVZ" +
        "yBKeyPHrLbdPqVIexUlQk7PasLm/Qx4SvRGVe9IMLrEzPV3MFJtrJoWaMobQkCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECKw8JlHMvVfuMBMGA1UdIwQMMAqACCT+fDEaN7GaMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAA5JEDEDyqfZzTGzOoMV+8RVke+a4qgOo7rnOEdletgGFEwz8A" +
        "tiMHBxR+UMxuHS82Hz3+F8XlyYIwlrG9wWVcB/tOyzgVyA28Yux9Q/meU7T6dco/AnmOdr" +
        "2XL6Xm5iLnARG+PkUPHOsxuweyB/sSUSA8ZJPowNRWTik57ul/bO";
    public static final String Intermediate_Certificate_4_PL_01_07_crt = 
        "MIICljCCAf+gAwIBAgICAJswDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTMtUEwuMDEuMDcwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBNC1QTC4wMS4wNzCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA7mNS8dGz0gkXDbBRzP2ypdNMahJbM3cSMHO0hYpn" +
        "uRsiXGUhIB0K4WVbnz6tr7Hch3yltK4H1Y12Lf8cXEETR2sE9lCY2A3r8/VM5OUbou5Y8k" +
        "wIf03VhP7cGKonaFtlj/WD77fidDePVp1Nk28gV0T2F/l4pM5TEJrq5C9PSUcCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECJBEcZsMRq6CMBMGA1UdIwQMMAqACKw8JlHMvVfuMA0GCSqG" +
        "SIb3DQEBBQUAA4GBACfbHKpuRJnZ5UU0sih8RuywhUo6Getwl/p6fsi87wYI61pvYru+hm" +
        "4R4eAMZvg7MrAarS3Iu3zKBU1HKeq1i+hpwTIXrngR8eL2fU/X6GPzdte3+3tjhah38bqF" +
        "zDon+N6ap4MKWRk033SsFYo1K88Mena2tGuFForJlV9DOF1l";
    public static final String Intermediate_CRL_1_PL_01_07_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4wNxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAItJQSfl3xjLAwDQYJKoZIhvcNAQEFBQADgYEAJtaE" +
        "I1+PCNL1/bgEVKWUIwvh58ugnWhxzbFW6hNJwNEz9/yt+FLZfNrT/Ezort4VVQFLQg7+Gj" +
        "KrkIujqfRJG4LXrXAV8ZsvSPuwyQ+hM1GdHGDPhj9x6DkjFusxJYUEs5BzlX7ovpnaIPSW" +
        "RPsatheSzu48pMOCmyTKE3MpuZg=";
    public static final String Intermediate_CRL_2_PL_01_07_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QTC4wMS4wNxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIJP58MRo3sZowDQYJKoZIhvcNAQEFBQADgYEALiV+" +
        "BFpXhgTjiMZBYLVuc/fqhHcXeXOGOmJZoKUnIXjETH3rzkkt5k4tMN00ycZVgpRwn3ZyQs" +
        "cFLcW8taau1J7iQOmGY/7qIT0eFx2OlgNmxqirmwx4OM5VSH5mEpnp9NOr1rfut1GDRzw0" +
        "tZ+nhD/PGDXYPu+QPX6jii0vdHo=";
    public static final String Intermediate_CRL_3_PL_01_07_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QTC4wMS4wNxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIrDwmUcy9V+4wDQYJKoZIhvcNAQEFBQADgYEASY47" +
        "p94jEh9FZ1TrPS82nWC3Z6ZKdaD9pUbaJpRnAId59QdBaD2Cxq+SfM3HTlz8grCAPKwulv" +
        "jDDhXhp4H/m63Q/pJbyl3bbMxnphMOoDwB9wwKIUQPM5wagMovF/UYtC8MoC++m2kuZ1eb" +
        "fR/OIJuQr+k/kD5Axhw/xolKPdE=";
    public static final String Intermediate_CRL_4_PL_01_07_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QTC4wMS4wNxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIkERxmwxGroIwDQYJKoZIhvcNAQEFBQADgYEAMhIQ" +
        "lE+BdCO6NBz+YgcH+tjP0n4OCdQ+7uxUxUYmPtPbsLwbDDEEZUjykgwiA6P47Cqh5fXB6G" +
        "tfInh1cmQi3y2IEHK+bRSx321qczOh34Yx2hw5vp+JFttbQAEl/BHixklrFBrXjN0UsWGC" +
        "ibXcZy0YjerWTp/yceoABz9p94U=";
    public static final String End_Certificate_PL_01_07_crt = 
        "MIIChzCCAfCgAwIBAgICAJwwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTQtUEwuMDEuMDcwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVBMLjAxLjA3MIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdH60mBM1eInACvOB83zLrtiebq9B5UBlAAVS8" +
        "9ucDwGx1HOJwhwk2AmvhN7pYuDc+BFzuNtgHojqZSDpRMA3rVsGlgOkZ3sOQzvxB73w+/X" +
        "XmCYpwcEGLpK4egl8r1aOYm0Zm4OxqWhNu9+Do7nrJczDLi8k/qh8/+Rfdtvt4kwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECEmVurZ+7UXFMBMGA1UdIwQMMAqACJBEcZsMRq6CMA0GCSqGSIb3DQEBBQUAA4GBAANe" +
        "AbvpAHwBu9+FlI4DOb65Z+h5f2Ok59FVbVqAj3zkMRkawppngK3CMY/1BQlGXOlHvE+CGz" +
        "x/7DsiV0O3rxOUjutt00PNxCyIM2pcOZeGUaAu5DJWn0SRwzTMJa4M5K+7wh/4sSPWyxKi" +
        "ueDq2VXvIgAfEVC8Lv44sxcOduSZ";
    public static final String[] TEST_60_DATA = new String[] {
        Intermediate_Certificate_1_PL_01_07_crt,
        Intermediate_Certificate_2_PL_01_07_crt,
        Intermediate_Certificate_3_PL_01_07_crt,
        Intermediate_Certificate_4_PL_01_07_crt,
        Intermediate_CRL_1_PL_01_07_crl,
        Intermediate_CRL_2_PL_01_07_crl,
        Intermediate_CRL_3_PL_01_07_crl,
        Intermediate_CRL_4_PL_01_07_crl,
        End_Certificate_PL_01_07_crt
    };

    /*  
     *  test61
     *  
     */ 

    public static final String Intermediate_Certificate_1_PL_01_08_crt = 
        "MIICmTCCAgKgAwIBAgICAJ0wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4wODCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsr+i9HxgO6LnOa6xOHfe9BeLVTo4iZd8rp6UTc02" +
        "C0MmsSjvIgn3UiayU7aoHcTH8tAXSV5bn0CIH4B46qLym//oE69hUFImy6d1kKgNoaUKWB" +
        "HztKVtswSSPjIUf7pbyp0wasYMN6fIKYyLpLXUxzA2DrD0kP2Y8ElQJKl2HocCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBBjAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECPMW3WMPtaowMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAH2N6S9ggfmRJkzhs82uOPXaHF62YEg1pbNxaCyJJbSt2iIIyy" +
        "NPSlE1OufPPH3pO7p5xcYi90LCI//0tlUL8y7aULFNygbshFY3B8MSgCz3KPA3UKdtIZYe" +
        "7lqP9/ob5wmkjtLpx6oZ4/38jxqe37pH1IwVjaUnoeElSo3EkCI5";
    public static final String Intermediate_Certificate_2_PL_01_08_crt = 
        "MIICmTCCAgKgAwIBAgICAJ4wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMDgwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1QTC4wMS4wODCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqZZolrig33i1rEwdP1pin8a5PgzSk7fT+qhrJRCg" +
        "UTOW5WyPtakrLTUipDcR07t8tIe0NsjRoph7+fAwbjWBfbJdydndHHGx5BqWg8Xi4zFhFd" +
        "6Mc5O6KO7Yqxs8lmthv/RAdL4Eiir9d9hqskKOtQKbLWz+Bz3+9NwfLGzwzPcCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECFjxM3RkbbhNMBMGA1UdIwQMMAqACPMW3WMPtaowMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAJOJKBubTS/kLnfXN5YbQfggxbO2c7DTxx2LhrnPiyVDEow+Xf" +
        "lMv4YK5olH6UUm02D8cv6Wxg4NeTtBBnwKQG/GV4Ssgc/rrpEzM7jFRQcUzPu0jfya2fX8" +
        "ZNBnSDjovlN6vmZHtiksjh66h3a0aVusEuOQXD29ogMR8qAGYQaZ";
    public static final String Intermediate_Certificate_3_PL_01_08_crt = 
        "MIICmTCCAgKgAwIBAgICAJ8wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUEwuMDEuMDgwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMy1QTC4wMS4wODCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAogLtEcWxzzkkIYe+KrwKhaQjjGQqy2KDsW00U5lx" +
        "+XJoT8eKd5pxFdCa0SPn/jkNILVeh07mIHec1WF8SOeveVT4Ewd3nG/6ZGoVVq6l0j+3RM" +
        "jpJbp26BPR69nFn6rmFUMoSNq0VG8Zl+UBqnjq83G3umJCJMMRekUTULSFEGUCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECGAFYeJIhrRzMBMGA1UdIwQMMAqACFjxM3RkbbhNMA0G" +
        "CSqGSIb3DQEBBQUAA4GBABHamiW7sPLQ83nXt3LZemcAp4QaDB8X94EuJGBwshEcKLoOHb" +
        "/3cZkPRbOiRQUh/YdpfyApndGFSi0DtwM2Z7yup+MzdrR0wzQoNS95A51nHE7XdCuVFemc" +
        "LTJ5rdd2BLK3OB5lQagVLzAY9Bs1vaeXKT2Cy+gSUkTIekWcsH3K";
    public static final String Intermediate_Certificate_4_PL_01_08_crt = 
        "MIICljCCAf+gAwIBAgICAKAwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTMtUEwuMDEuMDgwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBNC1QTC4wMS4wODCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAxVjjKlLlZzeZhamPO2NDnRtWM1oWZ3/kdwdBRn50" +
        "o1NRXb60Ir2HjniK1dRdbijAvR5uItLe9tmj4nusBiaPUGM0HNlEdQWSzble8rvUsP0apw" +
        "uJusV7zLvzwwbgLbMYT+8lMhxWXM34xszP+dgjWASQOVao1Uqs/MLLibOuueUCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECFMFrvh2hQ18MBMGA1UdIwQMMAqACGAFYeJIhrRzMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAFsCOJ4DzuMOKti5PvF71ZKOtcTHSv123ZNdPIbK6OatT9YhVuUOYB" +
        "AjMavggywrb+QOXOFfJMctQlS3y/JE9YyoNNt/4UTdx1jQ3I2ablonmzjt8eN5GJ9jUXth" +
        "fHjxnmGUeWlAvwMjEdzdigkyuWCi9LJfjyHtTjSf9n7w2rU+";
    public static final String Intermediate_CRL_1_PL_01_08_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4wOBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI8xbdYw+1qjAwDQYJKoZIhvcNAQEFBQADgYEAG2Aq" +
        "R1oelnrTgh56m6Mm+Lsm0Sf+Ot1W7LzZmMDwoZgmGLcTduVktx+XrtiDDWsf58hmneT1q0" +
        "5wl4yNH8y/VCAA3SM/gOq4ddOEiS8GbuEYo5P/julH/U3g6M0vfPUZ5y+7V0s35jIbTkjX" +
        "76n3Rhf88nvTscYvMdqrYyUhAmg=";
    public static final String Intermediate_CRL_2_PL_01_08_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QTC4wMS4wOBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIWPEzdGRtuE0wDQYJKoZIhvcNAQEFBQADgYEAX/+I" +
        "DkAx7PLTi2x6aYbLacPRaUSjMne84MDaEkYiA64Vo3eL6FbKe14z2mBsM2W7x8xDnxjZ0N" +
        "RbhcFZ2E6A1ct6HMunuKxjoROIsdWhrYMqJfKKMTWMviz1UjtupsGUWS0dVQCquAr6DJmr" +
        "W88P8wgiVH2VZsc+edDmCGDunrI=";
    public static final String Intermediate_CRL_3_PL_01_08_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QTC4wMS4wOBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIYAVh4kiGtHMwDQYJKoZIhvcNAQEFBQADgYEASw1+" +
        "6rGDKgpUtXcCziQCjy8mHFD2zV6x/Ppxm2Gj0U+5eFnIbMPmr4TUYwfSOROUycsiJX/Wa8" +
        "HEuqWJhIdcsHMA7TYf0iSXK597Bljjg4F/1Rgz0wqLjgMuA59eFbKjJ6zP1E6Sv2Ck0Ea9" +
        "HJsv5zFA1ljVnNWoQwoHsuLk/wk=";
    public static final String Intermediate_CRL_4_PL_01_08_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QTC4wMS4wOBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIUwWu+HaFDXwwDQYJKoZIhvcNAQEFBQADgYEAHHKd" +
        "U1SccTsK99BUDrvF930ejNRAvHQM9xv80wcUAy18x+TLwBH8vDTmP210/C5Zk9pQs+rLDd" +
        "doQQbWJrQkznyB1OSK0T41KZ9L0UE+YmFGJjz0PEzYHV0Kc57j5uc7Fsi8Xu20Y8JeTaJs" +
        "FUXVsvnCuoSxYmwY1futFWHJG7Q=";
    public static final String End_Certificate_PL_01_08_crt = 
        "MIICljCCAf+gAwIBAgICAKEwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTQtUEwuMDEuMDgwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBNS1QTC4wMS4wODCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwgNkhQrcqmjhkES6DNAW3uQLKILcFlrFvOlWfDPo" +
        "ngXzCKeed85npqL+Enxo4sLarEiywuDLrDgPf0gKnZXQWBmzWViZhvTsiAemH7iNsNS68s" +
        "hhb0vnLzlPpDUJDv7KVKW8VbM7nvplKptlEE6g5kmj3iEmM4l2u8Z/pmQoTsMCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAeYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECLfApJ09y/ZNMBMGA1UdIwQMMAqACFMFrvh2hQ18MA0GCSqG" +
        "SIb3DQEBBQUAA4GBAG2ANLc/ib9ayz0B0L6/XQf/xuwETEq8kb5vWml/PbcFD1b/uwRHI8" +
        "vTvM559nZgtzkhS5ZAvNBTh1CB9Ox/nugHc4srbH6/Wcd94pMQx/sfCB/C6zZ5Tbm7Y4jp" +
        "hkjnxwGUYTvgNzxmaAPLyCfqY7KwhCSzns2M+yuncEKqlzuT";
    public static final String[] TEST_61_DATA = new String[] {
        Intermediate_Certificate_1_PL_01_08_crt,
        Intermediate_Certificate_2_PL_01_08_crt,
        Intermediate_Certificate_3_PL_01_08_crt,
        Intermediate_Certificate_4_PL_01_08_crt,
        Intermediate_CRL_1_PL_01_08_crl,
        Intermediate_CRL_2_PL_01_08_crl,
        Intermediate_CRL_3_PL_01_08_crl,
        Intermediate_CRL_4_PL_01_08_crl,
        End_Certificate_PL_01_08_crt
    };

    /*  
     *  test62
     *  
     */ 

    public static final String Intermediate_Certificate_1_PL_01_09_crt = 
        "MIICmTCCAgKgAwIBAgICAKIwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4wOTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4slldx8rhfz5l2i0rwib2McrCyQkadTjJRoEGQCV" +
        "xT0dmw7GhDa6wJg2ozXLLk5y7ZCwlmBOTEoNbigHvcKSnJT8R/S+F4KqBz5d5dbRMNEKYz" +
        "jdbD7Sm7id+eyfq1s5cpmta2lBJ5gTaC9YPSOY2mucGcJ1muYzdOc6h+PCCNMCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBBjAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECO7tq4dJC8OgMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAHbth0HjAygIoWVrz59ZBPntOn5nzgUGpH60aSDOS6i9ZOKSoC" +
        "7wCOEt6IpKO7M7SNznxaX2uhFTYotneyq3qENvqZVXKhE6wQRsdK4kG10cxSB5AXPHJRgk" +
        "W9+p+Nb0iYVKwHdDCW8KHYIroGhSkKxuflwxhK6DcwQuA7y5q7r7";
    public static final String Intermediate_Certificate_2_PL_01_09_crt = 
        "MIICmTCCAgKgAwIBAgICAKMwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMDkwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1QTC4wMS4wOTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA70v7BFxmToZHF5M29JK6N0Ha6n729cv1U912mH9O" +
        "NTz9tafa+jv4W7njScv21CJbNlUO5rlAFcTlXY0U9vbqHEufhtwRQqi7+pkfa+Ig8bwl26" +
        "4U8L5rgmSvZJpEiiKfkmF2Rz9+zPPhHjk58ZcKoAcyhOdZ60KqmaaU/TVtEq8CAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBBDAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECKOwR13+P/BlMBMGA1UdIwQMMAqACO7tq4dJC8OgMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAN71oLHr0+uf6zCOC5L7oeCOGMUwvZyROu8eTztZrPYGjaamSm" +
        "Z0ZmUPOJP3g5nO6tHf34Tb9CTkwPdPicEaXuxflkSbJBV3mUFQ1BUDlyYTuaL8uT2N61dg" +
        "xt5RgYTIGsW3/2XrRvXsH91gSiEkccoUyjKnQcX3oZmEeITb6H8m";
    public static final String Intermediate_Certificate_3_PL_01_09_crt = 
        "MIICmTCCAgKgAwIBAgICAKQwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUEwuMDEuMDkwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMy1QTC4wMS4wOTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwMLmDs63ai7i4xC/1ufMFWeigJAlbKWMti/PeEKi" +
        "7LBfNJDRaO+1kde6QIo1vhkhKtokNu9ue3Rfo1+xGuZVohjRbHnmamEm5G3jihegPQgGCR" +
        "fDZoJDI9HMbwBa0RWw1Nes5igIVjdSHQKO/XTul1yyF2Dt03K2qeLwes+2FyECAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECPEAjG80q0FoMBMGA1UdIwQMMAqACKOwR13+P/BlMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAN9eiZXma2n0XgzdvYrlV/IEqBIhpcZ7gycjDumVBVITZJD2sJ" +
        "bkBi+N8dg7uovgxGxWGsyxqgAboLhMgbpbFzGh+HyIhQu/CeAx93PWYc5rP2l2Y8d7KJvk" +
        "p1GZEcG/nTakpjxTQ5MQYFsOHVsnDDOyaZYvqPuMrwGYsfoUa1wq";
    public static final String Intermediate_Certificate_4_PL_01_09_crt = 
        "MIICljCCAf+gAwIBAgICAKUwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTMtUEwuMDEuMDkwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBNC1QTC4wMS4wOTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAo4L9QEqzq2VXzkZI3cvUWR5v6vreKKQPfJPfEwNH" +
        "nMS0cgDjC4Fnw9ySI7Eb4A/OJGLIyg84mzTl6JX3kGoYr9/bJ8jOD7pN6CljXuHpwwmd7L" +
        "6Nf5Hy0ltjAIr5s67e33OWdPi4gApS4FN6nPSDkZotY73d1xqJYQQZWuNEsGUCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECLfU7BuxzXeCMBMGA1UdIwQMMAqACPEAjG80q0FoMA0GCSqG" +
        "SIb3DQEBBQUAA4GBABmQZOvwRpVsTD8uazfQpLJUZkuTap4OOPHie5xJsvOhGend2k+LiP" +
        "7btGoFrqmkyVV/+dNA8+45SRsnoOtgctiF2ubeqIvd7xf/J5C9Cmo+T89Mt7WEBEuDmEZm" +
        "JPXvOvyh6lRcYVSBnvVW5ZSstNAQKa/8xuyN0OrE1hJWbucn";
    public static final String Intermediate_CRL_1_PL_01_09_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4wORcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI7u2rh0kLw6AwDQYJKoZIhvcNAQEFBQADgYEAbXc1" +
        "QgR2TAvOPqJmRFFrDQkPVIVyEEDTwZy5aNnoAKK+AmJ5FZkBtbPJ8qt9UeYRh8lbX8+EIk" +
        "tyrAKw/1Kc3h7RDqAQ/p8t8kFwVQh2l4KTIukV8hYcj5sMKlt5f49ZwzWPyoOaLDomiUfI" +
        "OY/jaDMw293AjQXxGCDtnaTvh0o=";
    public static final String Intermediate_CRL_2_PL_01_09_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QTC4wMS4wORcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIo7BHXf4/8GUwDQYJKoZIhvcNAQEFBQADgYEAq6en" +
        "XtvIdh/DifGzWn11hqJIZxLQDGJZPoMmwSOLyB6OzsPrIg1xkOWZYEOELTR8+qP6emmx+D" +
        "CaEbUDLj60rso0gRQCBwTgHgjeMRpv8fGnV8MJgMv5BdzsGAGQbLSSY9FxtqeCPfZ6olHC" +
        "iUIopdZJZP8ZvGKQ6QGaMnLpJ78=";
    public static final String Intermediate_CRL_3_PL_01_09_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QTC4wMS4wORcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAI8QCMbzSrQWgwDQYJKoZIhvcNAQEFBQADgYEAraCx" +
        "ruxopFbKvxOx/CIF4niG27ABB2ZwU6n4NBGYHo1Y9NjuytjjMZvQjMHyoayqpnF5TA1vXL" +
        "jXjI3VgQcK7A4ah/0FNLFGtczyY8kXXrpbmdg8+xdNJEG3/e5rDW5VSf7OY1XqU85ySUJQ" +
        "ZR5uiy8LxlDdaIT4WT7X5ezs3wk=";
    public static final String Intermediate_CRL_4_PL_01_09_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QTC4wMS4wORcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIt9TsG7HNd4IwDQYJKoZIhvcNAQEFBQADgYEATtjA" +
        "BdSZYnIbv1bCL+aSiioJg9S9yWGD1mjsA/CDzvkzSffeSpvqaSy+Zwwf+NDMMG6Cs+SgU+" +
        "sxQdJALAbb4sYGEyXj/Exh9BYHvgoVahH4NWuhm6LIN8RTcMDAtGoGYFNGXGuT8XRBUJZ/" +
        "tH9re3gpWaE1rjWeB/2ZBR5ONcM=";
    public static final String End_Certificate_PL_01_09_crt = 
        "MIIChzCCAfCgAwIBAgICAKYwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTQtUEwuMDEuMDkwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVBMLjAxLjA5MIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+g1Puqjn+/Of35mqVVUricIV5x+bpZRCAgBDh" +
        "VYcmZFXLB/XnRd/mYTu0RR4ISEerC1km5tjGeCN2k3NGdZwz/wEh9kEL8WikSqpxUSUD/N" +
        "vQbliz4f3YECLcpNXKzkCvszeB5ZGHa0sLYDg3r62wy+1y2rtcrHzFEoMFgnnruwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECANGcL2klYf7MBMGA1UdIwQMMAqACLfU7BuxzXeCMA0GCSqGSIb3DQEBBQUAA4GBAHm+" +
        "/vQ7VxDry3VqiqKnNoOhAHTTIUphNWF4jddRqVc32IsjVaeTbcGwCIRflRm/lUplRvXXxb" +
        "JEbW9mP3nfTCREUdm49hjmo/szsPjgosFoEmuEKXThC81/y2vQkb4/jqRoOHEknU++38EU" +
        "Juv6Y6psZNa37x8Yn3i7S+b3TM2q";
    public static final String[] TEST_62_DATA = new String[] {
        Intermediate_Certificate_1_PL_01_09_crt,
        Intermediate_Certificate_2_PL_01_09_crt,
        Intermediate_Certificate_3_PL_01_09_crt,
        Intermediate_Certificate_4_PL_01_09_crt,
        Intermediate_CRL_1_PL_01_09_crl,
        Intermediate_CRL_2_PL_01_09_crl,
        Intermediate_CRL_3_PL_01_09_crl,
        Intermediate_CRL_4_PL_01_09_crl,
        End_Certificate_PL_01_09_crt
    };

    /*  
     *  test63
     *  
     */ 

    public static final String Intermediate_Certificate_1_PL_01_10_crt = 
        "MIICmTCCAgKgAwIBAgICAKcwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1QTC4wMS4xMDCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAr4LmuvhSms70CnuAHIHwz45csKvBPVtcDjA1tWNb" +
        "NIvvNHBzyt6G8U4CTVKmsFAZOzrWJem3b/ZywM1WlDarGJAAa/SRIYZ/jQwaOIoPW4OUfK" +
        "ZQI6MO7uAPcIQ4ugtPth10viVqZYLZn/6O26Q905YsFltuPFl64KrJVJJBlLECAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBBjAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECGRn9ckrcsEdMBMGA1UdIwQMMAqACKua6/nC51SPMA0G" +
        "CSqGSIb3DQEBBQUAA4GBANK+1qalm7Nl+PJHT9nQLVJ3ruQNAoMlH9fN52Q9BZCr30iWCd" +
        "+GhQIPRjxZ4GWojMnqbWzYQsxIR2PLdFc6SwjQrq+i2ES/LePDtaLQddS44/+GP/+qDpM9" +
        "Mqp3/Nbe1MfOKRBT57qgrxa8eUVieysoKeYX6yQpa8bab3qDwOTH";
    public static final String Intermediate_Certificate_2_PL_01_10_crt = 
        "MIICmTCCAgKgAwIBAgICAKgwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUEwuMDEuMTAwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1QTC4wMS4xMDCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAx5tMLJ3LRxi9jAzCSNkj8zyrSO0cImNGf6ZCIzEU" +
        "V8LrmXjgiZboPTh9LWQ3msWDLpzaxVxDLBXG3eMO8ys46TfJKciyeoiB8wfuNGMKAccm8u" +
        "43XjWs1KAdNikWEZupYPgdmA92oRlVcHshG9PqP4+xA6sydpu3V18Nyfa0n3MCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBBDAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECDE3dDXkS7TxMBMGA1UdIwQMMAqACGRn9ckrcsEdMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAE+8cyOUQ7y4atc4BlZNZvGNRZ63dbGDCM2AItTEAf4ETM9v7j" +
        "biUWTirJyoWsGxm2eIUk1V+EKxcuO3FotFUe7lS6thmVd6OYOSW+02RXMNklmptzK9I3AK" +
        "DZNh82ugLNyrrd06BSiED+0MoGVVI4gi3wdFtRiai+MgQVeWIB4i";
    public static final String Intermediate_Certificate_3_PL_01_10_crt = 
        "MIICmTCCAgKgAwIBAgICAKkwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUEwuMDEuMTAwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMy1QTC4wMS4xMDCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsmSUL/UZBYMdqU0PecjCd+9U+1Ld3mKkH303Fido" +
        "K6k5S4ZObxVHKhYDJyp3CcVT2+nENjzIfQQQaA11UK7Uf/jmVs0IC8e2scWzq0W2BeOLef" +
        "jVgNgXGsXyfLi9T4KJPPyGsKlIU2R2xKxgHmAOt/tw6OYX/OaEfM1jiQza5lkCAwEAAaNm" +
        "MGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBg" +
        "lghkgBZQMBMAEwEQYDVR0OBAoECHYI07i4owpIMBMGA1UdIwQMMAqACDE3dDXkS7TxMA0G" +
        "CSqGSIb3DQEBBQUAA4GBAK23Kx99Y9HtFBVnHWW/NfvNro7I5Wx/ZCko6ulHm84FPAjhnL" +
        "tvc4jmfAZd0wYPKQKWwUKUDWNEwIU1qkxyJYACckue35GLzj8aLY/z+h037vGonFmNutMM" +
        "rcRdiV7gVD17dYLVTt0RgxsDVDtut+twqHgIaKtKyJnl9dSgFFv1";
    public static final String Intermediate_Certificate_4_PL_01_10_crt = 
        "MIICljCCAf+gAwIBAgICAKowDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTMtUEwuMDEuMTAwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBNC1QTC4wMS4xMDCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEArgBnLCnqI6Sa7gXkZOvIKH4EL5i3CoG6eGG2R8aA" +
        "kjBs78IKGYj9gY7rRajAKSpf19zvfcW8+2gBDDj5AoCy6uDnBICmqdu+hkdokVi8dJHiTU" +
        "9LdS2TeuvFv47eiXoEBjMEAquCuSyHvW3lNrA+ESTnK3s7V4lBoO+o5mZD6dsCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECLTgYziQC9zmMBMGA1UdIwQMMAqACHYI07i4owpIMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAEx8wgBjBglU98rocddKAEKXkt4MNzrpUMq75C9HtnuOtFgM2oY/OC" +
        "x67aZSTEph9ag6Hc+MyxWB5rzGD9j0y7OLsasE9AX8vjplUq50wq1xAFkGi1GnqRK/Oe7D" +
        "S6R66+UFHW/3KAeNe96aaJuMcx0TRbfkGbW1ASSi/ixMd9Gi";
    public static final String Intermediate_CRL_1_PL_01_10_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1QTC4wMS4xMBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIZGf1yStywR0wDQYJKoZIhvcNAQEFBQADgYEAjkY5" +
        "nXjLst8CMz0fyEM7Ft2d9TOOJXV4TMAfSAP9QCnit8qzrdVdJ6TJIsJNZYBz9Ryr5K/iSw" +
        "KbYk0g6y/pskcMoHG3vJwNAxBbkf+fV7Eyve+90Z6oWDXHKLGCQQpdZ0a0wAqYeiScok8+" +
        "YHypEVLfbjWARR9fsci2Ps3tdvA=";
    public static final String Intermediate_CRL_2_PL_01_10_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1QTC4wMS4xMBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIMTd0NeRLtPEwDQYJKoZIhvcNAQEFBQADgYEAdpTU" +
        "xcywBjX2rD8Gu6zkDqlDmZfRXHDPtnf2RB4bHDx77kDEib6nH6DGoJdx8WnRTZsTjly3MG" +
        "62LfVmjp/bJyKHUQqBDrilv21EWsaI9JOr673Nk5iTZa/645GdgyLzSmxvcVDN40BAH0py" +
        "/2gvBQTPNzp2W1IR2mebuLdHwTI=";
    public static final String Intermediate_CRL_3_PL_01_10_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMy1QTC4wMS4xMBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIdgjTuLijCkgwDQYJKoZIhvcNAQEFBQADgYEATVf2" +
        "cEEGphsIe0AsqNJ5rENLe8DeDAV8R4XCKdeP5qmHmLMm9Z4pX8bIfU7bCoXiNIwGvIU6ag" +
        "FmHPNHEj70cQFVqCX/ZESc02hit+Os9g7pcl7s9QgwVUCMZdCiF/+pSEp3eCL5tFoKmAZe" +
        "nxkL0KOSuKmBzuqRtZufbhDvmbw=";
    public static final String Intermediate_CRL_4_PL_01_10_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBNC1QTC4wMS4xMBcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAItOBjOJAL3OYwDQYJKoZIhvcNAQEFBQADgYEAbG2B" +
        "BhvRQ1pY/8VFeiCRFD8mBzq5iW5hWv2P7Zdp9zEbQo0fI4Kbis3OGemEttCxvAc/UPfogr" +
        "UudImf3s8sLV9BS59xQUGQlxZ5XBNlripY8EjHNWrwgy7/x4hzlZ9yYBbqoNOqnHLy/gbM" +
        "XZWoCbIK0co70lh1soOQ6eqLDKM=";
    public static final String End_Certificate_PL_01_10_crt = 
        "MIICljCCAf+gAwIBAgICAKswDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTQtUEwuMDEuMTAwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBNS1QTC4wMS4xMDCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3bx0qx8s4Zse6Ri6NqkLEKUPLIOhTFj/9Dh7sxvE" +
        "HpemBlTjbp2in08WTxEb9n8iAIWuGs3Vqm82ttBQmayjIaWD5oE/BE0oV/e91NAv/aRLsl" +
        "f7VtOb6vi8Ef6muOAjI2dUaUD6QONkqkJhnZ353uR3LZnsAEAW+InePGFNEGkCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAeYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECIokB8m8Vi4QMBMGA1UdIwQMMAqACLTgYziQC9zmMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAKBGQwZQLQFXb+/kjP5xAtq+1rRtrblytjpv3ujJrKH1v2VB2+9boB" +
        "0YYYGJTy2Wuj0ZBEMeTzMO8Hol4Mq9pnYv5DCmfnZN3FuDidgnRsCjM3ZL7NcXXG9YwlKF" +
        "G2SXj0YfkSwN9gnyN11W8i+F/OSjlm+TDKHB3ePMcY8EnnXy";
    public static final String[] TEST_63_DATA = new String[] {
        Intermediate_Certificate_1_PL_01_10_crt,
        Intermediate_Certificate_2_PL_01_10_crt,
        Intermediate_Certificate_3_PL_01_10_crt,
        Intermediate_Certificate_4_PL_01_10_crt,
        Intermediate_CRL_1_PL_01_10_crl,
        Intermediate_CRL_2_PL_01_10_crl,
        Intermediate_CRL_3_PL_01_10_crl,
        Intermediate_CRL_4_PL_01_10_crl,
        End_Certificate_PL_01_10_crt
    };

    /*  
     *  test64
     *  
     */ 

    public static final String Intermediate_Certificate_RL_02_01_crt = 
        "MIICljCCAf+gAwIBAgICAKwwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wMi4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3AN+Y3Hl/9V0nKXHQotb/cA2VfZc5vrRu+ZjwKgK" +
        "6KasGegAorKSTybYX/fTbnaPwykDPfSscAnzAW5WdF9+wTLmvYc+6pkcx1ryKkGmofFMXi" +
        "bZ5LUO/oK0iuNjBKfLdWoi+hpciKyPb9Bs8SO/svKSNqTEbn9ts3q6tpbngoECAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECGXQ07qiAqv2MBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBADKtN3OOaRdte0X4xLC6nTGaK/u7IEKQ0DjduDHwJR5w27zefrx48Z" +
        "dlq8t5lAfQJqWmfk7iCIW1QJPLcZOouWDP2S9Cb0YooGQRIEkMjpBn3Xufx0XUphtCDs3W" +
        "9LAMVXqfuce1tpZ6Dvrh6/H2X8rJMU29Czsz949bh6tcsHJi";
    public static final String Intermediate_CRL_RL_02_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wMi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIZdDTuqICq/YwDQYJKoZIhvcNAQEFBQADgYEAxrDH" +
        "zKno1mkJqPTub0c9To6jC3CGTilV1E12oD0kFjkXqL40+W251qQ2wMC+G7ZrzBIc5dRuJ9" +
        "3feHZ7cc03/s3TziXDvSyfNOYpHzkPwT48HuSgBYgJ3uswwk+tDiA64NzbOJqssxxhFRok" +
        "9OpwC8eQkzgpA3a6816v2I3XL9s=";
    public static final String End_Certificate_RL_02_01_crt = 
        "MIIChzCCAfCgAwIBAgICAK0wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDIuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjAyLjAxMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCykRGcIKuxia47yRmJT8XpNNi2LTTbUUTteIBp" +
        "DZBfz2ExeWLruO9Rn1/oB/EP+4apx4r9rQ2tGsvr/7qQYeQK8W7eJzZgvxFadY57IMfUNq" +
        "1nEnj0ZvuWrOSf+K9v6FWX5Y2uyZS5Uvb1VVQv0Ev890+yXTtthPTjepk3JkkouwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECFIkVrx7NRAdMBMGA1UdIwQMMAqACGXQ07qiAqv2MA0GCSqGSIb3DQEBBQUAA4GBAI+B" +
        "T6bFZruoeFHXsYVjkQ42jSdYB9JuQkG7JLKte5gGlhyR+jMlJBzxBgNIfvlmYSnbRFPbE8" +
        "eqsGm90hJJoUuVMkm0i03H13uddlS494O6HhTGpaKcYwp3hbLhVcaY3wFTqTCuZk1T7Oxq" +
        "ggTrCDYvNH+/ZpQuy6nB/FH3SAHS";
    public static final String[] TEST_64_DATA = new String[] {
        Intermediate_Certificate_RL_02_01_crt,
        Intermediate_CRL_RL_02_01_crl,
        End_Certificate_RL_02_01_crt
    };

    /*  
     *  test65
     *  
     */ 

    public static final String Intermediate_Certificate_1_RL_03_01_crt = 
        "MIICljCCAf+gAwIBAgICAK4wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wMy4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsZG8wsV3Kuo+jtnKxLYGBuAqQwUh6Cs7ioDTNUFI" +
        "UDDJ0lOP1HVTMBA7DEcyTCGvnQ02dEVVuCddBTQvG5RvW7G7cCEW37cS56/3yPsU1bD/cp" +
        "3C1pPJpoun04va91Sxtgcmx7jnz69QPVrucu6aI1sZyeOlvzb8K7DceaAfR98CAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECMNzJ3SpyOLxMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBABo7oKmQilgji3w1tGz1cMrWxZxqGJqOAKcHywli+oxFo2oxSfEuFS" +
        "tN2aEd2Ja5HU5a0ySztvByXF1TTNurGez7ARxmcS2kpoQtQXTloywza4A5N7iQwk0yyo/E" +
        "J4lrXUfVRwZHr7FwA7qMODtFb0+Zivv9JLaq19GhnRhzZyWp";
    public static final String Intermediate_Certificate_2_RL_03_01_crt = 
        "MIICljCCAf+gAwIBAgICAK8wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1STC4wMy4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt7yNq1QZsV3p7OR8rgPuY7x7Bvs+nPhcLR7zFOgR" +
        "+plQUwpWQ2PhuzReVV4jNasKtNK9MIWoeV+eV3pEiso5obb9+Byvha1F6gkYNZMPs9Iv86" +
        "cJSMtownNJVGVAL9FEpof1QKLp7kfn08EjkoGmGy85xy9uFytd2S8n5TlrBqcCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECAVwoCPFqMtqMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAL9GufFieduzBJaMtsXtKHMf64O/KAGLSh1YDXS+a7Ku+EFw+WteKU" +
        "Ob6+c1m7VH9P711eATQoACotCdKusPECqeYDEmT9keqA4f7cP4VcvGwhvSVQJsPuB3LL3S" +
        "LIILE4zhT+O9G+5v+mkG/pEDirRYk6ZkdM91bsUuzsX40uyn";
    public static final String Intermediate_CRL_RL_03_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1STC4wMy4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIBXCgI8Woy2owDQYJKoZIhvcNAQEFBQADgYEAkwyA" +
        "I1rrz6tOmEpBHDzuJfqY2nbXCIXFN6dVuaKNZWHJ4ZNIc4/t29Wa5GgXYrVXyXRcXP/u5k" +
        "NEhOX2/NwCm6vL8+tclYP5qPLrh/Dk4v3nvcTFLKCvclAbf4Il0zfMQx+RRnO5PPqPDu5i" +
        "1tHHwOtA8Q+oO71lZEwPE+pX1Sc=";
    public static final String End_Certificate_RL_03_01_crt = 
        "MIIChzCCAfCgAwIBAgICALAwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDMuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjAzLjAxMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPGLfi8/T5p63cbGE98mqO5VzkeI1r2/2TLgvY" +
        "RpL1h8i+CVYKoX37yYwNXf+HkHhj1OXJSNrm7853ctmDf2h1fv3f1+qJLg4VRVzlEgErNq" +
        "74OR7XLXV77kGOmhip2g5BF5VKeqAdj0pCo1E5ZFHpRPFq/0DDmSda6GKJ6Dl8hwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECOHM3uWxFmcrMBMGA1UdIwQMMAqACMNzJ3SpyOLxMA0GCSqGSIb3DQEBBQUAA4GBAFBu" +
        "doX0TZK/yoUcrSkP8AtFiv5c7QvyEtigFZTT+lbW/g4RX/oJGNZCu78yAxCczl+Z6ft+0V" +
        "wInwahjyyAgw4QXxtw3b9CfqvT7HH7hcQ6r9ZA/NA9XpzNtxKfmXjzCZWdfmLJrd8KCnU/" +
        "utKRAObRBKiaTGa178SEWvtkoIXd";
    public static final String[] TEST_65_DATA = new String[] {
        Intermediate_Certificate_1_RL_03_01_crt,
        Intermediate_Certificate_2_RL_03_01_crt,
        Intermediate_CRL_RL_03_01_crl,
        End_Certificate_RL_03_01_crt
    };

    /*  
     *  test66
     *  
     */ 

    public static final String Intermediate_Certificate_RL_03_02_crt = 
        "MIICljCCAf+gAwIBAgICALEwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wMy4wMjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAvoTuc2LYBOhziBe02f6F8l9MwX74O1lknBcJjGvq" +
        "JcirQx/6hQgBQT4hz4RRXNy7DSBr3swEw4eDNSeyd6kvG0h9oI3+SVmVyPPVi5eKDL1roI" +
        "OBzmfx1+Nn/CnwOf8VroKDutBBQ0gJ24IEjwp6er/8hEAVN/yIjIi/MTFeoRkCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECKtCUOlmMPu6MBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAI9x8O/JgJuZV/s4OBUy3AvcW9QP3HWWBQSdxUdjSosT2schjn7wrR" +
        "gttL7vWjT1djsbATAHa5C3inG+VjGIq/NqWaPoHAucRNMs4oZX2ACZFuBLOb/qhywsKh5+" +
        "bjv4QgtqkUedzEratY6yQiJSiMSJVJSMzHosTVMX7oOp+cll";
    public static final String Intermediate_CRL_RL_03_02_crl = 
        "MIIBcDCB2gIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wMi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWjAjMCECAg" +
        "CyFw05OTAxMDExMjAwMDBaMAwwCgYDVR0VBAMKAQGgIzAhMAoGA1UdFAQDAgEBMBMGA1Ud" +
        "IwQMMAqACKtCUOlmMPu6MA0GCSqGSIb3DQEBBQUAA4GBAAEZ0Hg6sKiVXIeK6zbQrKtMMz" +
        "Vz2K68+SqN1LAjlNW6u+HSTlAvhRIFO1Hv5Zj7qbO226rLxas/X2XWXpMlm84NHN8T4dZU" +
        "4Yo5rhhpCHckRxNYn3AFcfcV4ra1rrTtdx8e7e7/m0Ghog9Ny52ZuQThasL9caF0JxUx6d" +
        "zbBHPm";
    public static final String End_Certificate_RL_03_02_crt = 
        "MIIChzCCAfCgAwIBAgICALIwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDMuMDIwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjAzLjAyMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNb6HGPRDulLMCCyCq6w2X8rHPtm1gN68JXFkX" +
        "j/BZsHhu29Z9hXj76hO//7O775EPVMSLyRy8t15yzYpXfZRHFaGB5bs8U2R5ClvsD2FR0H" +
        "t0JVfU6Ggn1lhO+jOiguJtXVRjofsfvHuiOe75ctaJ9lBpgwiV8tk4VRKz2e5xVwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECI3Gy0TgXMrwMBMGA1UdIwQMMAqACKtCUOlmMPu6MA0GCSqGSIb3DQEBBQUAA4GBAISQ" +
        "Qh9+7D6nk3FL5YQOzyZ0BSHQYjpbIVykJ+Lr4jBPKyGgCqW6jqWNg7X4waB77J2z/OkavY" +
        "A6qtpsk8r2wmG9thi8JyZZNhYMxAszHzFbBmSoxGRMvI0XarxgIu8Ky6V7jKVDLz12C3o9" +
        "H0yd+nZXilCD+p9BTjjg5bGUogJS";
    public static final String[] TEST_66_DATA = new String[] {
        Intermediate_Certificate_RL_03_02_crt,
        Intermediate_CRL_RL_03_02_crl,
        End_Certificate_RL_03_02_crt
    };

    /*  
     *  test67
     *  
     */ 

    public static final String Intermediate_Certificate_RL_03_03_crt = 
        "MIICljCCAf+gAwIBAgICALMwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wMy4wMzCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAu/o0uxgTrAvNDrMNuG2eTla+AmkLVCIXBbsIo0gs" +
        "tLm29tLwfBh/8l5OC0y6Xeh5lx+NLdelsiZGRNaaWmWHj9Ji5V6rclr8sXRDUjxe12zLeh" +
        "0G+a0TfpL380cx9RItqQyA1ZRiUNymmJHnm13hwrf7LPirR9BMrtyTT2EI3cMCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECHYt39LYdEn0MBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAIoSGa7MxnOuHoWM/BoJKsCeBmBHYCYDKmQ19JfsDHW8z8oAFiikFb" +
        "Gtw1Qpc0GFfJgN0cppaXfe5lDS6BWL2dPorhu3URfXKu84ATLwGmNhqLDY7zh/zPvLtG2m" +
        "izaMLC6ZwZL5KELpYpcP15EHPDquyP1xpV3fT17GjpG9IH8k";
    public static final String Intermediate_CRL_1_RL_03_03_crl = 
        "MIIBcDCB2gIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wMi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWjAjMCECAg" +
        "C0Fw05OTAxMDExMjAwMDBaMAwwCgYDVR0VBAMKAQGgIzAhMAoGA1UdFAQDAgEBMBMGA1Ud" +
        "IwQMMAqACHYt39LYdEn0MA0GCSqGSIb3DQEBBQUAA4GBAI3HsXanos/N6uO3QVUaBZzmCt" +
        "w1HCHMrLVG614YlUQiEedQ/oEc7dwCeD1rUbGNVkFPIRvMkmUQo1klhKAlEUmrtW+aH+If" +
        "6oqumifqxvaycWidacbgNLIAMQtlQmniPF6Pq0dv8sNeKq4CE0gjRHOPJ2zIqy3kJ3tZYB" +
        "pTguwO";
    public static final String Intermediate_CRL_2_RL_03_03_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wMy4wMxcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIdi3f0th0SfQwDQYJKoZIhvcNAQEFBQADgYEAXZSZ" +
        "ySsD7U6ETy9ZRmiKUCJMUV9CIhCY0mEihHjW0DhFTyV1Hr01yN5zUr/IFVuP/Xcx36IX4l" +
        "dVv6/MgR1GeM/BUGZhm4z6YwfAosZ1N3zayIy/pP3fa1rVRl8cgCxc/8qxg9nH9p6yPpxM" +
        "AOOu6TLYquk/dA7wJPEW7MPixXY=";
    public static final String End_Certificate_RL_03_03_crt = 
        "MIIChzCCAfCgAwIBAgICALQwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDMuMDMwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjAzLjAzMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5LNxAB+lm514Hk2ykrFUb7fCX0ryIEMg0mgeT" +
        "/z8Iw7xisht57koK4PTXY863aunfNNh+8oFTHZnoLB5dbkROj1nFRgcWPezzv1wNkZEpxn" +
        "NINtTPBogW22NPznoZ/rSk9JRFe0sCOVazkW9tZbY2ARqyJsYU1ez5tQIkDS47kQIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECMWddsi+qmxKMBMGA1UdIwQMMAqACHYt39LYdEn0MA0GCSqGSIb3DQEBBQUAA4GBAAv8" +
        "nrJaqEycAyIKdPBYTUqaxjkv4SmonDDJG9OqvD78/o9hUKKteoMkNUp8eexTkWk0L72L4N" +
        "/eXB30+m65E841V+Dy8L4bXh15n4qz4cyMt8Kvm7nbCqcgpiyBJmBxzfaXDLSthlmhcJ4X" +
        "zDFnav1LEw5fZklt7cnMl4YvLD8d";
    public static final String[] TEST_67_DATA = new String[] {
        Intermediate_Certificate_RL_03_03_crt,
        Intermediate_CRL_1_RL_03_03_crl,
        Intermediate_CRL_2_RL_03_03_crl,
        End_Certificate_RL_03_03_crt
    };

    /*  
     *  test68
     *  
     */ 

    public static final String Intermediate_Certificate_1_RL_05_01_crt = 
        "MIICljCCAf+gAwIBAgICALUwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wNS4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA59vHTe5A9AcT237mW7HdSfh8Pu4P2wJNLT7RXczN" +
        "7DD/P6mAkugSgPTXwwlE1oSB/hCxAtEPhwONYZFYlRClFJidHDdVApalB7UbosTghsUzAg" +
        "Lqw7NL+w9i3Un2G7JM2oWwugozQn/1hzr2Cii2TIB6K0RWKoPBJvaWUURS/G8CAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECP55Cc4eBca8MBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBALX594y5uF4Rt7CoRHeKZ5h8QiG7mc+kQDMjaSU4KJwNVVL0mJatQG" +
        "w90yFfhvprlgDt9UIAvpF6z5gysbrjHXJaEhVlXeg9D5mcxsL4THEc8f6oU1GjfT/SOD9l" +
        "QrT/keX3D9lcFEaTOgi0HIZ7aFIJgoWjXF/9kNNMEAs8sJNI";
    public static final String Intermediate_Certificate_2_RL_05_01_crt = 
        "MIICljCCAf+gAwIBAgICALYwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDUuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1STC4wNS4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtl4hX6HlF0M+lSBTG8jHiB06hOy87LL81yAE2JQt" +
        "/6F+LZjuOBTCIc2yO2bVM3XzUnjyYDBYGnBFp/7XpRoiADuPJSfmkzmezpyJc+hm96UR1g" +
        "Bpo+pPKbRTWuM+FYy+vPtaDk5wKOrmyNx440PwbzxTN3JeWz17xeYE98bXMc0CAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECJOjtwEYV9VSMBMGA1UdIwQMMAqACP55Cc4eBca8MA0GCSqG" +
        "SIb3DQEBBQUAA4GBAFbkOffoIjWSfxEuKszoK7Fj27Hf5jlV92xqXtBLURjNGi9jCLUIUd" +
        "QLnONZLJYo70Z6XaGjpAK1EtZKVWsz11JDq5egE1zNES//9Tz8xDtJ7Lcq0mwneVFxmBuL" +
        "gxkw4GKbBFKz10FoSP7VJWaeW080WwKnp96Me5GtZRe260N1";
    public static final String Intermediate_CRL_1_RL_05_01_crl = 
        "MIIBhTCB7wIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wNS4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWjA4MDYCAg" +
        "C2Fw05OTAxMDExMjAwMDBaMCEwCgYDVR0VBAMKAQEwEwYJYIZIAWUCAQwCAQH/BAMCAQCg" +
        "IzAhMAoGA1UdFAQDAgEBMBMGA1UdIwQMMAqACP55Cc4eBca8MA0GCSqGSIb3DQEBBQUAA4" +
        "GBAIdOaBfpAEKWLrSvepVjk3UTfEfsSP6y+kFMl33YXy18xUvVpLarGu6YjQIpXiL+ulkP" +
        "eF8TAc9AarUjvDf0kcslIOt3NhdMxR4/F614Ds/rPEXs4c7n4kCkvAlFg/19iIFeCaynx3" +
        "X0s/v1SwzgAUHi3P+OwAGDApDTyKbnmzvt";
    public static final String Intermediate_CRL_2_RL_05_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1STC4wNS4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIk6O3ARhX1VIwDQYJKoZIhvcNAQEFBQADgYEAfOOd" +
        "JiLUCFSurAafQEBfxE9KVrgFC+W9m64cmERicO1QL9aDVIDGJAIY1pdvWVdhLBIKwSugwB" +
        "ZH3ToptY+VizvFN1gkKGL2OuvDsXPHn1+QgmqvxYFPmvwDcwuxZ/3zD1VeHgEIKo9ugRnW" +
        "F8G2Ph6SWUxJCjJQpB7WIbydowI=";
    public static final String End_Certificate_RL_05_01_crt = 
        "MIIChzCCAfCgAwIBAgICALcwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUkwuMDUuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjA1LjAxMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9NWkW/mia20c5gM3DpcTsBWTNC/d/Cob+OVrS" +
        "lYytMjK4htO3MavavMZNTLAYFCXWhZ+Uo/uiAF0ddE4HaFI418eKJMSSbQyed0TG5Udw/t" +
        "3dhYeLzLEmVc0r00q5v+CLINsCNQAKaPV71UvoHrE092zZjmtacuAetBS1Q2ufpwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECGNPOXdCLpZ3MBMGA1UdIwQMMAqACJOjtwEYV9VSMA0GCSqGSIb3DQEBBQUAA4GBALTo" +
        "hfBEPdzZ6A9QNStakOhmhHYox70xOPuWqzSbIugZv4chKXNQGiUAoOGImTw1mcun/uPNtd" +
        "0bT+O+a9yX5gzW55CSmR/teHkTkND1mJhOMuYOmaCaBHnqgIIe1iEhMZQgag70+/tSmmQm" +
        "UpWGpxeK2c02tBK6gEmnqk75bKRT";
    public static final String[] TEST_68_DATA = new String[] {
        Intermediate_Certificate_1_RL_05_01_crt,
        Intermediate_Certificate_2_RL_05_01_crt,
        Intermediate_CRL_1_RL_05_01_crl,
        Intermediate_CRL_2_RL_05_01_crl,
        End_Certificate_RL_05_01_crt
    };

    /*  
     *  test69
     *  
     */ 

    public static final String Intermediate_Certificate_RL_05_02_crt = 
        "MIICljCCAf+gAwIBAgICALgwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wNS4wMjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAouNcO1wHvKHPR15L7Fohr/QbTkPWGr9QYp2MXEDy" +
        "BRGHt63Ob+yNvsP/C74GJA+PzvcRELSnJxmBVbdRN5y/u4S6Zt4yTTcrvp4vl//luoGLOX" +
        "NHhCXbrGavyoP/iKpbfP7fy948AN34i95HuZENoGPjG5stX0uk12P087S2tPcCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECFi86MGPmMsXMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAFVZVMZEsaVuL0qX5Ls94+x8gBklxPfxgfG5LeBR2/YcqW+7BhsVA1" +
        "GQhjBtwqCU9SOL16oTrqgw2+YeWBjaYuNYVlxfdifd0pQydpE1iDQWxmoKLzSDmtWgRYhz" +
        "v0TB6j8q+0x5Q0OOrHX0jdIiBnHrLmReCK8dY1x6fb6I0tTH";
    public static final String Intermediate_CRL_RL_05_02_crl = 
        "MIIBhTCB7wIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wNS4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWjA4MDYCAg" +
        "C5Fw05OTAxMDExMjAwMDBaMCEwCgYDVR0VBAMKAQEwEwYJYIZIAWUCAQwCAQH/BAMCAQCg" +
        "IzAhMAoGA1UdFAQDAgEBMBMGA1UdIwQMMAqACFi86MGPmMsXMA0GCSqGSIb3DQEBBQUAA4" +
        "GBAFMN6PWjz2bA1RRySYNXde2rKiYkZYghbtT4ig2yDJBKOiPnjdx+jriFJxGYpt7BvcNx" +
        "cDfijmDZ1clzprIvz0lFO6IwsQiWtLxOz4Doj6K2AD+7IxuGLceaXmubvi4e6VVC3xXGsu" +
        "OYsNgFzsdUXIazi74+eOcj4dqrHAepbhXT";
    public static final String End_Certificate_RL_05_02_crt = 
        "MIIChzCCAfCgAwIBAgICALkwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDUuMDIwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjA1LjAyMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuWE1aFx3Zjk6gM0Wy6ijcUegbiGvhjBgqIGwv" +
        "YissT0v3KGAKoh5wGeKC+rePQNbZ91j4XDLvUNUdNw8HVNdNG/igIwsuaJ9teKSbqrAw9X" +
        "aD2YjJz/I6X6WXFd/eQ+g9lY3eidOXJkglYSwWMxUV62RUZbGyqjR1so+XpmYxCQIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECLLbuNyVkkK9MBMGA1UdIwQMMAqACFi86MGPmMsXMA0GCSqGSIb3DQEBBQUAA4GBACKt" +
        "GgxIRXYHZGZgwYHjNzquM1pUJTbxxm3qYA4U6r44oAo1UzQTDpHOalflreGFvG05l1BCnQ" +
        "olQ8rcXU25v/CDfyww7cl8l7IxjYz7PNht7R97vjfMVqqButbn+BmU6D5kR9YXDCDPzaQ5" +
        "DrKNk+3tIjJNj6YhxhqC2tPG9RIN";
    public static final String[] TEST_69_DATA = new String[] {
        Intermediate_Certificate_RL_05_02_crt,
        Intermediate_CRL_RL_05_02_crl,
        End_Certificate_RL_05_02_crt
    };

    /*  
     *  test70
     *  
     */ 

    public static final String Intermediate_Certificate_1_RL_06_01_crt = 
        "MIICljCCAf+gAwIBAgICALowDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wNi4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAmhxr4ckU5C3E57odZjgcxl46ZF2QVy+K86YoLOGT" +
        "mq34NSHTFxP93mrNqMYdFKFedUTNI68HkecFVvVKoXsDNBnhyyCTQ3xXhBcMUXFByB+55k" +
        "W5LeQ8l1G2ugsyZ7Z+P8uylrpeGJt4RjOTilhcI2mnfZ7S+arFGe4KYgnsaFUCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECOS4X3XqhyJYMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBALCPtNwXGxVSUNGErkBHSYCHyqlA55jKQQvZ4P0PznWEQ/gBJx34hq" +
        "LxiBO2G+iDomzHszeM77TXkQBpNxCUw26Jxv2HuvyBXuSprgjw5F1tvLqwsBAnD5vsb0uD" +
        "NrkKIzJSIBFQ1SRhuCObaXnamfPJHBmkP25t4QqEvoXMtVHB";
    public static final String Intermediate_Certificate_2_RL_06_01_crt = 
        "MIICljCCAf+gAwIBAgICALswDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDYuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMi1STC4wNi4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2IKrW6HDZJVFw3e4cC7v/jPGXAexI4B88707NhAc" +
        "qxSVfGTPJBdfWo5pkptZKN5/L5n6+rixLItHnei/uwBCHvhwzeEIGo1yVCgz6R2MoNB966" +
        "Q5CHWfT43BUjp0rZLJkK4hVKNyXB78NVv2Fly+XWBDEnzQvgVPWbGOvzE3zh0CAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECK/1z9Xbu2jGMBMGA1UdIwQMMAqACOS4X3XqhyJYMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAAa/MVC+8ozm9py40a4o/kHbkkmFNQr4s9yi3KXXuVxsNvquFMXm4a" +
        "gC8GPoNjvV+RPRmU8wOM6I2/PPl2JEQRb7NDM8LkY/m/Au4GHVeln6FKlldiRm0A+YIr19" +
        "ip2RHOldikAjUUYv7JT3SP34sjtq2e8bsXfWEPG5BA/wxtm7";
    public static final String Intermediate_CRL_1_RL_06_01_crl = 
        "MIIBhTCB7wIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wNi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWjAjMCECAg" +
        "C7Fw05OTAxMDExMjAwMDBaMAwwCgYDVR0VBAMKAQGgODA2MAoGA1UdFAQDAgEBMBMGCWCG" +
        "SAFlAgEMAgEB/wQDAgEAMBMGA1UdIwQMMAqACOS4X3XqhyJYMA0GCSqGSIb3DQEBBQUAA4" +
        "GBAJSexboWDaqLVY6iiWt8ZX5GwuNwDBN1R2TgM95H7JqjMgoWML887dKk24p4eKACFMWI" +
        "Ji9nwsqdZ/h1FtPhYpSoJ8l8vo4imMKr+tTnMngDNpMMZPQyRY1AK1jSrLhEtUdjiEtrTY" +
        "rG56RNt4YyUtNxxfkEymvwJxmO/4YcAz/l";
    public static final String Intermediate_CRL_2_RL_06_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMi1STC4wNi4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIr/XP1du7aMYwDQYJKoZIhvcNAQEFBQADgYEAImRg" +
        "n9A7px9exOJL4Se9jsSHzZ3sAd3y16LdAb+HLtYLl1swNB4KPE+OebtzEoYiSzVVwezdlm" +
        "5WseZjfbd0q01srZI4FeACZe99iBSpKymdKxw2gRvfYZ8ZMwFpK2mQq9cmygFn53iOwP7j" +
        "3KE+lllielu7sYyEnkliF9wsaG0=";
    public static final String End_Certificate_RL_06_01_crt = 
        "MIIChzCCAfCgAwIBAgICALwwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTItUkwuMDYuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjA2LjAxMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZVBNzD7LZW6mC2GSbVPjpcJ7sWISYsL2eHqXb" +
        "/PuxtbOneOjYqx0GeL9pxDGSSNl2NrlG0G1HTU2MaEOVA6h96W9e5ADV/pzGPMr97z+3BV" +
        "unxLX+ciM3T7rUQm/LueQTEC2Ww19T6QOg2i8rEadYT0OoW6OcvyuomemspxgClQIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECK5pHDrhL7xjMBMGA1UdIwQMMAqACK/1z9Xbu2jGMA0GCSqGSIb3DQEBBQUAA4GBAF3J" +
        "Kskjs4jp+BBoei9YWYtmOupn9w3oGyhknNh2jz7api5Gtgk2SyKfYFvN6EhWZJEab0hPFe" +
        "WuYwO7zNCLGHw0cFXT/R48ogd6JkH6xDwj4afZDkWVTu8oaVD4h1rTYS6WPRzizAozOzhi" +
        "tmIo+MV/lCG8+jdVtFgeKycI8aX7";
    public static final String[] TEST_70_DATA = new String[] {
        Intermediate_Certificate_1_RL_06_01_crt,
        Intermediate_Certificate_2_RL_06_01_crt,
        Intermediate_CRL_1_RL_06_01_crl,
        Intermediate_CRL_2_RL_06_01_crl,
        End_Certificate_RL_06_01_crt
    };

    /*  
     *  test71
     *  
     */ 

    public static final String Intermediate_Certificate_RL_06_02_crt = 
        "MIICljCCAf+gAwIBAgICAL0wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wNi4wMjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAxMlJ0vbkMRGzuEDTDGuPmwDzU1xn3dFDZ1Tx6ONP" +
        "fwNN5gk6r9kYl5TZ8f5TbkQSnOzyhDSqX8dGumCSgukETXtYBU2+KiIAtliu5NJRbXe3La" +
        "vn102HxaHDLGsR0FFLiFM9GVhOOXryJoXoGZqUwvqbWyaQQEzrV4RWmuOv7xMCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECFNaMo88Vb5MMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAJsjJG4/U1OWCJPB1u7UD3TPKRgOR9hT5l3LzFw5s0CEGt2Beg25LP" +
        "GEGcr0sEdosVQI5m5CuPolpmlQv0FkZv5M1W+uXX+F/6edtMDEquDpdR97ihQSLZjFFqjE" +
        "ytuaD4gqtL/BKBbz3e93mOmR9Wi+kWlXOYl0j8wpU9ePSjDV";
    public static final String Intermediate_CRL_RL_06_02_crl = 
        "MIIBhTCB7wIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wNi4wMhcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWjAjMCECAg" +
        "C+Fw05OTAxMDExMjAwMDBaMAwwCgYDVR0VBAMKAQGgODA2MAoGA1UdFAQDAgEBMBMGCWCG" +
        "SAFlAgEMAgEB/wQDAgEAMBMGA1UdIwQMMAqACFNaMo88Vb5MMA0GCSqGSIb3DQEBBQUAA4" +
        "GBAAKNj5xmtE7wzO1p5igiAmCDV6KuYsiPAQPHPEBlmo85vzvWv2hpEtmk4nDhehogl0QX" +
        "rhvRRqR+cPE5vBLB8mAStW+ZR6FXQPnmU5qGHqCQ4Wh6TWZesd7oyftoS7bJD5Xdf5ErA9" +
        "qijWoz8FgxZHVnAFmjA0rUINkdQ5JfE5oj";
    public static final String End_Certificate_RL_06_02_crt = 
        "MIIChzCCAfCgAwIBAgICAL4wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDYuMDIwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjA2LjAyMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD3UzwrnwKRlP00Pn49iI35S0wLn7c1I3rsmzdm" +
        "YFicetxHNeOKXLg1CN1bqkbAJ+N39fKjrkusqb2T+R3zhAV5LeLT4fzbHYdU7f4r6xgW2/" +
        "b2WLv+QVR+ldTsVxgPp/ZUgYi4/vAow4Q/6IT+zWtlawMBob/nLjVl+jQ9N4coFwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECPhq75noL+9WMBMGA1UdIwQMMAqACFNaMo88Vb5MMA0GCSqGSIb3DQEBBQUAA4GBAIU2" +
        "5bLX/NyDC8dKUxRwVn8oc3YPQjK0zXGdUr15Ib+cLdRyFVCuAyxVdpTf/csuga6tDhGuTL" +
        "B18mTE/fAjhUOiKiOLD6m4P77Nj67l2NTi86RimsI/Z6r5+bU31ahrls/7kr788+f4oEIY" +
        "TyOJecojsJUOG3qzK9J50iszclxg";
    public static final String[] TEST_71_DATA = new String[] {
        Intermediate_Certificate_RL_06_02_crt,
        Intermediate_CRL_RL_06_02_crl,
        End_Certificate_RL_06_02_crt
    };

    /*  
     *  test72
     *  
     */ 

    public static final String Intermediate_Certificate_RL_07_01_crt = 
        "MIICljCCAf+gAwIBAgICAL8wDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wNy4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAxjHxSRwJjEkLG9Al5uSQ22QI8N/hJ8hhkhh9qlaJ" +
        "mHusM8sWpAp2vnuumlThTA2zZbptXZ8Krb7i/Kpym4wo3ZkEThwi/ijsM5QCunQJmESRGD" +
        "yPZJjfhWjoC+lCjbmzsOGLMETpgSEMy+EyoXkRCnKmXcmCMS8HjLrqdnwiWBUCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECHPEkeIs8GuwMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBABCmgEnb8dfnG9lWQKT5BmQm459WqRQAiqdfqf9w0qRMuVrdfLMwqx" +
        "oq4uh10A3d+auHohgT2fT9RzNaWnRoNaH9K6qLQsdCUZdqjbEGdyiIFzvWP9MkV9nhDlo2" +
        "GgiU68HfnpKO/WA9EaRHyEzwT9o4SA7hAbz+3L12hB2WLSOg";
    public static final String Intermediate_CRL_RL_07_01_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wNy4wMRcNOTgwMTAxMDYwMTAwWhcNOTgwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIc8SR4izwa7AwDQYJKoZIhvcNAQEFBQADgYEAOyZr" +
        "f1tRnuzoq7dgQo+eOYhb5JyRyrNaSwNnRy82wOP+/G3NH8V3NGonDFOOcd9SoLTbeW4o71" +
        "vdOrKZgom5H2MZK5M4wTdfPAfXB1wBxOMzW5jXzsRtaha4l6EPI+GVL0eXN+aW3k/pscdA" +
        "ToI+OxTmRRnCYS6yW3qL9RoTIXQ=";
    public static final String End_Certificate_RL_07_01_crt = 
        "MIIChzCCAfCgAwIBAgICAMAwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDcuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjA3LjAxMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrm/Zem9Tt2UJFUKdAhTNwvhLo03uOax74ZgbV" +
        "YNTCpKeEWkV5d5d7DRC4mCTX1yjIlg6K4l7T+sRGI4XAcDRgYLuoyG1X958XCXSdIPTdbK" +
        "Hxs/tFv4mrCwi1kU+zjyzDoqgjT6kUxgM39rfcvDMH6qSzHQKgTFp7Tj/DHiELqwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECGFR8c6rRbhcMBMGA1UdIwQMMAqACHPEkeIs8GuwMA0GCSqGSIb3DQEBBQUAA4GBAANZ" +
        "TVR288mKpDDzm9XZMZ9+K1kPZ+eQYX+vUul11luVw27AIJGR8Fb4PIGl4+ALvqU3NQP/6v" +
        "d+zvS7IfiR6q7aLS3w111BUCgDhTJAp3oSo12qfcp+2DB1M9QfjrM9nKgmh5bBJigdJwJM" +
        "W8HHKStUMLdxg+qkZJgZpnyowCFM";
    public static final String[] TEST_72_DATA = new String[] {
        Intermediate_Certificate_RL_07_01_crt,
        Intermediate_CRL_RL_07_01_crl,
        End_Certificate_RL_07_01_crt
    };

    /*  
     *  test73
     *  
     */ 

    public static final String Intermediate_Certificate_RL_07_02_crt = 
        "MIICljCCAf+gAwIBAgICAMEwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNNTAwMTAxMDYwMDMwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wNy4wMjCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA0CvEneaAPtxZOTqlh/TXBM6V0bQgKbO58yEyURcO" +
        "Zi7jzYsmNtN9Tsr0wAlD41/ZONsW4MMzZ13UCc0aGa+eE8XRULBe5cgaGxJKwVnEqz3W8z" +
        "v1MjOk7Anb8TkxMSlWlptC6V3eRA85p5Id9gXbIrP3E3NuSfyx6246oLjNnbECAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECIb5Ia6wKcHtMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAAYEHQY+Z4qv4bYLmd+sz4aNGwZF7FT6ZIQ43OSeb+t+ibL7rZ0X0y" +
        "4SCTMs1mAB44IA6RFurmeCFk0ladRCn3A1xaVI1HlHen13ovzDA9ogL4CWbYXvCUv/znQY" +
        "yVSQCTKwT8iVam8xS1MsNCe408iVjhRfR6u9Hi31M+Pf+AUe";
    public static final String Intermediate_CRL_RL_07_02_crl = 
        "MIIBSzCBtQIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wNy4wMhcNNTAwMTAxMDYwMTAwWhcNNTAwMTAxMTIwMTAwWqAjMCEwCg" +
        "YDVR0UBAMCAQEwEwYDVR0jBAwwCoAIhvkhrrApwe0wDQYJKoZIhvcNAQEFBQADgYEALVUq" +
        "3Wq/Opvp9ifmQ4VXz4dgLNR+5Nz3muJ4RZt5R5b4R3RYllhgXNYw2EbEVCFjnfm97z73Ke" +
        "wzVV+fo/u5GbqJHN2cAVEHarOpasLxySktNA1Cwq5OTzUF0dYISqYbyBvVcaOQBvU/Lwj7" +
        "MQJJVVq96iDKnAJYBX03EHKbBeg=";
    public static final String End_Certificate_RL_07_02_crt = 
        "MIIChzCCAfCgAwIBAgICAMIwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDcuMDIwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjA3LjAyMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD6YgsbjW9IL7/SBORKssFUZBUxmluOpxJK/7d7" +
        "JA2pxbg7L96xHFPWN36CYDJzTscNpbGrD3G2MPkg4GqoTo0rU28NYVzj4SwqYoSLIbXB+r" +
        "SVgWcxNgbJ+4x9bK3YccNLR1PWEFxz1NckhCLBmb5pI4E34MCxQ6PvFO02I19FwQIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECIutV9ItCIbZMBMGA1UdIwQMMAqACIb5Ia6wKcHtMA0GCSqGSIb3DQEBBQUAA4GBALQE" +
        "cBr31h3jKUHcuf3yztr9NWUkGMDM0NCXHOpQl7JbV3P5BjvaiRYWlUrN7+92G8EaUFORto" +
        "zp8GG+d/MvFooVQOvpOzyhautYWyqq3AWpZLppnxNk1mRAdjUAvJaONtv37eLsma0bhtLM" +
        "j62sQQ6CdoKbMtIEGuJgpwWqHYwY";
    public static final String[] TEST_73_DATA = new String[] {
        Intermediate_Certificate_RL_07_02_crt,
        Intermediate_CRL_RL_07_02_crl,
        End_Certificate_RL_07_02_crt
    };

    /*  
     *  test74
     *  
     */ 

    public static final String Intermediate_Certificate_RL_07_03_crt = 
        "MIICljCCAf+gAwIBAgICAMMwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wNy4wMzCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEA8QzGjV0NVTNrOgkeqTkQFCOvl7M0qmjmYJjuw4R3" +
        "YfQIXDN0m9HR2JKp5WKTSUedmWviGS7NbGSzLR7+6OkLwSoxN9PkA/fMko7O0KWBfduhvn" +
        "jymlDMb2GPb1hBjScbq8fVJHwzqUm+BtEO2MXwXKYY2hZr+OEyEGhSEThp90MCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECFwl2XphEZRSMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAAb5GERgYVGuOb62gVZAAnhuk5K7CCkWZucOv6iI7pAgI6S7pvool/" +
        "dXHC0tzgQ+/MkuWcr+22k/ya7f+iSfiYokjnQkgoYFYk3PkjyOXA3mzs5qhF0nOP6Gvmz4" +
        "asONA+qZSqa4pjxF9Kn8L64f9yeyEXnckmbzdmbjAFCveQIP";
    public static final String Intermediate_CRL_RL_07_03_crl = 
        "MIIBTTCBtwIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wNy4wMxcNOTkwMTAxMDYwMTAwWhgPMjA1MDAxMDExMjAxMDBaoCMwIT" +
        "AKBgNVHRQEAwIBATATBgNVHSMEDDAKgAhcJdl6YRGUUjANBgkqhkiG9w0BAQUFAAOBgQAz" +
        "DMl8P16hylNkUEw4z9//PJFObNPZCYdmzBfp0K3tNRrOAouUVegyX0gDHi8O+bmmJNgcnC" +
        "tMRXx+D4qP7bx5fDS2MVQhSsncf6u4UZ8pxbRc0JmwR5oGZLPQabrctgmEmg8ZKGApKtsf" +
        "pGyvvTwaAzM+GaWXD68bBEN3VfVdeQ==";
    public static final String End_Certificate_RL_07_03_crt = 
        "MIIChzCCAfCgAwIBAgICAMQwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDcuMDMwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjA3LjAzMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDU6mec24uBaVip7fFWHas+o/lpZBOfj/IPHXQ9" +
        "QaRZwmJZBB81AX3BJ60DD12o/+RXdHl7B2Eh9kYv/QEXOKmyhJFSPa0Lv7MQ/hCIcL4m1U" +
        "FDGtJ3SUixZMqVBP0xjwXoNS88zzaCBL+co2TxhBrYMzeNQOX1eEkXMT4pvULmAwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECBBgFdYLuvk9MBMGA1UdIwQMMAqACFwl2XphEZRSMA0GCSqGSIb3DQEBBQUAA4GBAAof" +
        "dPOGa4ZxRPcLw6zWM/NLzF3XYDqXAsZBsC75r0GRrogqEYn07tVUDNaQczDtjRLBRNmxWE" +
        "+qCkJwc+wOBJqOFUxcuhK9oag6OE94+UIHdh3Td9i2ELZXj9RSNchnjyFohj5gk1dJSO41" +
        "86Ls3mCT9JcssR0dSxxkF0ENfZCG";
    public static final String[] TEST_74_DATA = new String[] {
        Intermediate_Certificate_RL_07_03_crt,
        Intermediate_CRL_RL_07_03_crl,
        End_Certificate_RL_07_03_crt
    };

    /*  
     *  test75
     *  
     */ 

    public static final String Intermediate_Certificate_RL_08_01_crt = 
        "MIICljCCAf+gAwIBAgICAMUwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wOC4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAs2YRTEl3C1TmmneJ6K110nSACn+KXxSOTGAGN5xv" +
        "XW751StpE2iEQIbRVPQdMzmcQX0bcg/WpdrewPQld9NRjFj7it+9YNQh7vMKhZwoAPoDmv" +
        "TnTdTEuV0c1FLVDVhiaAD9KMBa4fBLRfTKVzgzAr+oNqLhm3YBd2JWRHg+fA8CAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECB4we8+hIrkKMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBABTQI82uCMwQ4bgUWr9lawSI5DyWg3KY13F45rAlmKyckgne9SHbCH" +
        "+Lvm3XkkIqKmeHfJ3QTf7bpz6eErn3CxRrGm5JWblcYbVT+smjboJ9A0BXifqINYLy3qGc" +
        "AnNRkPq8OUREj2sU1qWKagUIgA/Vk2WyZhcUiApJPHI4fwv9";
    public static final String Intermediate_CRL_RL_08_01_crl = 
        "MIIBWjCBxAIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wOC4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqAyMDAwCg" +
        "YDVR0UBAMCAQEwDQYDVR0bAQH/BAMCAQEwEwYDVR0jBAwwCoAIHjB7z6EiuQowDQYJKoZI" +
        "hvcNAQEFBQADgYEAkjF0oERt5XW2i70gyspkEYIHyGCHnqngky5yuwQSRrlW7t0vGdKV7W" +
        "50evTeSVV41uhi1MBcccpx1MdRcB5vsatFSSKcKx4NF3PuHXxXCm2HkfXQy4K5zftE3jOZ" +
        "5s+yTHiw3s/QSErtHRca+TQcEZwamI+p402TEa6e82l6xHI=";
    public static final String End_Certificate_RL_08_01_crt = 
        "MIIChzCCAfCgAwIBAgICAMYwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDguMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjA4LjAxMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDfEMqWMqk3Rre5m4ILtQIz45JImvU379Al/S6t" +
        "2y/TzimJc4nhIKQp80VaZA/gwu/DcvMgJPM+FFz5U5rRkDaYASsc34tZUESF5LC6ZbtGqf" +
        "J96IKdajvkGLsHyI7dseuwaQ0FlOwcmKMSR898MGNNbKxaQNLEXsIFypRDsN6JhwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECMT22ARjB1ABMBMGA1UdIwQMMAqACB4we8+hIrkKMA0GCSqGSIb3DQEBBQUAA4GBAIaP" +
        "EqI7oHl/+h3MszG4VB1Va9NTN0kaysTyjQSVBi9jhOlPkzuXc2wI1bymBhatHEn6OrgP13" +
        "vsOiH2BiyudYcYjKpwI4FUiyKLIc0CXzM0VYFoMzb91QtsK1EnvAPDKNYVVFXrL7ABVIK4" +
        "hU6HfMMUbnpKWBxT5274iHScX8tL";
    public static final String[] TEST_75_DATA = new String[] {
        Intermediate_Certificate_RL_08_01_crt,
        Intermediate_CRL_RL_08_01_crl,
        End_Certificate_RL_08_01_crt
    };

    /*  
     *  test76
     *  
     */ 

    public static final String Intermediate_Certificate_RL_09_01_crt = 
        "MIICljCCAf+gAwIBAgICAMcwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9EMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxUcnVzdCBBbmNob3IwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNVBAMTDENBMS1STC4wOS4wMTCBnzANBg" +
        "kqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsvkvLv5fMFYvohaXO8a7GgU4rDHe9iL7LP1VeNUg" +
        "GIdJGqPEnuggQ/guhrBHafGh1NtmlEbmPJ4WQ99dBbPHHeO8sfCgkmWC0SqPODoI+t3qJE" +
        "kf2z9dWoAij15RXPliywZz+S6bTtcEQAREyBQ6M8/HJ83wRXp/uCpdPOSxVPkCAwEAAaNj" +
        "MGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0gBA8wDTALBglghk" +
        "gBZQMBMAEwEQYDVR0OBAoECISY4bvGMEBTMBMGA1UdIwQMMAqACKua6/nC51SPMA0GCSqG" +
        "SIb3DQEBBQUAA4GBAAd7g+dWso4V/Vr+QIoNLueCBAYWdOF+Yz3VeomcsDAs2V8E+xcZaq" +
        "jo2LrMygYCeMxVfXx/ZdhLPOaZ+ahNAbk+nWRwj35JdTNAAbMMWFdZUgR6N+uzx1v7i86p" +
        "AWUpRJ9IYPgUoQ5pmjdf3Ru1nrLfRt4yp+kNHWp6IL/+MwcM";
    public static final String Intermediate_CRL_RL_09_01_crl = 
        "MIIBXDCBxgIBATANBgkqhkiG9w0BAQUFADBeMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS" +
        "5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb2QxEDAOBgNVBAsTB1Rlc3RpbmcxFTATBgNV" +
        "BAMTDENBMS1STC4wOS4wMRcNOTkwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMTAwWqA0MDIwCg" +
        "YDVR0UBAMCAQEwDwYDVR0cAQH/BAUwA4IB/zATBgNVHSMEDDAKgAiEmOG7xjBAUzANBgkq" +
        "hkiG9w0BAQUFAAOBgQAKTXYgqlP+upFIwOSpdaVKDT8aqFzY9nSIsxHg5Wdl43U7p44LvQ" +
        "lW8XKhw74oQl1ExU5s7mDaEqB0JIozGzmoNyKsErgWKNW+lpKSxR5+1EHOB6Oo2KijpTsv" +
        "GFrHFCnF09f9JaTaMRIXOljx3rMO1UZsftKy/L9z3aUz8hQRnQ==";
    public static final String End_Certificate_RL_09_01_crt = 
        "MIIChzCCAfCgAwIBAgICAMgwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxGDAWBg" +
        "NVBAoTD1UuUy4gR292ZXJubWVudDEMMAoGA1UECxMDRG9kMRAwDgYDVQQLEwdUZXN0aW5n" +
        "MRUwEwYDVQQDEwxDQTEtUkwuMDkuMDEwHhcNOTgwMTAxMTIwMTAwWhcNNDgwMTAxMTIwMT" +
        "AwWjBgMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQL" +
        "EwNEb0QxEDAOBgNVBAsTB1Rlc3RpbmcxFzAVBgNVBAMTDlVzZXIxLVJMLjA5LjAxMIGfMA" +
        "0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDpz09VCXzAhH4/ifMk0RAzaBqJCXaHHqAdO/TW" +
        "6uvOVtl+fGvWXhXmSSCUfzg5xBqdUXrqcyxOME3vdgF1uOFZ4q2K6+Zuxmm+GCOCIpe+Gl" +
        "Jzqz4WKXG0iaXXQOYa56itNc/6Z6D/aAjNJavI19w0lmb9l6U2WBfn3LywxHp4dwIDAQAB" +
        "o1IwUDAOBgNVHQ8BAf8EBAMCBeAwFgYDVR0gBA8wDTALBglghkgBZQMBMAEwEQYDVR0OBA" +
        "oECOri1JgnJfLjMBMGA1UdIwQMMAqACISY4bvGMEBTMA0GCSqGSIb3DQEBBQUAA4GBADmV" +
        "Ee0xy25Z0HtmWwprKPjJDr/p7TgzbmNC58pUPkgtxnJFP4yrzNB9FQBWSfnjZpzQkLSU7i" +
        "7O6cf5HkqjQqoPErDnJLWgGzjbF80v2IIyZk7rEpAAM4MwjIk7hFvJK8QkTht9F4N1zj2X" +
        "0TQkmlbo9Z4SFj/3fsbl9h2GdKuU";
    public static final String[] TEST_76_DATA = new String[] {
        Intermediate_Certificate_RL_09_01_crt,
        Intermediate_CRL_RL_09_01_crl,
        End_Certificate_RL_09_01_crt
    };

}
