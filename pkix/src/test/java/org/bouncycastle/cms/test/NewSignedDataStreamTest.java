package org.bouncycastle.cms.test;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;

public class NewSignedDataStreamTest
    extends TestCase
{

    byte[] successResp = Base64.decode(
          "MIIFnAoBAKCCBZUwggWRBgkrBgEFBQcwAQEEggWCMIIFfjCCARehgZ8wgZwx"
        + "CzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEgcHJhZGVzaDESMBAGA1UE"
        + "BxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAKBgNVBAsTA0FUQzEeMBwG"
        + "A1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQwIgYJKoZIhvcNAQkBFhVv"
        + "Y3NwQHRjcy1jYS50Y3MuY28uaW4YDzIwMDMwNDAyMTIzNDU4WjBiMGAwOjAJ"
        + "BgUrDgMCGgUABBRs07IuoCWNmcEl1oHwIak1BPnX8QQUtGyl/iL9WJ1VxjxF"
        + "j0hAwJ/s1AcCAQKhERgPMjAwMjA4MjkwNzA5MjZaGA8yMDAzMDQwMjEyMzQ1"
        + "OFowDQYJKoZIhvcNAQEFBQADgYEAfbN0TCRFKdhsmvOdUoiJ+qvygGBzDxD/"
        + "VWhXYA+16AphHLIWNABR3CgHB3zWtdy2j7DJmQ/R7qKj7dUhWLSqclAiPgFt"
        + "QQ1YvSJAYfEIdyHkxv4NP0LSogxrumANcDyC9yt/W9yHjD2ICPBIqCsZLuLk"
        + "OHYi5DlwWe9Zm9VFwCGgggPMMIIDyDCCA8QwggKsoAMCAQICAQYwDQYJKoZI"
        + "hvcNAQEFBQAwgZQxFDASBgNVBAMTC1RDUy1DQSBPQ1NQMSYwJAYJKoZIhvcN"
        + "AQkBFhd0Y3MtY2FAdGNzLWNhLnRjcy5jby5pbjEMMAoGA1UEChMDVENTMQww"
        + "CgYDVQQLEwNBVEMxEjAQBgNVBAcTCUh5ZGVyYWJhZDEXMBUGA1UECBMOQW5k"
        + "aHJhIHByYWRlc2gxCzAJBgNVBAYTAklOMB4XDTAyMDgyOTA3MTE0M1oXDTAz"
        + "MDgyOTA3MTE0M1owgZwxCzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEg"
        + "cHJhZGVzaDESMBAGA1UEBxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAK"
        + "BgNVBAsTA0FUQzEeMBwGA1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQw"
        + "IgYJKoZIhvcNAQkBFhVvY3NwQHRjcy1jYS50Y3MuY28uaW4wgZ8wDQYJKoZI"
        + "hvcNAQEBBQADgY0AMIGJAoGBAM+XWW4caMRv46D7L6Bv8iwtKgmQu0SAybmF"
        + "RJiz12qXzdvTLt8C75OdgmUomxp0+gW/4XlTPUqOMQWv463aZRv9Ust4f8MH"
        + "EJh4ekP/NS9+d8vEO3P40ntQkmSMcFmtA9E1koUtQ3MSJlcs441JjbgUaVnm"
        + "jDmmniQnZY4bU3tVAgMBAAGjgZowgZcwDAYDVR0TAQH/BAIwADALBgNVHQ8E"
        + "BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwNgYIKwYBBQUHAQEEKjAoMCYG"
        + "CCsGAQUFBzABhhpodHRwOi8vMTcyLjE5LjQwLjExMDo3NzAwLzAtBgNVHR8E"
        + "JjAkMCKgIKAehhxodHRwOi8vMTcyLjE5LjQwLjExMC9jcmwuY3JsMA0GCSqG"
        + "SIb3DQEBBQUAA4IBAQB6FovM3B4VDDZ15o12gnADZsIk9fTAczLlcrmXLNN4"
        + "PgmqgnwF0Ymj3bD5SavDOXxbA65AZJ7rBNAguLUo+xVkgxmoBH7R2sBxjTCc"
        + "r07NEadxM3HQkt0aX5XYEl8eRoifwqYAI9h0ziZfTNes8elNfb3DoPPjqq6V"
        + "mMg0f0iMS4W8LjNPorjRB+kIosa1deAGPhq0eJ8yr0/s2QR2/WFD5P4aXc8I"
        + "KWleklnIImS3zqiPrq6tl2Bm8DZj7vXlTOwmraSQxUwzCKwYob1yGvNOUQTq"
        + "pG6jxn7jgDawHU1+WjWQe4Q34/pWeGLysxTraMa+Ug9kPe+jy/qRX2xwvKBZ");

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String TEST_MESSAGE = "Hello World!";
    private static String          _signDN;
    private static KeyPair         _signKP;
    private static X509Certificate _signCert;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;

    private static KeyPair         _origDsaKP;
    private static X509Certificate _origDsaCert;

    private static X509CRL         _signCrl;
    private static X509CRL         _origCrl;

    private static KeyPair         _signEd448KP;
    private static X509Certificate _signEd448Cert;

    private static boolean         _initialised = false;

    public NewSignedDataStreamTest(String name)
    {
        super(name);
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;

            if (Security.getProvider(BC) == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }

            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();  
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);
    
            _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);
    
            _origDsaKP   = CMSTestUtil.makeDsaKeyPair();
            _origDsaCert = CMSTestUtil.makeCertificate(_origDsaKP, _origDN, _signKP, _signDN);
            
            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _signCrl  = CMSTestUtil.makeCrl(_signKP);
            _origCrl  = CMSTestUtil.makeCrl(_origKP);

            _signEd448KP   = CMSTestUtil.makeEd448KeyPair();
            _signEd448Cert = CMSTestUtil.makeCertificate(_signEd448KP, _signDN, _origKP, _origDN);
        }
    }
    
    private void verifySignatures(CMSSignedDataParser sp, byte[] contentDigest) 
        throws Exception
    {
        Store               certStore = sp.getCertificates();
        Store               crlStore = sp.getCRLs();
        SignerInformationStore  signers = sp.getSignerInfos();

        Set digestIDs = new HashSet(sp.getDigestAlgorithmIDs());

        assertTrue(digestIDs.size() > 0);

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();
    
        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());
    
            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
    
            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));

            digestIDs.remove(signer.getDigestAlgorithmID());

            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }

        assertTrue(digestIDs.size() == 0);
        assertEquals(certStore.getMatches(null).size(), sp.getCertificates().getMatches(null).size());
        assertEquals(crlStore.getMatches(null).size(), sp.getCRLs().getMatches(null).size());
    }
    
    private void verifySignatures(CMSSignedDataParser sp) 
        throws Exception
    {
        verifySignatures(sp, null);
    }

    private void verifyEncodedData(ByteArrayOutputStream bOut)
        throws Exception
    {
        CMSSignedDataParser sp;
        sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        sp.close();
    }

    private void checkSigParseable(byte[] sig)
        throws Exception
    {
        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), sig);
        sp.getVersion();
        CMSTypedStream sc = sp.getSignedContent();
        if (sc != null)
        {
            sc.drain();
        }
        sp.getCertificates();
        sp.getCRLs();
        sp.getSignerInfos();
        sp.close();
    }

    public void testSha1EncapsulatedSignature()
        throws Exception
    {
        byte[]  encapSigData = Base64.decode(
                  "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEH"
                + "AaCAJIAEDEhlbGxvIFdvcmxkIQAAAAAAAKCCBGIwggINMIIBdqADAgECAgEF"
                + "MA0GCSqGSIb3DQEBBAUAMCUxFjAUBgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJ"
                + "BgNVBAYTAkFVMB4XDTA1MDgwNzA2MjU1OVoXDTA1MTExNTA2MjU1OVowJTEW"
                + "MBQGA1UEChMNQm91bmN5IENhc3RsZTELMAkGA1UEBhMCQVUwgZ8wDQYJKoZI"
                + "hvcNAQEBBQADgY0AMIGJAoGBAI1fZGgH9wgC3QiK6yluH6DlLDkXkxYYL+Qf"
                + "nVRszJVYl0LIxZdpb7WEbVpO8fwtEgFtoDsOdxyqh3dTBv+L7NVD/v46kdPt"
                + "xVkSNHRbutJVY8Xn4/TC/CDngqtbpbniMO8n0GiB6vs94gBT20M34j96O2IF"
                + "73feNHP+x8PkJ+dNAgMBAAGjTTBLMB0GA1UdDgQWBBQ3XUfEE6+D+t+LIJgK"
                + "ESSUE58eyzAfBgNVHSMEGDAWgBQ3XUfEE6+D+t+LIJgKESSUE58eyzAJBgNV"
                + "HRMEAjAAMA0GCSqGSIb3DQEBBAUAA4GBAFK3r1stYOeXYJOlOyNGDTWEhZ+a"
                + "OYdFeFaS6c+InjotHuFLAy+QsS8PslE48zYNFEqYygGfLhZDLlSnJ/LAUTqF"
                + "01vlp+Bgn/JYiJazwi5WiiOTf7Th6eNjHFKXS3hfSGPNPIOjvicAp3ce3ehs"
                + "uK0MxgLAaxievzhFfJcGSUMDMIICTTCCAbagAwIBAgIBBzANBgkqhkiG9w0B"
                + "AQQFADAlMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTAe"
                + "Fw0wNTA4MDcwNjI1NTlaFw0wNTExMTUwNjI1NTlaMGUxGDAWBgNVBAMTD0Vy"
                + "aWMgSC4gRWNoaWRuYTEkMCIGCSqGSIb3DQEJARYVZXJpY0Bib3VuY3ljYXN0"
                + "bGUub3JnMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTCB"
                + "nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgHCJyfwV6/V3kqSu2SOU2E/K"
                + "I+N0XohCMUaxPLLNtNBZ3ijxwaV6JGFz7siTgZD/OGfzir/eZimkt+L1iXQn"
                + "OAB+ZChivKvHtX+dFFC7Vq+E4Uy0Ftqc/wrGxE6DHb5BR0hprKH8wlDS8wSP"
                + "zxovgk4nH0ffUZOoDSuUgjh3gG8CAwEAAaNNMEswHQYDVR0OBBYEFLfY/4EG"
                + "mYrvJa7Cky+K9BJ7YmERMB8GA1UdIwQYMBaAFDddR8QTr4P634sgmAoRJJQT"
                + "nx7LMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEEBQADgYEADIOmpMd6UHdMjkyc"
                + "mIE1yiwfClCsGhCK9FigTg6U1G2FmkBwJIMWBlkeH15uvepsAncsgK+Cn3Zr"
                + "dZMb022mwtTJDtcaOM+SNeuCnjdowZ4i71Hf68siPm6sMlZkhz49rA0Yidoo"
                + "WuzYOO+dggzwDsMldSsvsDo/ARyCGOulDOAxggEvMIIBKwIBATAqMCUxFjAU"
                + "BgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJBgNVBAYTAkFVAgEHMAkGBSsOAwIa"
                + "BQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP"
                + "Fw0wNTA4MDcwNjI1NTlaMCMGCSqGSIb3DQEJBDEWBBQu973mCM5UBOl9XwQv"
                + "lfifHCMocTANBgkqhkiG9w0BAQEFAASBgGxnBl2qozYKLgZ0ygqSFgWcRGl1"
                + "LgNuE587LtO+EKkgoc3aFqEdjXlAyP8K7naRsvWnFrsB6pUpnrgI9Z8ZSKv8"
                + "98IlpsSSJ0jBlEb4gzzavwcBpYbr2ryOtDcF+kYmKIpScglyyoLzm+KPXOoT"
                + "n7MsJMoKN3Kd2Vzh6s10PFgeAAAAAAAA");

        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), encapSigData);

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }
    
    public void testSHA1WithRSANoAttributes()
        throws Exception
    {
        List         certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray(TEST_MESSAGE.getBytes());
    
        certList.add(_origCert);
        certList.add(_signCert);
    
        Store certs = new JcaCertStore(certList);
    
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        JcaSignerInfoGeneratorBuilder siBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        siBuilder.setDirectSignature(true);

        gen.addSignerInfoGenerator(siBuilder.build(sha1Signer, _origCert));
    
        gen.addCertificates(certs);
    
        CMSSignedData s = gen.generate(msg, false);

        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(),
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), s.getEncoded());
        
        sp.getSignedContent().drain();
        
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);
        
        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
    }
    
    public void testDSANoAttributes()
        throws Exception
    {
        List                certList = new ArrayList();
        CMSTypedData        msg = new CMSProcessableByteArray(TEST_MESSAGE.getBytes());
    
        certList.add(_origDsaCert);
        certList.add(_signCert);
    
        JcaCertStore          certs = new JcaCertStore(certList);
    
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        builder.setDirectSignature(true);

        gen.addSignerInfoGenerator(builder.build(new JcaContentSignerBuilder("SHA1withDSA").setProvider(BC).build(_origDsaKP.getPrivate()), _origDsaCert));
    
        gen.addCertificates(certs);
    
        CMSSignedData s = gen.generate(msg);
    
        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(),
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), s.getEncoded());
        
        sp.getSignedContent().drain();
        
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);
        
        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
    }
    
    public void testSHA1WithRSA()
        throws Exception
    {
        List                  certList = new ArrayList();
        List                  crlList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);

        crlList.add(_signCrl);
        crlList.add(_origCrl);

        Store           certs = new JcaCertStore(certList);
        Store           crls = new JcaCRLStore(crlList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));
    
        gen.addCertificates(certs);

        gen.addCRLs(crls);

        OutputStream sigOut = gen.open(bOut);
    
        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(),
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);
        
        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
        
        //
        // try using existing signer
        //
        gen = new CMSSignedDataStreamGenerator();
    
        gen.addSigners(sp.getSignerInfos());
        
        gen.addCertificates(sp.getCertificates());
        gen.addCRLs(sp.getCRLs());

        bOut.reset();
        
        sigOut = gen.open(bOut, true);
    
        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();
    
        verifyEncodedData(bOut);

        //
        // look for the CRLs
        //
        Collection col = sp.getCRLs().getMatches(null);

        assertEquals(2, col.size());
        assertTrue(col.contains(new JcaX509CRLHolder(_signCrl)));
        assertTrue(col.contains(new JcaX509CRLHolder(_origCrl)));
    }

    public void testSHA1WithRSAAndOtherRevocation()
        throws Exception
    {
        List                  certList = new ArrayList();
        CMSTypedData          msg = new CMSProcessableByteArray("Hello world!".getBytes());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        List otherInfo = new ArrayList();
        OCSPResp response = new OCSPResp(successResp);

        otherInfo.add(response.toASN1Structure());

        gen.addOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response, new CollectionStore(otherInfo));

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        CMSTypedStream stream = sp.getSignedContent();

        assertEquals(CMSObjectIdentifiers.data, stream.getContentType());

        stream.drain();

        //
        // check version
        //
        assertEquals(5, sp.getVersion());

        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);

        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));

        Store dataOtherInfo = sp.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);

        assertEquals(1, dataOtherInfo.getMatches(null).size());

        OCSPResp dataResponse = new OCSPResp(OCSPResponse.getInstance(dataOtherInfo.getMatches(null).iterator().next()));

        assertEquals(response, dataResponse);
    }

    public void testSHA1WithRSANonData()
        throws Exception
    {
        List                  certList = new ArrayList();
        List                  crlList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(new JcaX509CertificateHolder(_origCert));
        certList.add(new JcaX509CertificateHolder(_signCert));

        crlList.add(new JcaX509CRLHolder(_signCrl));
        crlList.add(new JcaX509CRLHolder(_origCrl));

        Store           certs = new JcaCertStore(certList);
        Store           crls = new JcaCRLStore(crlList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);
        gen.addCRLs(crls);

        OutputStream sigOut = gen.open(new ASN1ObjectIdentifier("1.2.3.4"), bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        CMSTypedStream stream = sp.getSignedContent();

        assertEquals(new ASN1ObjectIdentifier("1.2.3.4"), stream.getContentType());

        stream.drain();

        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);

        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
    }

    public void testSHA1AndMD5WithRSA()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);
    
        Store           certs = new JcaCertStore(certList);
    
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());
        ContentSigner md5Signer = new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(sha1Signer, _origCert));

        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(md5Signer, _origCert));
        
        gen.addCertificates(certs);
    
        OutputStream sigOut = gen.open(bOut);
    
        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(),
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        verifySignatures(sp);
    }
    
    public void testSHA1WithRSAEncapsulatedBufferedStream()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        //
        // find unbuffered length
        //
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, true);
        
        for (int i = 0; i != 2000; i++)
        {
            sigOut.write(i & 0xff);
        }
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        int unbufferedLength = bOut.toByteArray().length;
        
        //
        // find buffered length with buffered stream - should be equal
        //
        bOut = new ByteArrayOutputStream();

        gen = new CMSSignedDataStreamGenerator();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        sigOut = gen.open(bOut, true);

        BufferedOutputStream bfOut = new BufferedOutputStream(sigOut, 300);
        
        for (int i = 0; i != 2000; i++)
        {
            bfOut.write(i & 0xff);
        }
        
        bfOut.close();
        
        verifyEncodedData(bOut);
        
        assertTrue(bOut.toByteArray().length == unbufferedLength);
    }

    public void testSHA1WithRSAEncapsulatedBuffered()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);
    
        Store           certs = new JcaCertStore(certList);
    
        //
        // find unbuffered length
        //
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);
    
        OutputStream sigOut = gen.open(bOut, true);
        
        for (int i = 0; i != 2000; i++)
        {
            sigOut.write(i & 0xff);
        }
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        int unbufferedLength = bOut.toByteArray().length;
        
        //
        // find buffered length - buffer size less than default
        //
        bOut = new ByteArrayOutputStream();
    
        gen = new CMSSignedDataStreamGenerator();
        
        gen.setBufferSize(300);

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);
    
        sigOut = gen.open(bOut, true);
    
        for (int i = 0; i != 2000; i++)
        {
            sigOut.write(i & 0xff);
        }
        
        sigOut.close();
        
        verifyEncodedData(bOut);

        assertTrue(bOut.toByteArray().length > unbufferedLength);
    }
    
    public void testSHA1WithRSAEncapsulated()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(CMSAlgorithm.SHA1.getId());

        AttributeTable table = ((SignerInformation)sp.getSignerInfos().getSigners().iterator().next()).getSignedAttributes();
        Attribute hash = table.get(CMSAttributes.messageDigest);

        assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));

        //
        // try using existing signer
        //
        gen = new CMSSignedDataStreamGenerator();

        gen.addSigners(sp.getSignerInfos());
        
        gen.addCertificates(sp.getCertificates());
        
        bOut.reset();
        
        sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();

        CMSSignedData sd = new CMSSignedData(new CMSProcessableByteArray(TEST_MESSAGE.getBytes()), bOut.toByteArray());

        assertEquals(1, sd.getSignerInfos().getSigners().size());

        verifyEncodedData(bOut);
    }

    public void testEd448Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEd448KP, _signEd448Cert, "Ed448", false);
    }

    private void encapsulatedTest(
        KeyPair signaturePair,
        X509Certificate signatureCert,
        String signatureAlgorithm,
        boolean isDirect)
        throws Exception
    {
        List certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(signatureCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(signaturePair.getPrivate());

        gen.addSignerInfoGenerator(
            new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BC)
                    .build())
                .setDirectSignature(isDirect).build(signer, signatureCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);

        //
        // try using existing signer
        //
        gen = new CMSSignedDataStreamGenerator();

        gen.addSigners(sp.getSignerInfos());

        gen.addCertificates(sp.getCertificates());

        bOut.reset();

        sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedData sd = new CMSSignedData(new CMSProcessableByteArray(TEST_MESSAGE.getBytes()), bOut.toByteArray());

        assertEquals(1, sd.getSignerInfos().getSigners().size());

        verifyEncodedData(bOut);
    }

    public void testSHA1WithRSAEncapsulatedSubjectKeyID()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, CMSTestUtil.createSubjectKeyId(_origCert.getPublicKey()).getKeyIdentifier()));
        
        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);

        byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(CMSAlgorithm.SHA1.getId());

        AttributeTable table = ((SignerInformation)sp.getSignerInfos().getSigners().iterator().next()).getSignedAttributes();
        Attribute hash = table.get(CMSAttributes.messageDigest);

        assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));

        //
        // try using existing signer
        //
        gen = new CMSSignedDataStreamGenerator();

        gen.addSigners(sp.getSignerInfos());

        gen.addCertificates(sp.getCertificates());

        bOut.reset();

        sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedData sd = new CMSSignedData(new CMSProcessableByteArray(TEST_MESSAGE.getBytes()), bOut.toByteArray());

        assertEquals(1, sd.getSignerInfos().getSigners().size());

        verifyEncodedData(bOut);
    }

    public void testAttributeGenerators()
        throws Exception
    {
        final ASN1ObjectIdentifier dummyOid1 = new ASN1ObjectIdentifier("1.2.3");
        final ASN1ObjectIdentifier dummyOid2 = new ASN1ObjectIdentifier("1.2.3.4");
        List                      certList = new ArrayList();
        ByteArrayOutputStream     bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        JcaCertStore           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        CMSAttributeTableGenerator signedGen = new DefaultSignedAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
            {
                Hashtable table = createStandardAttributeTable(parameters);

                DEROctetString val = new DEROctetString((byte[])parameters.get(CMSAttributeTableGenerator.DIGEST));
                Attribute attr = new Attribute(dummyOid1, new DERSet(val));

                table.put(attr.getAttrType(), attr);

                return new AttributeTable(table);
            }
        };

        CMSAttributeTableGenerator unsignedGen = new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
            {
                DEROctetString val = new DEROctetString((byte[])parameters.get(CMSAttributeTableGenerator.SIGNATURE));
                Attribute attr = new Attribute(dummyOid2, new DERSet(val));

                return new AttributeTable(new DERSet(attr));
            }
        };
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        JcaSignerInfoGeneratorBuilder siBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        siBuilder.setSignedAttributeGenerator(signedGen).setUnsignedAttributeGenerator(unsignedGen);

        gen.addSignerInfoGenerator(siBuilder.build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);

        //
        // check attributes
        //
        SignerInformationStore  signers = sp.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            checkAttribute(signer.getContentDigest(), signer.getSignedAttributes().get(dummyOid1));
            checkAttribute(signer.getSignature(), signer.getUnsignedAttributes().get(dummyOid2));
        }
    }

    private void checkAttribute(byte[] expected, Attribute attr)
    {
        DEROctetString      value = (DEROctetString)attr.getAttrValues().getObjectAt(0);

        assertEquals(new DEROctetString(expected), value);
    }

    public void testWithAttributeCertificate()
        throws Exception
    {
        List                  certList = new ArrayList();

        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha1Signer, _origCert));

        gen.addCertificates(certs);

        X509AttributeCertificateHolder attrCert = CMSTestUtil.getAttributeCertificate();

        Store store = new CollectionStore(Collections.singleton(attrCert));

        gen.addAttributeCertificates(store);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        sp.getSignedContent().drain();

        assertEquals(4, sp.getVersion());

        store = sp.getAttributeCertificates();

        Collection coll = store.getMatches(null);

        assertEquals(1, coll.size());

        assertTrue(coll.contains(attrCert));
    }

    public void testSignerStoreReplacement()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[]                data = TEST_MESSAGE.getBytes();

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, false);

        sigOut.write(data);

        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        //
        // create new Signer
        //
        ByteArrayInputStream  original = new ByteArrayInputStream(bOut.toByteArray());

        bOut.reset();

        gen = new CMSSignedDataStreamGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA224withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        sigOut = gen.open(bOut);

        sigOut.write(data);

        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        CMSSignedData sd = new CMSSignedData(bOut.toByteArray());

        //
        // replace signer
        //
        ByteArrayOutputStream newOut = new ByteArrayOutputStream();

        CMSSignedDataParser.replaceSigners(original, sd.getSignerInfos(), newOut);

        sd = new CMSSignedData(new CMSProcessableByteArray(data), newOut.toByteArray());
        SignerInformation signer = (SignerInformation)sd.getSignerInfos().getSigners().iterator().next();

        assertEquals(signer.getDigestAlgOID(), CMSAlgorithm.SHA224.getId());

        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), new CMSTypedStream(new ByteArrayInputStream(data)), newOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }

    public void testEncapsulatedSignerStoreReplacement()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        //
        // create new Signer
        //
        ByteArrayInputStream  original = new ByteArrayInputStream(bOut.toByteArray());

        bOut.reset();

        gen = new CMSSignedDataStreamGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA224withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedData sd = new CMSSignedData(bOut.toByteArray());

        //
        // replace signer
        //
        ByteArrayOutputStream newOut = new ByteArrayOutputStream();

        CMSSignedDataParser.replaceSigners(original, sd.getSignerInfos(), newOut);

        sd = new CMSSignedData(newOut.toByteArray());
        SignerInformation signer = (SignerInformation)sd.getSignerInfos().getSigners().iterator().next();

        assertEquals(signer.getDigestAlgOID(), CMSAlgorithm.SHA224.getId());

        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), newOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }

    public void testCertStoreReplacement()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[]                data = TEST_MESSAGE.getBytes();

        certList.add(_origDsaCert);

        JcaCertStore           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        gen.addSignerInfoGenerator(builder.build(new JcaContentSignerBuilder("SHA1withRSA").build(_origKP.getPrivate()), _origCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut);

        sigOut.write(data);

        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        //
        // create new certstore with the right certificates
        //
        certList = new ArrayList();
        certList.add(_origCert);
        certList.add(_signCert);

        certs = new JcaCertStore(certList);


        //
        // replace certs
        //
        ByteArrayInputStream original = new ByteArrayInputStream(bOut.toByteArray());
        ByteArrayOutputStream newOut = new ByteArrayOutputStream();

        CMSSignedDataParser.replaceCertificatesAndCRLs(original, certs, null, null, newOut);

        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), new CMSTypedStream(new ByteArrayInputStream(data)), newOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }

    public void testEncapsulatedCertStoreReplacement()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origDsaCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        gen.addSignerInfoGenerator(builder.build(new JcaContentSignerBuilder("SHA1withRSA").build(_origKP.getPrivate()), _origCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        //
        // create new certstore with the right certificates
        //
        certList = new ArrayList();
        certList.add(_origCert);
        certList.add(_signCert);

        certs = new JcaCertStore(certList);

        //
        // replace certs
        //
        ByteArrayInputStream original = new ByteArrayInputStream(bOut.toByteArray());
        ByteArrayOutputStream newOut = new ByteArrayOutputStream();

        CMSSignedDataParser.replaceCertificatesAndCRLs(original, certs, null, null, newOut);

        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), newOut.toByteArray());

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }

    public void testCertOrdering1()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        sp.getSignedContent().drain();
        certs = sp.getCertificates();
        Iterator it = certs.getMatches(null).iterator();

        assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signCert), it.next());
    }

    public void testCertOrdering2()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_signCert);
        certList.add(_origCert);

        Store           certs = new JcaCertStore(certList);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), bOut.toByteArray());

        sp.getSignedContent().drain();
        certs = sp.getCertificates();
        Iterator it = certs.getMatches(null).iterator();

        assertEquals(new JcaX509CertificateHolder(_signCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
    }

    public void testCertsOnly()
        throws Exception
    {
        List certList = new ArrayList();
        certList.add(_origCert);
        certList.add(_signCert);
    
        Store certs = new JcaCertStore(certList);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
        gen.addCertificates(certs);

        gen.open(bOut).close();

        checkSigParseable(bOut.toByteArray());
    }

    public void testMSPKCS7()
        throws Exception
    {
        byte[] data = getInput("SignedMSPkcs7.sig");

        CMSSignedDataParser sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), data);

        sp.getSignedContent().drain();

        Store certStore = sp.getCertificates();
        SignerInformationStore signers = sp.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
        }
    }

    private byte[] getInput(String name)
        throws IOException
    {
        return Streams.readAll(getClass().getResourceAsStream(name));
    }

    public static Test suite()
        throws Exception
    {
        init();
        
        return new CMSTestSetup(new TestSuite(NewSignedDataStreamTest.class));
    }
}
