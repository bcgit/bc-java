package org.bouncycastle.tsp.test;

import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SimpleTimeZone;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

public class NewTSPTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testGeneral()
        throws Exception
    {
        String signDN = "O=Bouncy Castle, C=AU";
        KeyPair signKP = TSPTestUtil.makeKeyPair();
        X509Certificate signCert = TSPTestUtil.makeCACertificate(signKP,
            signDN, signKP, signDN);

        String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        KeyPair origKP = TSPTestUtil.makeKeyPair();
        X509Certificate origCert = TSPTestUtil.makeCertificate(origKP,
            origDN, signKP, signDN);


        List certList = new ArrayList();
        certList.add(origCert);
        certList.add(signCert);

        Store certs = new JcaCertStore(certList);

        basicTest(origKP.getPrivate(), origCert, certs);
        resolutionTest(origKP.getPrivate(), origCert, certs, TimeStampTokenGenerator.R_SECONDS, "19700101000009Z");
        resolutionTest(origKP.getPrivate(), origCert, certs, TimeStampTokenGenerator.R_TENTHS_OF_SECONDS, "19700101000009.9Z");
        resolutionTest(origKP.getPrivate(), origCert, certs, TimeStampTokenGenerator.R_HUNDREDTHS_OF_SECONDS, "19700101000009.99Z");
        resolutionTest(origKP.getPrivate(), origCert, certs, TimeStampTokenGenerator.R_MILLISECONDS, "19700101000009.999Z");
        basicSha256Test(origKP.getPrivate(), origCert, certs);
        basicTestWithTSA(origKP.getPrivate(), origCert, certs);
        overrideAttrsTest(origKP.getPrivate(), origCert, certs);
        responseValidationTest(origKP.getPrivate(), origCert, certs);
        incorrectHashTest(origKP.getPrivate(), origCert, certs);
        badAlgorithmTest(origKP.getPrivate(), origCert, certs);
        timeNotAvailableTest(origKP.getPrivate(), origCert, certs);
        badPolicyTest(origKP.getPrivate(), origCert, certs);
        tokenEncodingTest(origKP.getPrivate(), origCert, certs);
        certReqTest(origKP.getPrivate(), origCert, certs);
        testAccuracyZeroCerts(origKP.getPrivate(), origCert, certs);
        testAccuracyWithCertsAndOrdering(origKP.getPrivate(), origCert, certs);
        testNoNonse(origKP.getPrivate(), origCert, certs);
        extensionTest(origKP.getPrivate(), origCert, certs);
        additionalExtensionTest(origKP.getPrivate(), origCert, certs);
    }

    public void testCertOrdering()
        throws Exception
    {
        List            certList = new ArrayList();

        String _origDN   = "O=Bouncy Castle, C=AU";
        KeyPair _origKP   = CMSTestUtil.makeKeyPair();
        X509Certificate _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

        String _signDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
        KeyPair _signKP   = CMSTestUtil.makeKeyPair();
        X509Certificate _signCert = TSPTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

        KeyPair _signDsaKP   = CMSTestUtil.makeDsaKeyPair();
        X509Certificate _signDsaCert = CMSTestUtil.makeCertificate(_signDsaKP, _signDN, _origKP, _origDN);

        certList.add(_origCert);
        certList.add(_signDsaCert);
        certList.add(_signCert);

        Store      certs = new JcaCertStore(certList);

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", _signKP.getPrivate(), _signCert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        
        reqGen.setCertReq(true);

        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse initResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), new Date());

        // original CMS SignedData object
        CMSSignedData sd = initResp.getTimeStampToken().toCMSSignedData();

        certs = sd.getCertificates();
        Iterator it = certs.getMatches(null).iterator();

        assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signDsaCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signCert), it.next());

        // definite-length
        TimeStampResponse dlResp = new TimeStampResponse(initResp.getEncoded(ASN1Encoding.DL));

        sd = dlResp.getTimeStampToken().toCMSSignedData();

        certs = sd.getCertificates();
        it = certs.getMatches(null).iterator();

        assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signDsaCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signCert), it.next());

        // convert to DER - the default encoding
        TimeStampResponse derResp = new TimeStampResponse(initResp.getEncoded());

        sd = derResp.getTimeStampToken().toCMSSignedData();

        certs = sd.getCertificates();
        it = certs.getMatches(null).iterator();

        assertEquals(new JcaX509CertificateHolder(_origCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signCert), it.next());
        assertEquals(new JcaX509CertificateHolder(_signDsaCert), it.next());
    }

    private void basicTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificate));
    }

    public void testSM2withSM3()
        throws Exception
    {
        //
         // set up the keys
         //
         PrivateKey privKey;
         PublicKey pubKey;

         try
         {
             KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

             g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

             KeyPair p = g.generateKeyPair();

             privKey = p.getPrivate();
             pubKey = p.getPublic();
         }
         catch (Exception e)
         {
             fail("error setting up keys - " + e.toString());
             return;
         }

        //
        // extensions
        //

        //
        // create the certificate - version 1
        //

        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider(BC).build(privKey);
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name("CN=Test"),
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000),
            new Date(System.currentTimeMillis() + 50000),
            new X500Name("CN=Test"),
            pubKey);

        certGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().build("SM3withSM2", privKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

       // tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SM3, new byte[32], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificate));
    }

    private void resolutionTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs,
        int   resolution,
        String timeString)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        tsTokenGen.setResolution(resolution);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(9999L));

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");

        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));

        assertEquals(timeString, tsToken.getTimeStampInfo().toASN1Structure().getGenTime().getTimeString());

        // test zero truncation
        tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(9000L));
        tsToken = tsResp.getTimeStampToken();

        assertEquals("19700101000009Z", tsToken.getTimeStampInfo().toASN1Structure().getGenTime().getTimeString());

        if (resolution > TimeStampTokenGenerator.R_HUNDREDTHS_OF_SECONDS)
        {
            tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(9990L));
            tsToken = tsResp.getTimeStampToken();

            assertEquals("19700101000009.99Z", tsToken.getTimeStampInfo().toASN1Structure().getGenTime().getTimeString());
        }
        if (resolution > TimeStampTokenGenerator.R_TENTHS_OF_SECONDS)
        {
            tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(9900L));
            tsToken = tsResp.getTimeStampToken();

            assertEquals("19700101000009.9Z", tsToken.getTimeStampInfo().toASN1Structure().getGenTime().getTimeString());
        }
    }

    private void basicSha256Test(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", privateKey, cert), new SHA256DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        assertEquals(PKIStatus.GRANTED, tsResp.getStatus());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2));

        DigestCalculator digCalc = new SHA256DigestCalculator();

        OutputStream dOut = digCalc.getOutputStream();

        dOut.write(cert.getEncoded());

        dOut.close();

        byte[] certHash = digCalc.getDigest();

        SigningCertificateV2 sigCertV2 = SigningCertificateV2.getInstance(table.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2).getAttributeValues()[0]);

        assertTrue(Arrays.areEqual(certHash, sigCertV2.getCerts()[0].getCertHash()));
    }

    private void overrideAttrsTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSimpleSignerInfoGeneratorBuilder signerInfoGenBuilder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC");

        IssuerSerial issuerSerial = new IssuerSerial(new GeneralNames(new GeneralName(new X509CertificateHolder(cert.getEncoded()).getIssuer())), cert.getSerialNumber());

        DigestCalculator digCalc = new SHA1DigestCalculator();

        OutputStream dOut = digCalc.getOutputStream();

        dOut.write(cert.getEncoded());

        dOut.close();

        byte[] certHash = digCalc.getDigest();

        digCalc = new SHA256DigestCalculator();

        dOut = digCalc.getOutputStream();

        dOut.write(cert.getEncoded());

        dOut.close();

        byte[] certHash256 = digCalc.getDigest();

        final ESSCertID essCertid = new ESSCertID(certHash, issuerSerial);
        final ESSCertIDv2 essCertidV2 = new ESSCertIDv2(certHash256, issuerSerial);

        signerInfoGenBuilder.setSignedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                CMSAttributeTableGenerator attrGen = new DefaultSignedAttributeTableGenerator();

                AttributeTable table = attrGen.getAttributes(parameters);
                table = table.add(PKCSObjectIdentifiers.id_aa_signingCertificate, new SigningCertificate(essCertid));
                table = table.add(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new SigningCertificateV2(new ESSCertIDv2[]{essCertidV2}));

                return table;
            }
        });

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(signerInfoGenBuilder.build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificate));
        assertNotNull("no signingCertificateV2 attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2));

        SigningCertificate sigCert = SigningCertificate.getInstance(table.get(PKCSObjectIdentifiers.id_aa_signingCertificate).getAttributeValues()[0]);

        assertEquals(new X509CertificateHolder(cert.getEncoded()).getIssuer(), sigCert.getCerts()[0].getIssuerSerial().getIssuer().getNames()[0].getName());
        assertEquals(cert.getSerialNumber(), sigCert.getCerts()[0].getIssuerSerial().getSerial().getValue());
        assertTrue(Arrays.areEqual(certHash, sigCert.getCerts()[0].getCertHash()));

        SigningCertificateV2 sigCertV2 = SigningCertificateV2.getInstance(table.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2).getAttributeValues()[0]);

        assertEquals(new X509CertificateHolder(cert.getEncoded()).getIssuer(), sigCertV2.getCerts()[0].getIssuerSerial().getIssuer().getNames()[0].getName());
        assertEquals(cert.getSerialNumber(), sigCertV2.getCerts()[0].getIssuerSerial().getSerial().getValue());
        assertTrue(Arrays.areEqual(certHash256, sigCertV2.getCerts()[0].getCertHash()));
    }

    private void basicTestWithTSA(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);
        tsTokenGen.setTSA(new GeneralName(new X500Name("CN=Test")));

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificate));
    }

    private void additionalExtensionTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);
        tsTokenGen.setTSA(new GeneralName(new X500Name("CN=Test")));

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.auditIdentity, false, new DERUTF8String("Test"));

        TimeStampResponse tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), new Date(), "Okay", extGen.generate());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificate));

        Extensions ext = tsToken.getTimeStampInfo().getExtensions();

        assertEquals(1, ext.getExtensionOIDs().length);
        assertEquals(new Extension(Extension.auditIdentity, false, new DERUTF8String("Test").getEncoded()), ext.getExtension(Extension.auditIdentity));
    }

    private void responseValidationTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));

        //
        // check validation
        //
        tsResp.validate(request);

        try
        {
            request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(101));

            tsResp.validate(request);

            fail("response validation failed on invalid nonce.");
        }
        catch (TSPValidationException e)
        {
            // ignore
        }

        try
        {
            request = reqGen.generate(TSPAlgorithms.SHA1, new byte[22], BigInteger.valueOf(100));

            tsResp.validate(request);

            fail("response validation failed on wrong digest.");
        }
        catch (TSPValidationException e)
        {
            // ignore
        }

        try
        {
            request = reqGen.generate(TSPAlgorithms.MD5, new byte[20], BigInteger.valueOf(100));

            tsResp.validate(request);

            fail("response validation failed on wrong digest.");
        }
        catch (TSPValidationException e)
        {
            // ignore
        }
    }

    private void incorrectHashTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[16]);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        if (tsToken != null)
        {
            fail("incorrectHash - token not null.");
        }

        PKIFailureInfo failInfo = tsResp.getFailInfo();

        if (failInfo == null)
        {
            fail("incorrectHash - failInfo set to null.");
        }

        if (failInfo.intValue() != PKIFailureInfo.badDataFormat)
        {
            fail("incorrectHash - wrong failure info returned.");
        }
    }

    private void badAlgorithmTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSimpleSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC);

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(new ASN1ObjectIdentifier("1.2.3.4.5"), new byte[20]);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        if (tsToken != null)
        {
            fail("badAlgorithm - token not null.");
        }

        PKIFailureInfo failInfo = tsResp.getFailInfo();

        if (failInfo == null)
        {
            fail("badAlgorithm - failInfo set to null.");
        }

        if (failInfo.intValue() != PKIFailureInfo.badAlg)
        {
            fail("badAlgorithm - wrong failure info returned.");
        }
    }

    private void timeNotAvailableTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(new ASN1ObjectIdentifier("1.2.3.4.5"), new byte[20]);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp;

        try
        {
            tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), null);
        }
        catch (TSPException e)
        {
            tsResp = tsRespGen.generateRejectedResponse(e);
        }

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        if (tsToken != null)
        {
            fail("timeNotAvailable - token not null.");
        }

        PKIFailureInfo failInfo = tsResp.getFailInfo();

        if (failInfo == null)
        {
            fail("timeNotAvailable - failInfo set to null.");
        }

        if (failInfo.intValue() != PKIFailureInfo.timeNotAvailable)
        {
            fail("timeNotAvailable - wrong failure info returned.");
        }
    }

    private void badPolicyTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

        reqGen.setReqPolicy(new ASN1ObjectIdentifier("1.1"));

        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20]);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED, new HashSet());

        TimeStampResponse tsResp;

        try
        {
            tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), new Date());
        }
        catch (TSPException e)
        {
            tsResp = tsRespGen.generateRejectedResponse(e);
        }

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        if (tsToken != null)
        {
            fail("badPolicy - token not null.");
        }

        PKIFailureInfo failInfo = tsResp.getFailInfo();

        if (failInfo == null)
        {
            fail("badPolicy - failInfo set to null.");
        }

        if (failInfo.intValue() != PKIFailureInfo.unacceptedPolicy)
        {
            fail("badPolicy - wrong failure info returned.");
        }
    }

    private void certReqTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

        //
        // request with certReq false
        //
        reqGen.setCertReq(false);

        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        assertNull(tsToken.getTimeStampInfo().getGenTimeAccuracy());  // check for abscence of accuracy

        assertEquals("1.2", tsToken.getTimeStampInfo().getPolicy().getId());

        try
        {
            tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));
        }
        catch (TSPValidationException e)
        {
            fail("certReq(false) verification of token failed.");
        }

        Store respCerts = tsToken.getCertificates();

        Collection certsColl = respCerts.getMatches(null);

        if (!certsColl.isEmpty())
        {
            fail("certReq(false) found certificates in response.");
        }
    }


    private void tokenEncodingTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3.4.5.6"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);
        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampResponse tsResponse = new TimeStampResponse(tsResp.getEncoded());

        if (!Arrays.areEqual(tsResponse.getEncoded(), tsResp.getEncoded())
            || !Arrays.areEqual(tsResponse.getTimeStampToken().getEncoded(),
            tsResp.getTimeStampToken().getEncoded()))
        {
            fail();
        }
    }

    private void testAccuracyZeroCerts(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        tsTokenGen.setAccuracySeconds(1);
        tsTokenGen.setAccuracyMillis(2);
        tsTokenGen.setAccuracyMicros(3);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));

        //
        // check validation
        //
        tsResp.validate(request);

        //
        // check tstInfo
        //
        TimeStampTokenInfo tstInfo = tsToken.getTimeStampInfo();

        //
        // check accuracy
        //
        GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

        assertEquals(1, accuracy.getSeconds());
        assertEquals(2, accuracy.getMillis());
        assertEquals(3, accuracy.getMicros());

        assertEquals(new BigInteger("23"), tstInfo.getSerialNumber());

        assertEquals("1.2", tstInfo.getPolicy().getId());

        //
        // test certReq
        //
        Store store = tsToken.getCertificates();

        Collection certificates = store.getMatches(null);

        assertEquals(0, certificates.size());
    }

    private void testAccuracyWithCertsAndOrdering(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

        tsTokenGen.addCertificates(certs);

        tsTokenGen.setAccuracySeconds(3);
        tsTokenGen.setAccuracyMillis(1);
        tsTokenGen.setAccuracyMicros(2);

        tsTokenGen.setOrdering(true);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

        reqGen.setCertReq(true);

        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        assertTrue(request.getCertReq());

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp;

        try
        {
            tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), new Date());
        }
        catch (TSPException e)
        {
            tsResp = tsRespGen.generateRejectedResponse(e);
        }

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));

        //
        // check validation
        //
        tsResp.validate(request);

        //
        // check tstInfo
        //
        TimeStampTokenInfo tstInfo = tsToken.getTimeStampInfo();

        //
        // check accuracy
        //
        GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

        assertEquals(3, accuracy.getSeconds());
        assertEquals(1, accuracy.getMillis());
        assertEquals(2, accuracy.getMicros());

        assertEquals(new BigInteger("23"), tstInfo.getSerialNumber());

        assertEquals("1.2.3", tstInfo.getPolicy().getId());

        assertEquals(true, tstInfo.isOrdered());

        assertEquals(tstInfo.getNonce(), BigInteger.valueOf(100));

        //
        // test certReq
        //
        Store store = tsToken.getCertificates();

        Collection certificates = store.getMatches(null);

        assertEquals(2, certificates.size());
    }

    private void testNoNonse(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(privateKey), cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20]);

        Set algorithms = new HashSet();

        algorithms.add(TSPAlgorithms.SHA1);

        request.validate(algorithms, new HashSet(), new HashSet());

        assertFalse(request.getCertReq());

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("24"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));

        //
        // check validation
        //
        tsResp.validate(request);

        //
        // check tstInfo
        //
        TimeStampTokenInfo tstInfo = tsToken.getTimeStampInfo();

        //
        // check accuracy
        //
        GenTimeAccuracy accuracy = tstInfo.getGenTimeAccuracy();

        assertNull(accuracy);

        assertEquals(new BigInteger("24"), tstInfo.getSerialNumber());

        assertEquals("1.2.3", tstInfo.getPolicy().getId());

        assertEquals(false, tstInfo.isOrdered());

        assertNull(tstInfo.getNonce());

        //
        // test certReq
        //
        Store store = tsToken.getCertificates();

        Collection certificates = store.getMatches(null);

        assertEquals(0, certificates.size());
    }

    private void extensionTest(
        PrivateKey privateKey,
        X509Certificate cert,
        Store certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

        // test case only!!!
        reqGen.setReqPolicy(Extension.noRevAvail);
        // test case only!!!
        reqGen.addExtension(Extension.biometricInfo, true, new DEROctetString(new byte[20]));

        TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        try
        {
            request.validate(new HashSet(), new HashSet(), new HashSet());
            fail("no exception");
        }
        catch (Exception e)
        {
            assertEquals(e.getMessage(), "request contains unknown algorithm");
        }

        Set algorithms = new HashSet();

        algorithms.add(TSPAlgorithms.SHA1);

        try
        {
            request.validate(algorithms, new HashSet(), new HashSet());
            fail("no exception");
        }
        catch (Exception e)
        {
            assertEquals(e.getMessage(), "request contains unknown policy");
        }

        Set policies = new HashSet();

        policies.add(Extension.noRevAvail);

        try
        {
            request.validate(algorithms, policies, new HashSet());
            fail("no exception");
        }
        catch (Exception e)
        {
            assertEquals(e.getMessage(), "request contains unknown extension");
        }

        Set extensions = new HashSet();

        extensions.add(Extension.biometricInfo);

        // should validate with full set
        request.validate(algorithms, policies, extensions);

        // should validate with null policy
        request.validate(algorithms, null, extensions);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));

        AttributeTable table = tsToken.getSignedAttributes();

        assertNotNull("no signingCertificate attribute found", table.get(PKCSObjectIdentifiers.id_aa_signingCertificate));
    }
}
