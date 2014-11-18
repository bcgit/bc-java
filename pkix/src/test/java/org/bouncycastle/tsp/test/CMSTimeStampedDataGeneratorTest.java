package org.bouncycastle.tsp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.tsp.cms.CMSTimeStampedData;
import org.bouncycastle.tsp.cms.CMSTimeStampedDataGenerator;
import org.bouncycastle.tsp.cms.CMSTimeStampedDataParser;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.Streams;

public class CMSTimeStampedDataGeneratorTest
    extends TestCase
{

    BouncyCastleProvider bouncyCastleProvider;
    CMSTimeStampedDataGenerator cmsTimeStampedDataGenerator = null;
    String fileInput = "FileDaFirmare.data";
    byte[] baseData;

    protected void setUp()
        throws Exception
    {
        bouncyCastleProvider = new BouncyCastleProvider();
        if (Security.getProvider(bouncyCastleProvider.getName()) == null)
        {
            Security.addProvider(bouncyCastleProvider);
        }

        cmsTimeStampedDataGenerator = new CMSTimeStampedDataGenerator();
        ByteArrayOutputStream origStream = new ByteArrayOutputStream();
        InputStream in = this.getClass().getResourceAsStream(fileInput);
        int ch;

        while ((ch = in.read()) >= 0)
        {
            origStream.write(ch);
        }

        origStream.close();

        this.baseData = origStream.toByteArray();

    }

    protected void tearDown()
        throws Exception
    {
        cmsTimeStampedDataGenerator = null;
        Security.removeProvider(bouncyCastleProvider.getName());
    }

    public void testGenerate()
        throws Exception
    {
        BcDigestCalculatorProvider calculatorProvider = new BcDigestCalculatorProvider();
        ASN1ObjectIdentifier algOID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"); // SHA-256
        DigestCalculator hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(algOID));

        cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);

        hashCalculator.getOutputStream().write(baseData);
        hashCalculator.getOutputStream().close();

        TimeStampToken timeStampToken = createTimeStampToken(hashCalculator.getDigest(), NISTObjectIdentifiers.id_sha256);
        CMSTimeStampedData cmsTimeStampedData = cmsTimeStampedDataGenerator.generate(timeStampToken, baseData);

        for (int i = 0; i < 3; i++)
        {
            byte[] newRequestData = cmsTimeStampedData.calculateNextHash(hashCalculator);
            TimeStampToken newTimeStampToken = createTimeStampToken(newRequestData, NISTObjectIdentifiers.id_sha256);
            cmsTimeStampedData = cmsTimeStampedData.addTimeStamp(newTimeStampToken);
        }
        byte[] timeStampedData = cmsTimeStampedData.getEncoded();

        // verify
        DigestCalculatorProvider newCalculatorProvider = new BcDigestCalculatorProvider();
        DigestCalculator imprintCalculator = cmsTimeStampedData.getMessageImprintDigestCalculator(newCalculatorProvider);
        CMSTimeStampedData newCMSTimeStampedData = new CMSTimeStampedData(timeStampedData);
        byte[] newContent = newCMSTimeStampedData.getContent();
        assertEquals("Content expected and verified are different", true, Arrays.areEqual(newContent, baseData));

        imprintCalculator.getOutputStream().write(newContent);

        byte[] digest = imprintCalculator.getDigest();

        TimeStampToken[] tokens = cmsTimeStampedData.getTimeStampTokens();
        assertEquals("TimeStampToken expected and verified are different", 4, tokens.length);
        for (int i = 0; i < tokens.length; i++)
        {
            cmsTimeStampedData.validate(newCalculatorProvider, digest, tokens[i]);
        }
    }

    public void testGenerateWithMetadata()
        throws Exception
    {
        cmsTimeStampedDataGenerator.setMetaData(true, fileInput, "TXT");

        BcDigestCalculatorProvider calculatorProvider = new BcDigestCalculatorProvider();
        ASN1ObjectIdentifier algOID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"); // SHA-256
        DigestCalculator hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(algOID));

        cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);

        hashCalculator.getOutputStream().write(baseData);
        hashCalculator.getOutputStream().close();

        TimeStampToken timeStampToken = createTimeStampToken(hashCalculator.getDigest(), NISTObjectIdentifiers.id_sha256);
        CMSTimeStampedData cmsTimeStampedData = cmsTimeStampedDataGenerator.generate(timeStampToken, baseData);

        for (int i = 0; i <= 3; i++)
        {
            byte[] newRequestData = cmsTimeStampedData.calculateNextHash(hashCalculator);
            TimeStampToken newTimeStampToken = createTimeStampToken(newRequestData, NISTObjectIdentifiers.id_sha256);
            cmsTimeStampedData = cmsTimeStampedData.addTimeStamp(newTimeStampToken);
        }
        byte[] timeStampedData = cmsTimeStampedData.getEncoded();

        metadataCheck(timeStampedData);
        metadataParserCheck(timeStampedData);
    }

    public void testGenerateWithMetadataAndDifferentAlgorithmIdentifier()
        throws Exception
    {
        cmsTimeStampedDataGenerator.setMetaData(true, fileInput, "TXT");

        BcDigestCalculatorProvider calculatorProvider = new BcDigestCalculatorProvider();

        ASN1ObjectIdentifier algIdentifier = NISTObjectIdentifiers.id_sha224;

        DigestCalculator hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(algIdentifier));
        cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);
        hashCalculator.getOutputStream().write(baseData);
        hashCalculator.getOutputStream().close();

        byte[] requestData = hashCalculator.getDigest();
        TimeStampToken timeStampToken = createTimeStampToken(requestData, algIdentifier);

        CMSTimeStampedData cmsTimeStampedData = cmsTimeStampedDataGenerator.generate(timeStampToken, baseData);

        for (int i = 0; i <= 3; i++) {
            switch (i) {
            case 0:
                algIdentifier =    NISTObjectIdentifiers.id_sha224;
                break;
            case 1:
                algIdentifier =    NISTObjectIdentifiers.id_sha256;
                break;
            case 2:
                algIdentifier =    NISTObjectIdentifiers.id_sha384;
                break;
            case 3:
                algIdentifier =    NISTObjectIdentifiers.id_sha512;
                break;
            }
            hashCalculator = calculatorProvider.get(new AlgorithmIdentifier(algIdentifier));
            byte[] newRequestData = cmsTimeStampedData.calculateNextHash(hashCalculator);
            TimeStampToken newTimeStampToken = createTimeStampToken(newRequestData, algIdentifier);
            cmsTimeStampedData = cmsTimeStampedData.addTimeStamp(newTimeStampToken);
        }
        byte[] timeStampedData = cmsTimeStampedData.getEncoded();

        metadataCheck(timeStampedData);
        metadataParserCheck(timeStampedData);

    }


    private void metadataCheck(byte[] timeStampedData)
        throws Exception
    {
        CMSTimeStampedData cmsTspData = new CMSTimeStampedData(timeStampedData);
        DigestCalculatorProvider newCalculatorProvider = new BcDigestCalculatorProvider();
        DigestCalculator imprintCalculator = cmsTspData.getMessageImprintDigestCalculator(newCalculatorProvider);

        byte[] newContent = cmsTspData.getContent();
        assertEquals("Content expected and verified are different", true, Arrays.areEqual(newContent, baseData));

        imprintCalculator.getOutputStream().write(newContent);

        assertEquals(fileInput, cmsTspData.getFileName());
        assertEquals("TXT", cmsTspData.getMediaType());

        byte[] digest = imprintCalculator.getDigest();

        TimeStampToken[] tokens = cmsTspData.getTimeStampTokens();
        assertEquals("TimeStampToken expected and verified are different", 5, tokens.length);
        for (int i = 0; i < tokens.length; i++)
        {
            cmsTspData.validate(newCalculatorProvider, digest, tokens[i]);
        }
    }

    private void metadataParserCheck(byte[] timeStampedData)
        throws Exception
    {
        CMSTimeStampedDataParser cmsTspData = new CMSTimeStampedDataParser(timeStampedData);
        DigestCalculatorProvider newCalculatorProvider = new BcDigestCalculatorProvider();

        InputStream input = cmsTspData.getContent();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        Streams.pipeAll(input, bOut);

        assertEquals("Content expected and verified are different", true, Arrays.areEqual(bOut.toByteArray(), baseData));

        DigestCalculator imprintCalculator = cmsTspData.getMessageImprintDigestCalculator(newCalculatorProvider);

        Streams.pipeAll(new ByteArrayInputStream(bOut.toByteArray()), imprintCalculator.getOutputStream());

        assertEquals(fileInput, cmsTspData.getFileName());
        assertEquals("TXT", cmsTspData.getMediaType());

        byte[] digest = imprintCalculator.getDigest();

        TimeStampToken[] tokens = cmsTspData.getTimeStampTokens();
        assertEquals("TimeStampToken expected and verified are different", 5, tokens.length);
        for (int i = 0; i < tokens.length; i++)
        {
            cmsTspData.validate(newCalculatorProvider, digest, tokens[i]);
        }
    }

    private TimeStampToken createTimeStampToken(byte[] hash, ASN1ObjectIdentifier hashAlg)
        throws Exception
    {
        String algorithmName = null;
        if (hashAlg.equals(NISTObjectIdentifiers.id_sha224))
        {
            algorithmName = "SHA224withRSA";
        }
        else if (hashAlg.equals(NISTObjectIdentifiers.id_sha256))
        {
            algorithmName = "SHA256withRSA";
        }
        else if (hashAlg.equals(NISTObjectIdentifiers.id_sha384))
        {
            algorithmName = "SHA384withRSA";
        }
        else if (hashAlg.equals(NISTObjectIdentifiers.id_sha512))
        {
            algorithmName = "SHA512withRSA";
        }

        String signDN = "O=Bouncy Castle, C=AU";
        KeyPair signKP = TSPTestUtil.makeKeyPair();
        X509Certificate signCert = TSPTestUtil.makeCACertificate(signKP,
            signDN, signKP, signDN);

        String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        KeyPair origKP = TSPTestUtil.makeKeyPair();
        X509Certificate cert = TSPTestUtil.makeCertificate(origKP,
            origDN, signKP, signDN);

        PrivateKey privateKey = origKP.getPrivate();

        List certList = new ArrayList();
        certList.add(cert);
        certList.add(signCert);

        Store certs = new JcaCertStore(certList);


        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build(algorithmName, privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(hashAlg, hash);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        return tsResp.getTimeStampToken();
    }
}
