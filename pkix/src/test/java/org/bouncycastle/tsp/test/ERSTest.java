package org.bouncycastle.tsp.test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.tsp.ers.ArchiveTimeStampValidationException;
import org.bouncycastle.tsp.ers.ERSArchiveTimeStamp;
import org.bouncycastle.tsp.ers.ERSArchiveTimeStampGenerator;
import org.bouncycastle.tsp.ers.ERSByteData;
import org.bouncycastle.tsp.ers.ERSData;
import org.bouncycastle.tsp.ers.ERSDataGroup;
import org.bouncycastle.tsp.ers.ERSDirectoryDataGroup;
import org.bouncycastle.tsp.ers.ERSEvidenceRecord;
import org.bouncycastle.tsp.ers.ERSEvidenceRecordGenerator;
import org.bouncycastle.tsp.ers.ERSFileData;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class ERSTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    public static final byte[] H1_DATA = Strings.toByteArray("This is H1");
    public static final byte[] H2_DATA = Strings.toByteArray("This is H2");
    public static final byte[] H3A_DATA = Strings.toByteArray("This is H3A");
    public static final byte[] H3B_DATA = Strings.toByteArray("This is H3B");
    public static final byte[] H3C_DATA = Strings.toByteArray("This is H3C");
    public static final byte[] H4_DATA = Strings.toByteArray("This is H4");

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testBasicBuild()
        throws Exception
    {
        ERSData h1Doc = new ERSByteData(H1_DATA);
        ERSData h2Doc = new ERSByteData(H2_DATA);
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA)});

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        ersGen.addData(h1Doc);
        ersGen.addData(h2Doc);
        ersGen.addData(h3Docs);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();

        tspReqGen.setCertReq(true);

        TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);

        Assert.assertTrue(Arrays.areEqual(Hex.decode("98fbf91c1aebdfec514d4a76532ec95f27ebcf4c8b6f7e2947afcbbfe7084cd4"),
            tspReq.getMessageImprintDigest()));


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

        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(origKP.getPrivate()), origCert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

        tsTokenGen.addCertificates(certs);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp;

        try
        {
            tsResp = tsRespGen.generateGrantedResponse(tspReq, new BigInteger("23"), new Date());
        }
        catch (TSPException e)
        {
            tsResp = tsRespGen.generateRejectedResponse(e);
        }

        ERSArchiveTimeStamp ats = ersGen.generateArchiveTimeStamp(tsResp);

        ats = new ERSArchiveTimeStamp(ats.getEncoded(), digestCalculatorProvider);

        ats.validatePresent(h1Doc, new Date());
        ats.validatePresent(h2Doc, new Date());
        ats.validatePresent(h3Docs, new Date());

        // check for individual sub-documents
        List<byte[]> h3Hashes = h3Docs.getHashes(digestCalculator);
        for (int i = 0; i != h3Hashes.size(); i++)
        {
            ats.validatePresent((byte[])h3Hashes.get(i), new Date());
        }

        X509CertificateHolder tspCert = ats.getSigningCertificate();

        ats.validate(new JcaSimpleSignerInfoVerifierBuilder().build(tspCert));
    }

    public void testSingleTimeStamp()
        throws Exception
    {
        ERSData h1Doc = new ERSByteData(H1_DATA);
        ERSData h2Doc = new ERSByteData(H2_DATA);
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA)});

        DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        List<byte[]> hashes = h3Docs.getHashes(
            digestCalculator);

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        ersGen.addData(h1Doc);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();

        tspReqGen.setCertReq(true);

        TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);

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

        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(origKP.getPrivate()), origCert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

        tsTokenGen.addCertificates(certs);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp;

        try
        {
            tsResp = tsRespGen.generateGrantedResponse(tspReq, new BigInteger("23"), new Date());
        }
        catch (TSPException e)
        {
            tsResp = tsRespGen.generateRejectedResponse(e);
        }

        ERSArchiveTimeStamp ats = ersGen.generateArchiveTimeStamp(tsResp);

        ats.validatePresent(h1Doc, new Date());

        try
        {
            ats.validatePresent(h2Doc, new Date());
            fail();
        }
        catch (ArchiveTimeStampValidationException e)
        {
            assertEquals("object hash not found in wrapped timestamp", e.getMessage());
        }
    }

    public void testBasicBuildEvidenceRecord()
        throws Exception
    {
        ERSData h1Doc = new ERSByteData(H1_DATA);
        ERSData h2Doc = new ERSByteData(H2_DATA);
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA)});

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        ersGen.addData(h1Doc);
        ersGen.addData(h2Doc);
        ersGen.addData(h3Docs);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();

        tspReqGen.setCertReq(true);

        TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);

        Assert.assertTrue(Arrays.areEqual(Hex.decode("98fbf91c1aebdfec514d4a76532ec95f27ebcf4c8b6f7e2947afcbbfe7084cd4"),
            tspReq.getMessageImprintDigest()));


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

        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(origKP.getPrivate()), origCert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2.3"));

        tsTokenGen.addCertificates(certs);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp;

        try
        {
            tsResp = tsRespGen.generateGrantedResponse(tspReq, new BigInteger("23"), new Date());
        }
        catch (TSPException e)
        {
            tsResp = tsRespGen.generateRejectedResponse(e);
        }

        ERSArchiveTimeStamp ats = ersGen.generateArchiveTimeStamp(tsResp);

        ERSEvidenceRecordGenerator evGen = new ERSEvidenceRecordGenerator(digestCalculatorProvider);

        ERSEvidenceRecord ev = evGen.generate(ats);

        ev.validatePresent(h1Doc, new Date());
        ev.validatePresent(h2Doc, new Date());
        ev.validatePresent(h3Docs, new Date());

        // check for individual sub-documents
        List<byte[]> h3Hashes = h3Docs.getHashes(digestCalculator);
        for (int i = 0; i != h3Hashes.size(); i++)
        {
            ev.validatePresent((byte[])h3Hashes.get(i), new Date());
        }

        X509CertificateHolder tspCert = ev.getSigningCertificate();

        ev.validate(new JcaSimpleSignerInfoVerifierBuilder().build(tspCert));

        ERSEvidenceRecord ev2 = new ERSEvidenceRecord(ev.getEncoded(), digestCalculatorProvider);

        tspCert = ev2.getSigningCertificate();

        ev2.validate(new JcaSimpleSignerInfoVerifierBuilder().build(tspCert));

        ev2.validatePresent(h3Docs, new Date());
    }

    public void test4NodeBuild()
        throws Exception
    {
        ERSData h1Doc = new ERSByteData(H1_DATA);
        ERSData h2Doc = new ERSByteData(H2_DATA);
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA)});
        ERSData h4Doc = new ERSByteData(H4_DATA);

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        ersGen.addData(h1Doc);
        ersGen.addData(h2Doc);
        ersGen.addData(h3Docs);
        ersGen.addData(h4Doc);

        TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();

        tspReqGen.setCertReq(true);

        TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);

        Assert.assertTrue(Arrays.areEqual(Hex.decode("d82fea0eaff4b12925a201dff2332965953ca38c1eef6c9e31b55bbce4ce2984"),
            tspReq.getMessageImprintDigest()));

        ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

        List<ERSData> dataList = new ArrayList<ERSData>();

        dataList.add(h1Doc);
        dataList.add(h2Doc);
        dataList.add(h3Docs);
        dataList.add(h4Doc);

        ersGen.addAllData(dataList);

        tspReqGen = new TimeStampRequestGenerator();

        tspReqGen.setCertReq(true);

        tspReq = ersGen.generateTimeStampRequest(tspReqGen);

        Assert.assertTrue(Arrays.areEqual(Hex.decode("d82fea0eaff4b12925a201dff2332965953ca38c1eef6c9e31b55bbce4ce2984"),
            tspReq.getMessageImprintDigest()));
    }

    public void testDirUtil()
        throws Exception
    {
        File rootDir = File.createTempFile("ers", ".dir");
        rootDir.delete();
        if (rootDir.mkdir())
        {
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
            DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

            File h1 = new File(rootDir, "h1");
            OutputStream fOut = new FileOutputStream(h1);
            fOut.write(H1_DATA);
            fOut.close();

            File h2 = new File(rootDir, "h2");
            fOut = new FileOutputStream(h2);
            fOut.write(H2_DATA);
            fOut.close();

            File h3 = new File(rootDir, "h3");
            h3.mkdir();
            fOut = new FileOutputStream(new File(h3, "a"));
            fOut.write(H3A_DATA);
            fOut.close();
            fOut = new FileOutputStream(new File(h3, "b"));
            fOut.write(H3B_DATA);
            fOut.close();
            fOut = new FileOutputStream(new File(h3, "c"));
            fOut.write(H3C_DATA);
            fOut.close();

            ERSArchiveTimeStampGenerator ersGen = new ERSArchiveTimeStampGenerator(digestCalculator);

            ersGen.addData(new ERSFileData(h1));
            ersGen.addData(new ERSFileData(h2));
            ersGen.addData(new ERSDirectoryDataGroup(h3));

            TimeStampRequestGenerator tspReqGen = new TimeStampRequestGenerator();

            tspReqGen.setCertReq(true);

            TimeStampRequest tspReq = ersGen.generateTimeStampRequest(tspReqGen);

            Assert.assertTrue(Arrays.areEqual(Hex.decode("98fbf91c1aebdfec514d4a76532ec95f27ebcf4c8b6f7e2947afcbbfe7084cd4"),
                tspReq.getMessageImprintDigest()));

            deleteDirectory(rootDir);
        }
        else
        {
            throw new Exception("can't create temp dir");
        }
    }

    private void deleteDirectory(File directory)
    {
        File[] files = directory.listFiles();
        if (files != null)
        {
            for (int i = 0; i != files.length; i++)
            {
                deleteDirectory(files[i]);
            }
        }
        directory.delete();
    }

    public void testSort()
        throws Exception
    {
        ERSDataGroup h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H1_DATA),
                new ERSByteData(H2_DATA)}
        );

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();

        trySort(h3Docs, NISTObjectIdentifiers.id_sha256, digestCalculatorProvider);

        h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H2_DATA),
                new ERSByteData(H1_DATA)}
        );

        trySort(h3Docs, NISTObjectIdentifiers.id_sha256, digestCalculatorProvider);

        h3Docs = new ERSDataGroup(
            new ERSData[]{new ERSByteData(H1_DATA),
                new ERSByteData(H2_DATA),
                new ERSByteData(H3A_DATA),
                new ERSByteData(H3B_DATA),
                new ERSByteData(H3C_DATA),
                new ERSByteData(H4_DATA)}
        );
        trySort(h3Docs, NISTObjectIdentifiers.id_sha256, digestCalculatorProvider);
        trySort(h3Docs, NISTObjectIdentifiers.id_sha224, digestCalculatorProvider);
        trySort(h3Docs, NISTObjectIdentifiers.id_sha384, digestCalculatorProvider);
    }

    private void trySort(ERSDataGroup h3Docs, ASN1ObjectIdentifier sha, DigestCalculatorProvider digestCalculatorProvider)
        throws OperatorCreationException
    {
        List<byte[]> hashes = h3Docs.getHashes(digestCalculatorProvider.get(
            new AlgorithmIdentifier(sha)));
        for (int i = 0; i != hashes.size() - 1; i++)
        {
            assertTrue(compare((byte[])hashes.get(i), (byte[])hashes.get(i + 1)) < 0);
        }
    }

    private int compare(byte[] a, byte[] b)
    {
        return new BigInteger(1, a).compareTo(new BigInteger(1, b));
    }
}
