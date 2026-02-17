package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509v1CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcHssLmsContentSignerBuilder;
import org.bouncycastle.operator.bc.BcHssLmsContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Store;

public class PQCSignedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String BCPQC = BouncyCastlePQCProvider.PROVIDER_NAME;

    boolean DEBUG = true;

    private static String _origDN;
    private static KeyPair _origKP;
    private static X509Certificate _origCert;

    private static KeyPair _origLmsKP;
    private static X509Certificate _origLmsCert;
    private static KeyPair _origFalconKP;
    private static X509Certificate _origFalconCert;
    private static KeyPair _origPicnicKP;
    private static X509Certificate _origPicnicCert;
    private static KeyPair _origMlDsaKP;
    private static X509Certificate _origMlDsaCert;
    private static KeyPair _origSlhDsaKP;
    private static X509Certificate _origSlhDsaCert;

    private static String _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;
    private static KeyPair _signLmsKP;
    private static X509Certificate _signLmsCert;
    private static KeyPair _signFalconKP;
    private static X509Certificate _signFalconCert;
    private static KeyPair _signPicnicKP;
    private static X509Certificate _signPicnicCert;
    private static KeyPair _signMlDsaKP;
    private static X509Certificate _signMlDsaCert;
    private static KeyPair _signSlhDsaKP;
    private static X509Certificate _signSlhDsaCert;

    private static boolean _initialised = false;

    private static final Set noParams = new HashSet();

    static
    {
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA512);
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA3_512);
    }

    public PQCSignedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
        throws Exception
    {
        init();
        //checkCreationHssLms();
        junit.textui.TestRunner.run(PQCSignedDataTest.class);
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(PQCSignedDataTest.class));
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
            if (Security.getProvider(BCPQC) == null)
            {
                Security.addProvider(new BouncyCastlePQCProvider());
            }

            _origDN = "O=Bouncy Castle, C=AU";
            _origKP = PQCTestUtil.makeKeyPair();
            _origCert = PQCTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

            _signDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _signKP = PQCTestUtil.makeKeyPair();
            _signCert = PQCTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

            _origLmsKP = PQCTestUtil.makeLmsKeyPair();
            _origLmsCert = PQCTestUtil.makeCertificate(_origLmsKP, _origDN, _origLmsKP, _origDN);

            _signLmsKP = PQCTestUtil.makeLmsKeyPair();
            _signLmsCert = PQCTestUtil.makeCertificate(_signLmsKP, _signDN, _origLmsKP, _origDN);

            _origFalconKP = PQCTestUtil.makeFalconKeyPair();
            _origFalconCert = PQCTestUtil.makeCertificate(_origFalconKP, _origDN, _origFalconKP, _origDN);

            _signFalconKP = PQCTestUtil.makeFalconKeyPair();
            _signFalconCert = PQCTestUtil.makeCertificate(_signFalconKP, _signDN, _origFalconKP, _origDN);

            _origPicnicKP = PQCTestUtil.makePicnicKeyPair();
            _origPicnicCert = PQCTestUtil.makeCertificate(_origPicnicKP, _origDN, _origPicnicKP, _origDN);

            _signPicnicKP = PQCTestUtil.makePicnicKeyPair();
            _signPicnicCert = PQCTestUtil.makeCertificate(_signPicnicKP, _signDN, _origPicnicKP, _origDN);

            _origMlDsaKP = PQCTestUtil.makeMlDsaKeyPair();
            _origMlDsaCert = PQCTestUtil.makeCertificate(_origMlDsaKP, _origDN, _origMlDsaKP, _origDN);

            _signMlDsaKP = PQCTestUtil.makeMlDsaKeyPair();
            _signMlDsaCert = PQCTestUtil.makeCertificate(_signMlDsaKP, _signDN, _origMlDsaKP, _origDN);

            _origSlhDsaKP = PQCTestUtil.makeSlhDsaKeyPair();
            _origSlhDsaCert = PQCTestUtil.makeCertificate(_origSlhDsaKP, _origDN, _origSlhDsaKP, _origDN);

            _signSlhDsaKP = PQCTestUtil.makeSlhDsaKeyPair();
            _signSlhDsaCert = PQCTestUtil.makeCertificate(_signSlhDsaKP, _signDN, _origSlhDsaKP, _origDN);
        }
    }

    public void testSPHINCS256Encapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("SHA512withSPHINCS256").setProvider(BCPQC).build(_origKP.getPrivate()), _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        SignerId sid = null;

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
    }

    public void testFalconEncapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origFalconCert);
        certList.add(_signFalconCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("Falcon-512").setProvider(BCPQC).build(_origFalconKP.getPrivate()), _origFalconCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
    }

    public void testLmsEncapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origLmsCert);
        certList.add(_signLmsCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("LMS", _origLmsCert.getPublicKey()).setProvider(BC).build(_origLmsKP.getPrivate()), _origLmsCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        Set<AlgorithmIdentifier> digAlgIds = s.getDigestAlgorithmIDs();

        assertTrue(digAlgIds.contains(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)));
        assertTrue(digAlgIds.size() == 1);

        certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
    }

    public void testCheckCreationHss()
        throws Exception
    {
        //
        // set up the keys
        //
        AsymmetricKeyParameter privKey;
        AsymmetricKeyParameter pubKey;

        AsymmetricCipherKeyPairGenerator kpg = new HSSKeyPairGenerator();

        kpg.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LMSParameters(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w4)}, new SecureRandom()));

        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();

        privKey = (AsymmetricKeyParameter)pair.getPrivate();
        pubKey = (AsymmetricKeyParameter)pair.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);

        builder.addRDN(RFC4519Style.c, "AU");
        builder.addRDN(RFC4519Style.o, "The Legion of the Bouncy Castle");
        builder.addRDN(RFC4519Style.l, "Melbourne");
        builder.addRDN(RFC4519Style.st, "Victoria");
        builder.addRDN(PKCSObjectIdentifiers.pkcs_9_at_emailAddress, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new BcHssLmsContentSignerBuilder().build(privKey);
        X509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);


        X509CertificateHolder cert = certGen.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));

        assertTrue(cert.isSignatureValid(new BcHssLmsContentVerifierProviderBuilder().build(pubKey)));


        //
        // create the certificate - version 1
        //
        sigGen = new BcHssLmsContentSignerBuilder().build(privKey);
        X509v1CertificateBuilder certGen1 = new BcX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        cert = certGen1.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));

        assertTrue(cert.isSignatureValid(new BcHssLmsContentVerifierProviderBuilder().build(pubKey)));

        AsymmetricKeyParameter certPubKey = org.bouncycastle.pqc.crypto.util.PublicKeyFactory.createKey(cert.getSubjectPublicKeyInfo());

        assertTrue(cert.isSignatureValid(new BcHssLmsContentVerifierProviderBuilder().build(certPubKey)));

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509");

        X509Certificate x509cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(cert);
    }

    public void testCheckCreationLms()
        throws Exception
    {
        //
        // set up the keys
        //
        AsymmetricKeyParameter privKey;
        AsymmetricKeyParameter pubKey;

        AsymmetricCipherKeyPairGenerator kpg = new LMSKeyPairGenerator();

        kpg.init(new LMSKeyGenerationParameters(
            new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4), new SecureRandom()));

        AsymmetricCipherKeyPair pair = kpg.generateKeyPair();

        privKey = (AsymmetricKeyParameter)pair.getPrivate();
        pubKey = (AsymmetricKeyParameter)pair.getPublic();

        //
        // distinguished name table.
        //
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);

        builder.addRDN(RFC4519Style.c, "AU");
        builder.addRDN(RFC4519Style.o, "The Legion of the Bouncy Castle");
        builder.addRDN(RFC4519Style.l, "Melbourne");
        builder.addRDN(RFC4519Style.st, "Victoria");
        builder.addRDN(PKCSObjectIdentifiers.pkcs_9_at_emailAddress, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate - version 3
        //
        ContentSigner sigGen = new BcHssLmsContentSignerBuilder().build(privKey);
        X509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);


        X509CertificateHolder cert = certGen.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));

        assertTrue(cert.isSignatureValid(new BcHssLmsContentVerifierProviderBuilder().build(pubKey)));


        //
        // create the certificate - version 1
        //

        sigGen = new BcHssLmsContentSignerBuilder().build(privKey);
        X509v1CertificateBuilder certGen1 = new BcX509v1CertificateBuilder(builder.build(), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), builder.build(), pubKey);

        cert = certGen1.build(sigGen);

        assertTrue(cert.isValidOn(new Date()));

        assertTrue(cert.isSignatureValid(new BcHssLmsContentVerifierProviderBuilder().build(pubKey)));

        AsymmetricKeyParameter certPubKey = ((HSSPublicKeyParameters)org.bouncycastle.pqc.crypto.util.PublicKeyFactory.createKey(cert.getSubjectPublicKeyInfo())).getLMSPublicKey();

        assertTrue(cert.isSignatureValid(new BcHssLmsContentVerifierProviderBuilder().build(certPubKey)));

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509");

        X509Certificate x509cert = (X509Certificate)fact.generateCertificate(bIn);

        //System.out.println(new String(cert.getEncoded()));
    }

    public void testTryLmsSettings()
        throws Exception
    {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        try
        {
            new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("LMS").setProvider(BC).build(_origLmsKP.getPrivate()), _origLmsCert).generate(PKCSObjectIdentifiers.data);
        }
        catch (OperatorCreationException e)
        {
            assertEquals("no digest algorithm specified for signature algorithm", e.getMessage());
        }

        SignerInfo sigInfo = new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("LMS", new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)).setProvider(BC).build(_origLmsKP.getPrivate()), _origLmsCert).generate(PKCSObjectIdentifiers.data);

        assertEquals(sigInfo.getDigestAlgorithm(), new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
    }

    public void testPicnicEncapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origPicnicCert);
        certList.add(_signPicnicCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("PICNIC").setProvider(BCPQC).build(_origPicnicKP.getPrivate()), _origPicnicCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        checkSignature(s, gen);
    }

    public void testMLDSAEncapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origMlDsaCert);
        certList.add(_signMlDsaCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("ML-DSA").setProvider(BC).build(_origMlDsaKP.getPrivate()), _origMlDsaCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        AlgorithmIdentifier digestAlgorithmID = s.getSignerInfos().getSigners().iterator().next().getDigestAlgorithmID();
        // CNSA compliance requires SHA-384 or SHA-512. We now default to SHA-512
        assertEquals(NISTObjectIdentifiers.id_sha512, digestAlgorithmID.getAlgorithm());
        assertNull(digestAlgorithmID.getParameters());

        checkSignature(s, gen);
    }

    public void testHashMLDSAEncapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origMlDsaCert);
        certList.add(_signMlDsaCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("HASH-ML-DSA").setProvider(BC).build(_origMlDsaKP.getPrivate()), _origMlDsaCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        checkSignature(s, gen);
    }

    public void testSLHDSAEncapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origSlhDsaCert);
        certList.add(_signSlhDsaCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("SLH-DSA").setProvider(BC).build(_origSlhDsaKP.getPrivate()), _origSlhDsaCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        checkSignature(s, gen);
    }

    public void testHashSLHDSAEncapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(_origSlhDsaCert);
        certList.add(_signSlhDsaCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("HASH-SLH-DSA").setProvider(BC).build(_origSlhDsaKP.getPrivate()), _origSlhDsaCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        checkSignature(s, gen);
    }

    private void checkSignature(CMSSignedData s, CMSSignedDataGenerator gen)
        throws IOException, CMSException, OperatorCreationException, CertificateException
    {
        Store certs;
        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();


        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            cert.getSubjectPublicKeyInfo();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));

            //
            // check content digest
            //

            byte[] contentDigest = (byte[])gen.getGeneratedDigests().get(signer.getDigestAlgOID());

            AttributeTable table = signer.getSignedAttributes();
            Attribute hash = table.get(CMSAttributes.messageDigest);

            assertTrue(MessageDigest.isEqual(contentDigest, ((ASN1OctetString)hash.getAttrValues().getObjectAt(0)).getOctets()));
        }
    }
}
