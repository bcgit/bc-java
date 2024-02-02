package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSAuthenticatedData;
import org.bouncycastle.cms.CMSAuthenticatedDataGenerator;
import org.bouncycastle.cms.CMSAuthenticatedDataParser;
import org.bouncycastle.cms.CMSAuthenticatedDataStreamGenerator;
import org.bouncycastle.cms.CMSCompressedData;
import org.bouncycastle.cms.CMSCompressedDataGenerator;
import org.bouncycastle.cms.CMSCompressedDataStreamGenerator;
import org.bouncycastle.cms.CMSDigestedData;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.KeyAgreeRecipientInformation;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.OriginatorInfoGenerator;
import org.bouncycastle.cms.OriginatorInformation;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.bc.BcECSignerInfoVerifierBuilder;
import org.bouncycastle.cms.bc.BcEdDSASignerInfoVerifierBuilder;
import org.bouncycastle.cms.bc.BcKEKEnvelopedRecipient;
import org.bouncycastle.cms.bc.BcKEKRecipientInfoGenerator;
import org.bouncycastle.cms.bc.BcPasswordEnvelopedRecipient;
import org.bouncycastle.cms.bc.BcPasswordRecipientInfoGenerator;
import org.bouncycastle.cms.bc.BcRSAKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.bc.BcRSAKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.ZlibCompressor;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.util.AnnotatedPrivateKey;
import org.bouncycastle.jcajce.util.PrivateKeyAnnotator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.bc.BcAESSymmetricKeyUnwrapper;
import org.bouncycastle.operator.bc.BcAESSymmetricKeyWrapper;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcSymmetricKeyUnwrapper;
import org.bouncycastle.operator.bc.BcSymmetricKeyWrapper;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.test.GeneralTest;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;


public class CMSGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        CMSGeneralTest test = new CMSGeneralTest();
        test.setUp();
        test.init();
        test.testOpenSSLVectors();
        test.testECKeyAgree();
        test.testKeyTransDESEDE3Short();
        test.testOriginatorInfo2();
        test.testTwoAESKEK();
        test.testUnprotectedAttributes();
        test.testWorkingData();
        test.testNewCompressedData();
        test.testPasswordAES256();
        test.testAES256CCMContentType();
        test.testCMSAlgorithmProtection();
        test.testOriginatorInfo();
        test.testSHA1WithRSA();
        test.testDigestedData();
        test.testSHA1WithRSANoAttributesSimple();
        test.testSHA224WithRSAEncapsulated();
        test.testSHA1WithRSAEncapsulatedSubjectKeyID();
        test.testSHA1WithRSAPSS();
        test.testEd448();
        test.testSHA224WithRSAPSS();
        test.testSHA256WithRSAPSS();
        test.testSHA384WithRSAPSS();
        test.testSHA224WithRSAEncapsulated();
        test.testSHA256WithRSAEncapsulated();
        test.testRIPEMD128WithRSAEncapsulated();
        test.testRIPEMD160WithRSAEncapsulated();
        test.testRIPEMD256WithRSAEncapsulated();
        test.testECDSAEncapsulated();
        test.testECDSAEncapsulatedSubjectKeyID();
        test.testECDSASHA224Encapsulated();
        test.testECDSASHA256Encapsulated();
        test.testECDSASHA384Encapsulated();
        test.testECDSASHA512Encapsulated();
        test.testDetachedVerificationWithBufferingContentSigner();
        test.testBcEnvelopedData();
        test.testAuthEnvelopedData1();
        test.testKeyTransOAEPDefault();

    }

    private static final AsymmetricKeyParameter RSA_PRIVATE_KEY_SPEC = new RSAPrivateCrtKeyParameters(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16),
        new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
        new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
        new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
        new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
        new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
        new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    private static String _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;

    private static String _origDN;
    private static KeyPair _origKP;
    private static X509Certificate _origCert;

    private static X509CRL _signCrl;
    private static String _reciDN;
    private static KeyPair _reciKP;
    private static X509Certificate _reciCert;

    private static KeyPair _signEcDsaKP;
    private static X509Certificate _signEcDsaCert;
    private static KeyPair _origEcKP;
    private static KeyPair _reciEcKP;
    private static X509Certificate _reciEcCert;

    private static KeyPair _signEd448KP;
    private static X509Certificate _signEd448Cert;

    private static X509CRL _origCrl;

    private static boolean _initialised = false;

    public static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            Security.addProvider(new BouncyCastleProvider());

            _signDN = "O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _origEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);

            _signCrl = CMSTestUtil.makeCrl(_signKP);

            _signEd448KP = CMSTestUtil.makeEd448KeyPair();
            _signEd448Cert = CMSTestUtil.makeCertificate(_signEd448KP, _signDN, _origKP, _origDN);

            _signEcDsaKP = CMSTestUtil.makeEcDsaKeyPair();
            _signEcDsaCert = CMSTestUtil.makeCertificate(_signEcDsaKP, _signDN, _origKP, _origDN);

            _origCrl = CMSTestUtil.makeCrl(_origKP);
        }
    }

    public void testKeyTransOAEPDefault()
        throws Exception
    {
        if (!_initialised)
        {
            init();
        }
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        final JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();

        testException("unknown parameter spec passed.", "InvalidAlgorithmParameterException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 20, 1));
            }
        });
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert, paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT)).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets(), paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT), _reciCert.getPublicKey()).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();

        assertEquals(2, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(PKCSObjectIdentifiers.id_RSAES_OAEP, recipient.getKeyEncryptionAlgorithm().getAlgorithm());

            AnnotatedPrivateKey privateKey = PrivateKeyAnnotator.annotate(_reciKP.getPrivate(), "fred");

            assertEquals("fred", privateKey.getAnnotation(AnnotatedPrivateKey.LABEL));
            assertEquals("fred", privateKey.toString());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }

        RecipientId id = new JceKeyTransRecipientId(_reciCert.getIssuerX500Principal(), _reciCert.getSerialNumber(),
            ASN1OctetString.getInstance(ASN1OctetString.getInstance(_reciCert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets()).getOctets());

        RecipientId id2 = new JceKeyTransRecipientId(null, _reciCert.getSerialNumber());
        assertFalse(id2.match(id));
        assertTrue(id.match(((KeyTransRecipientId)id.clone()).getSubjectKeyIdentifier()));

        Collection<RecipientInformation> collection = recipients.getRecipients(id);
        if (collection.size() != 2)
        {
            fail("recipients not matched using general recipient ID.");
        }
        assertTrue(collection.iterator().next() instanceof RecipientInformation);
    }

    public void testAuthEnvelopedData1()
        throws Exception
    {
        if (!_initialised)
        {
            init();
        }
        CMSAuthEnvelopedData authEnv = new CMSAuthEnvelopedData(new ByteArrayInputStream(AuthEnvelopedDataTest.Sample1));
        // Tests for CMSAuthEnvelopedData
        assertNull(authEnv.getOriginatorInfo());
        assertNull(authEnv.getAuthAttrs());
        assertNull(authEnv.getUnauthAttrs());
        CMSAuthEnvelopedData authEnv1 = new CMSAuthEnvelopedData(authEnv.toASN1Structure());
        assertTrue(Arrays.equals(authEnv.getMac(), authEnv1.getMac()));
        RecipientInformationStore recipients = authEnv.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(AuthEnvelopedDataTest.Sample1Key));

        byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

        assertEquals("auth-enveloped data", Strings.fromByteArray(recData));

        assertTrue(org.bouncycastle.util.Arrays.areEqual(AuthEnvelopedDataTest.Sample1, authEnv.getEncoded()));

        // Tests for BcCMSContentEncryptorBuilder
        testException("incorrect keySize for encryptionOID passed to builder.", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new BcCMSContentEncryptorBuilder(PKCSObjectIdentifiers.des_EDE3_CBC, 192 + 1);
            }
        });

        testException("incorrect keySize for encryptionOID passed to builder.", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new BcCMSContentEncryptorBuilder(OIWObjectIdentifiers.desCBC, 64 + 1);
            }
        });

        testException("incorrect keySize for encryptionOID passed to builder.", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new BcCMSContentEncryptorBuilder(PKCSObjectIdentifiers.id_alg_CMS3DESwrap, 192 + 1);
            }
        });

        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new BcCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CCM)
            .setSecureRandom(CryptoServicesRegistrar.getSecureRandom())
            .build();

        assertEquals(NISTObjectIdentifiers.id_aes128_CCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                    new DERSet(new Time(new Date())));
                attrs.put(testAttr.getAttrType(), testAttr);
                return new AttributeTable(attrs);
            }
        });


        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        recipients = encAuthData.getRecipientInfos();

        recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        if (System.getProperty("java.version").indexOf("1.5.") < 0)
        {
            recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals("Hello, world!", Strings.fromByteArray(recData));
        }
    }

    public void testBcEnvelopedData()
        throws Exception
    {

        ASN1ObjectIdentifier algorithm = CMSAlgorithm.AES256_CBC;
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new BcPasswordRecipientInfoGenerator(algorithm, "password".toCharArray()).setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2).setSaltAndIterationCount(new byte[20], 5));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
            CMSAlgorithm.AES128_CBC.getId());

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            PasswordRecipientInformation recipient = (PasswordRecipientInformation)it.next();
            assertEquals(PKCSObjectIdentifiers.id_PBKDF2.toString(), recipient.getKeyDerivationAlgOID());
            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.id_alg_PWRI_KEK.toString());
            assertNotNull(recipient.getKeyDerivationAlgParams());
            byte[] recData = recipient.getContent(new BcPasswordEnvelopedRecipient("password".toCharArray()).setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2));

            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }

        //
        // try algorithm parameters constructor
        //
        it = c.iterator();

        RecipientInformation recipient = (RecipientInformation)it.next();

        byte[] recData = recipient.getContent(new BcPasswordEnvelopedRecipient("password".toCharArray()).setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2));
        assertEquals(true, Arrays.equals(data, recData));

        data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        edGen = new CMSEnvelopedDataGenerator();

        Certificate certStruct = Certificate.getInstance(_reciEcCert.getEncoded());

        byte[] subjectKeyID = new IssuerAndSerialNumber(certStruct.getIssuer(), _reciEcCert.getSerialNumber()).getEncoded();

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF,
            _origEcKP.getPrivate(), _origEcKP.getPublic(),
            CMSAlgorithm.AES128_WRAP)
            .addRecipient(subjectKeyID, _reciEcCert.getPublicKey())
            .setProvider(new BouncyCastleProvider())
            .setSecureRandom(CryptoServicesRegistrar.getSecureRandom()));

        ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new BcCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).build());

        assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.AES128_CBC.getId());

        recipients = ed.getRecipientInfos();

        assertEquals(1, recipients.getRecipients().size());

        final SecretKey key = CMSTestUtil.makeAESKey(128);

        tryKekAlgorithm(new BcAESSymmetricKeyWrapper(new KeyParameter(key.getEncoded())).setSecureRandom(CryptoServicesRegistrar.getSecureRandom()),
            new BcAESSymmetricKeyUnwrapper(new KeyParameter(key.getEncoded())).setSecureRandom(CryptoServicesRegistrar.getSecureRandom()),
            NISTObjectIdentifiers.id_aes128_wrap);

        testException("unable to unwrap key: ", "OperatorException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new BcAESSymmetricKeyUnwrapper(new KeyParameter(key.getEncoded())).generateUnwrappedKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_CCM), new byte[32]);
            }
        });
    }

    private void tryKekAlgorithm(BcSymmetricKeyWrapper kekWrapper, BcSymmetricKeyUnwrapper kekUnwrapper, ASN1ObjectIdentifier algOid)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        byte[] data = "WallaWallaWashington".getBytes();
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

        edGen.addRecipientInfoGenerator(new BcKEKRecipientInfoGenerator(kekId, kekWrapper));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new BcCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(ed.getEncryptionAlgOID(), CMSAlgorithm.DES_EDE3_CBC.getId());

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(algOid.getId(), recipient.getKeyEncryptionAlgOID());

            byte[] recData = recipient.getContent(new BcKEKEnvelopedRecipient(kekUnwrapper));

            assertTrue(Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testDetachedVerificationWithBufferingContentSigner()
        throws Exception
    {
        if (!_initialised)
        {
            init();
        }
        CMSSignedData sig = new CMSSignedData(new ByteArrayInputStream(getInput("counterSig.p7m")));

        SignerInformationStore ss = sig.getSignerInfos();
        Collection signersCollection = ss.getSigners();

        SignerInformationStore cs = new SignerInformationStore((SignerInformation)signersCollection.iterator().next());
        Collection csSigners = cs.getSigners();
        assertEquals(1, csSigners.size());

        Iterator it = csSigners.iterator();
        while (it.hasNext())
        {
            final SignerInformation cSigner = (SignerInformation)it.next();
            assertEquals(3, cSigner.getVersion());
            assertEquals(CMSObjectIdentifiers.data, cSigner.getContentType());
            assertNull(cSigner.getDigestAlgParams());
            testException("method can only be called after verify.", "IllegalStateException", new TestExceptionOperation()
            {
                @Override
                public void operation()
                    throws Exception
                {
                    cSigner.getContentDigest();
                }
            });
            Collection certCollection = sig.getCertificates().getMatches(cSigner.getSID());


            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertFalse(cSigner.isCounterSignature());
            assertNotNull(cSigner.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_contentType));
            assertEquals(true, cSigner.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(cert)));
        }

        verifySignatures(sig, null);

        CMSSignedData s = new CMSSignedData(new CMSProcessableByteArray(BcSignedDataTest.disorderedMessage), new ByteArrayInputStream(BcSignedDataTest.disorderedSet));

        Store certs = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(false, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));

            RSADigestSigner rsasig = new RSADigestSigner(new SHA1Digest());

            rsasig.init(false, PublicKeyFactory.createKey(cert.getSubjectPublicKeyInfo()));

            byte[] encoded = signer.toASN1Structure().getAuthenticatedAttributes().getEncoded();
            rsasig.update(encoded, 0, encoded.length);

            assertEquals(true, rsasig.verifySignature(signer.getSignature()));
        }
        byte[] data = "Hello World!".getBytes();
        List certList = new ArrayList();
        final CMSTypedData msg = new CMSProcessableByteArray(data);

        certList.add(_origCert);
        certList.add(_signCert);

        certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator(digAlgFinder);

//        testException("this method can only be used with SignerInfoGenerator", "IllegalStateException", new TestExceptionOperation()
//        {
//            @Override
//            public void operation()
//                throws Exception
//            {
//                 new CMSSignedDataGenerator(digAlgFinder).generate(msg, true);
//            }
//        });

        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digProvider);
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(_origKP.getPrivate());
        ContentSigner md5Signer = new JcaContentSignerBuilder("MD5withRSA").setProvider(BC).build(_origKP.getPrivate());

        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(new BufferingContentSigner(sha1Signer, 4096), _origCert));
        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(new BufferingContentSigner(md5Signer), _origCert));

        gen.addCertificates(certs);

        s = gen.generate(msg);

        MessageDigest sha1 = MessageDigest.getInstance("SHA1", BC);
        MessageDigest md5 = MessageDigest.getInstance("MD5", BC);
        Map hashes = new HashMap();
        byte[] sha1Hash = sha1.digest(data);
        byte[] md5Hash = md5.digest(data);

        hashes.put(CMSAlgorithm.SHA1, sha1Hash);
        hashes.put(CMSAlgorithm.MD5, md5Hash);

        s = new CMSSignedData(hashes, s.getEncoded());

        verifySignatures(s, null);
    }

    private void verifySignatures(CMSSignedData s, byte[] contentDigest)
        throws Exception
    {
        Store certStore = s.getCertificates();
        Store crlStore = s.getCRLs();
        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));

            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }

        Collection certColl = certStore.getMatches(null);
        Collection crlColl = crlStore.getMatches(null);

        assertEquals(certColl.size(), s.getCertificates().getMatches(null).size());
        assertEquals(crlColl.size(), s.getCRLs().getMatches(null).size());
    }

    private byte[] getInput(String name)
        throws IOException
    {
        return Streams.readAll(getClass().getResourceAsStream(name));
    }

    private void encapsulatedTest(
        KeyPair signaturePair,
        X509Certificate signatureCert,
        String signatureAlgorithm,
        AlgorithmIdentifier digestAlgorithm)
        throws Exception
    {
        ConfigurableProvider provider = (ConfigurableProvider)Security.getProvider(BC);

        if (!provider.hasAlgorithm("Signature", signatureAlgorithm))
        {
            return;
        }

        List certList = new ArrayList();
        List crlList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(signatureCert);
        certList.add(_origCert);

        crlList.add(_signCrl);

        Store certs = new JcaCertStore(certList);
        Store crlStore = new JcaCRLStore(crlList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(signaturePair.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(contentSigner, signatureCert));

        gen.addCertificates(certs);
        gen.setDefiniteLengthEncoding(true);
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

            if (digestAlgorithm != null)
            {
                assertEquals(signer.getDigestAlgorithmID().getAlgorithm().toString() + " " + digestAlgorithm.getAlgorithm(), signer.getDigestAlgorithmID(), digestAlgorithm);
            }

            if (signatureAlgorithm.indexOf("RSA") > 0)
            {
                BCRSAPublicKey publicKey = (BCRSAPublicKey)signaturePair.getPublic();
                AsymmetricKeyParameter pubkey = new RSAKeyParameters(false, publicKey.getModulus(), publicKey.getPublicExponent());
                assertTrue(signer.verify(
                    new BcRSASignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider()).build(pubkey)));
            }
            else if (signatureAlgorithm.indexOf("ECDSA") > 0)
            {
                BCECPublicKey publicKey = (BCECPublicKey)signaturePair.getPublic();
                AsymmetricKeyParameter pubkey = new ECPublicKeyParameters(publicKey.getQ(), new ECDomainParameters(publicKey.getParameters().getCurve(),
                    publicKey.getParameters().getG(), publicKey.getParameters().getN(), publicKey.getParameters().getH(), publicKey.getParameters().getSeed()));

                assertTrue(signer.verify(
                    new BcECSignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider()).build(pubkey)));
            }
            else if (signatureAlgorithm.equals("ED448"))
            {
                BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey)signaturePair.getPublic();
                AsymmetricKeyParameter pubkey = new Ed448PublicKeyParameters(publicKey.getPointEncoding());
                assertTrue(signer.verify(
                    new BcEdDSASignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider()).build(pubkey)));
            }
            else
            {
                assertTrue(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
            }
        }

        //
        // check for CRLs
        //
        Collection crls = crlStore.getMatches(null);

        assertEquals(1, crls.size());

        assertTrue(crls.contains(new JcaX509CRLHolder(_signCrl)));

        //
        // try using existing signer
        //

        gen = new CMSSignedDataGenerator();

        gen.addSigners(s.getSignerInfos());

        gen.addCertificates(s.getCertificates());

        s = gen.generate(msg, true);

        bIn = new ByteArrayInputStream(s.getEncoded());
        aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certs = s.getCertificates();

        signers = s.getSignerInfos();
        c = signers.getSigners();
        it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }

        checkSignerStoreReplacement(s, signers);

        //
        // check signer information lookup
        //

        byte[] ext = signatureCert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        SignerId sid = new JcaSignerId(signatureCert.getIssuerX500Principal(), signatureCert.getSerialNumber(), ASN1OctetString.getInstance(ASN1OctetString.getInstance(ext).getOctets()).getOctets());
        assertFalse(sid.equals(certs));
        assertFalse(sid.equals(new JcaSignerId(signatureCert.getIssuerX500Principal(), signatureCert.getSerialNumber())));
        Collection collection = signers.getSigners((SignerId)sid.clone());

        assertEquals(1, collection.size());
        SignerInformation si = (SignerInformation)collection.iterator().next();
        assertFalse(sid.match(si));
    }

    private void checkSignerStoreReplacement(
        CMSSignedData orig,
        SignerInformationStore signers)
        throws Exception
    {
        CMSSignedData s = CMSSignedData.replaceSigners(orig, signers);

        Store certs = s.getCertificates();

        signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }
    }

    public void testSHA1WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA1withRSA", null);
    }

    public void testEd448()
        throws Exception
    {
        encapsulatedTest(_signEd448KP, _signEd448Cert, "ED448", new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256_len, new ASN1Integer(512)));
    }

    public void testSHA1WithRSAEncapsulatedSubjectKeyID()
        throws Exception
    {
        subjectKeyIDTest(_signKP, _signCert, "SHA1withRSA");
    }

    public void testSHA1WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA1withRSAandMGF1");
    }

    public void testSHA224WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA224withRSAandMGF1");
    }

    public void testSHA256WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA256withRSAandMGF1");
    }

    public void testSHA384WithRSAPSS()
        throws Exception
    {
        rsaPSSTest("SHA384withRSAandMGF1");
    }

    public void testSHA224WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA224withRSA", null);
    }

    public void testSHA256WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "SHA256withRSA", null);
    }

    public void testRIPEMD128WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "RIPEMD128withRSA", null);
    }

    public void testRIPEMD160WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "RIPEMD160withRSA", null);
    }

    public void testRIPEMD256WithRSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signKP, _signCert, "RIPEMD256withRSA", null);
    }

    public void testECDSAEncapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA1withECDSA", null);
    }

    public void testECDSAEncapsulatedSubjectKeyID()
        throws Exception
    {
        subjectKeyIDTest(_signEcDsaKP, _signEcDsaCert, "SHA1withECDSA");
    }

    public void testECDSASHA224Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA224withECDSA", null);
    }

    public void testECDSASHA256Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA256withECDSA", null);
    }

    public void testECDSASHA384Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA384withECDSA", null);
    }

    public void testECDSASHA512Encapsulated()
        throws Exception
    {
        encapsulatedTest(_signEcDsaKP, _signEcDsaCert, "SHA512withECDSA", null);
    }

    private void subjectKeyIDTest(
        KeyPair signaturePair,
        X509Certificate signatureCert,
        String signatureAlgorithm)
        throws Exception
    {
        List certList = new ArrayList();
        List crlList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello World!".getBytes());

        certList.add(signatureCert);
        certList.add(_origCert);

        crlList.add(_signCrl);

        Store certStore = new JcaCertStore(certList);
        Store crlStore = new JcaCRLStore(crlList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(signaturePair.getPrivate());

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(contentSigner, CMSTestUtil.createSubjectKeyId(signatureCert.getPublicKey()).getKeyIdentifier()));

        gen.addCertificates(certStore);
        gen.addCRLs(crlStore);

        CMSSignedData s = gen.generate(msg, true);

        assertEquals(3, s.getVersion());

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certStore = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }

        //
        // check for CRLs
        //
        Collection crls = crlStore.getMatches(null);

        assertEquals(1, crls.size());

        assertTrue(crls.contains(new JcaX509CRLHolder(_signCrl)));

        //
        // try using existing signer
        //

        gen = new CMSSignedDataGenerator();

        gen.addSigners(s.getSignerInfos());

        gen.addCertificates(s.getCertificates());
        gen.setDefiniteLengthEncoding(true);
        s = gen.generate(msg, true);

        bIn = new ByteArrayInputStream(s.getEncoded());
        aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certStore = s.getCertificates();

        signers = s.getSignerInfos();
        c = signers.getSigners();
        it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));
        }

        checkSignerStoreReplacement(s, signers);
    }

    private void rsaPSSTest(String signatureAlgorithmName)
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(BC).build(_origKP.getPrivate());

        JcaSignerInfoGeneratorBuilder siBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        siBuilder.setDirectSignature(true);

        gen.addSignerInfoGenerator(siBuilder.build(contentSigner, _origCert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, false);

        //
        // compute expected content digest
        //
        String digestName = signatureAlgorithmName.substring(0, signatureAlgorithmName.indexOf('w'));
        MessageDigest md = MessageDigest.getInstance(digestName, BC);

        verifySignatures(s, md.digest("Hello world!".getBytes()));
    }

    public void testSHA1WithRSANoAttributesSimple()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(_origCert);
        certList.add(_signCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder().setProvider(new BouncyCastleProvider()).setDirectSignature(true);

        gen.addSignerInfoGenerator(builder.build("SHA1withRSA", _origKP.getPrivate(), new JcaX509CertificateHolder(_origCert)));//.getPublicKey().getEncoded()));
        //new IssuerAndSerialNumber(new JcaX509CertificateHolder(_origCert).toASN1Structure()).getEncoded()));

        gen.addCertificates(certs);
        gen.setDefiniteLengthEncoding(true);

        CMSSignedData s = gen.generate(msg, true);

        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);

        verifySignatures(s, md.digest("Hello world!".getBytes()));
    }

    public void testSHA1WithRSA()
        throws Exception
    {
        List certList = new ArrayList();
        List crlList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(_origCert);
        certList.add(_signCert);

        crlList.add(_signCrl);
        crlList.add(_origCrl);

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator(digAlgFinder);

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(new JcaCertStore(certList));
        gen.addCRLs(new JcaCRLStore(crlList));

        OutputStream sigOut = gen.open(bOut);

        CMSCompressedDataStreamGenerator cGen = new CMSCompressedDataStreamGenerator();

        cGen.setBufferSize(4096);

        OutputStream cOut = cGen.open(sigOut, new ZlibCompressor());

        cOut.write(MiscDataStreamTest.TEST_MESSAGE.getBytes());

        cOut.close();

        sigOut.close();

        checkSigParseable(bOut.toByteArray());

        // generate compressed stream
        ByteArrayOutputStream cDataOut = new ByteArrayOutputStream();

        cOut = cGen.open(cDataOut, new ZlibCompressor());

        cOut.write(MiscDataStreamTest.TEST_MESSAGE.getBytes());

        cOut.close();

        CMSSignedDataParser sp = new CMSSignedDataParser(digCalcProv,
            new CMSTypedStream(PKCSObjectIdentifiers.data.getId(), new ByteArrayInputStream(cDataOut.toByteArray())), bOut.toByteArray());

        sp.getSignedContent().drain();
        assertEquals(PKCSObjectIdentifiers.data.toString(), sp.getSignedContentTypeOID());
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", BC);

        verifySignatures(sp, md.digest(cDataOut.toByteArray()));
    }

    private void checkSigParseable(byte[] sig)
        throws Exception
    {
        CMSSignedDataParser sp = new CMSSignedDataParser(digCalcProv, sig);
        sp.getVersion();
        CMSTypedStream sc = sp.getSignedContent();
        if (sc != null)
        {
            sc.drain();
        }
        sp.getCertificates();
        sp.getSignerInfos();
        sp.close();
    }

    private void verifySignatures(CMSSignedDataParser sp, byte[] contentDigest)
        throws Exception
    {
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

            assertEquals(true, signer.verify(new JcaSignerInfoVerifierBuilder(digCalcProv)
                .setProvider(new BouncyCastleProvider())
                .setSignatureAlgorithmFinder(sigAlgFinder)
                .setSignatureAlgorithmNameGenerator(new DefaultCMSSignatureAlgorithmNameGenerator())
                .build(cert)));

            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }
    }

    public void testDigestedData()
        throws Exception
    {
        CMSDigestedData digData = new CMSDigestedData(new ByteArrayInputStream(MiscDataStreamTest.digestedData));

        assertTrue(org.bouncycastle.util.Arrays.areEqual(MiscDataStreamTest.data, (byte[])digData.getDigestedContent().getContent()));

        assertTrue(digData.verify(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()));
    }

    public void testOriginatorInfo()
        throws Exception
    {
        ASN1ObjectIdentifier macAlg = CMSAlgorithm.DES_EDE3_CBC;
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
        adGen.setBufferSize(4096);
        adGen.setBEREncodeRecipients(true);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

        List origCerts = new ArrayList(1);
        origCerts.add(_origCert);
        adGen.setOriginatorInfo(new OriginatorInfoGenerator(new JcaCertStore(origCerts)).generate());

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        OutputStream aOut = adGen.open(bOut, new JceCMSMacCalculatorBuilder(macAlg)
            .setProvider(new BouncyCastleProvider())
            .setSecureRandom(CryptoServicesRegistrar.getSecureRandom())
            .build());

        aOut.write(data);

        aOut.close();

        CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(bOut.toByteArray());
        assertEquals(ad.getMacAlgorithm().getAlgorithm(), macAlg);
        assertNotNull(ad.getMacAlgParams());
        assertNull(ad.getUnauthAttrs());
        assertNull(ad.getContentDigest());
        assertTrue(ad.getOriginatorInfo().getCertificates().getMatches(null).contains(origCert));

        RecipientInformationStore recipients = ad.getRecipientInfos();

        assertEquals(ad.getMacAlgOID(), macAlg.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();
            assertNotNull(recipient.getKeyEncryptionAlgParams());
            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
    }

    public void testCMSAlgorithmProtection()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
        DigestCalculatorProvider calcProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};
        SecretKey kek = CMSTestUtil.makeDesede192Key();

        adGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek)
            .setProvider(new BouncyCastleProvider())
            .setSecureRandom(CryptoServicesRegistrar.getSecureRandom()));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build(),
            calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));

        checkData(data, kek, ad);

        ContentInfo adInfo = ad.toASN1Structure();
        AuthenticatedData iAd = AuthenticatedData.getInstance(adInfo.getContent().toASN1Primitive().getEncoded());

        try
        {
            new CMSAuthenticatedData(new ContentInfo(CMSObjectIdentifiers.authenticatedData,
                new AuthenticatedData(iAd.getOriginatorInfo(), iAd.getRecipientInfos(), iAd.getMacAlgorithm(), new AlgorithmIdentifier(TeleTrusTObjectIdentifiers.ripemd160, DERNull.INSTANCE), iAd.getEncapsulatedContentInfo(), iAd.getAuthAttrs(), iAd.getMac(), iAd.getUnauthAttrs())), calcProvider);
        }
        catch (CMSException e)
        {
            Assert.assertEquals(e.getMessage(), "CMS Algorithm Identifier Protection check failed for digestAlgorithm");
        }

        AlgorithmIdentifier newDigAlgId = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        Assert.assertFalse(iAd.getDigestAlgorithm().equals(newDigAlgId));
        checkData(data, kek, new CMSAuthenticatedData(new ContentInfo(CMSObjectIdentifiers.authenticatedData,
            new AuthenticatedData(iAd.getOriginatorInfo(), iAd.getRecipientInfos(), iAd.getMacAlgorithm(), newDigAlgId, iAd.getEncapsulatedContentInfo(), iAd.getAuthAttrs(), iAd.getMac(), iAd.getUnauthAttrs())), calcProvider));

        try
        {
            new CMSAuthenticatedData(new ContentInfo(CMSObjectIdentifiers.authenticatedData,
                new AuthenticatedData(iAd.getOriginatorInfo(), iAd.getRecipientInfos(), new AlgorithmIdentifier(CMSAlgorithm.AES192_CBC), iAd.getDigestAlgorithm(), iAd.getEncapsulatedContentInfo(), iAd.getAuthAttrs(), iAd.getMac(), iAd.getUnauthAttrs())), calcProvider);
        }
        catch (CMSException e)
        {
            Assert.assertEquals(e.getMessage(), "CMS Algorithm Identifier Protection check failed for macAlgorithm");
        }

        try
        {
            AlgorithmIdentifier newMacAlgId = new AlgorithmIdentifier(CMSAlgorithm.DES_EDE3_CBC);
            Assert.assertFalse(iAd.getMacAlgorithm().equals(newMacAlgId));
            new CMSAuthenticatedData(new ContentInfo(CMSObjectIdentifiers.authenticatedData,
                new AuthenticatedData(iAd.getOriginatorInfo(), iAd.getRecipientInfos(), newMacAlgId, iAd.getDigestAlgorithm(), iAd.getEncapsulatedContentInfo(), iAd.getAuthAttrs(), iAd.getMac(), iAd.getUnauthAttrs())), calcProvider);
        }
        catch (CMSException e)
        {
            Assert.assertEquals(e.getMessage(), "CMS Algorithm Identifier Protection check failed for macAlgorithm");
        }
    }

    private void checkData(byte[] data, SecretKey kek, CMSAuthenticatedData ad)
        throws CMSException
    {
        RecipientInformationStore recipients = ad.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKEKAuthenticatedRecipient(kek).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
            assertTrue(Arrays.equals(ad.getContentDigest(), recipient.getContentDigest()));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testAES256CCMContentType()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();
        ASN1ObjectIdentifier macAlg = CMSAlgorithm.AES256_CCM;
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("CCM", BC);

        algParams.init(new CCMParameters(Hex.decode("000102030405060708090a0b"), 16).getEncoded());

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

        adGen.setOriginatorInfo(new OriginatorInfoGenerator(origCert).generate());

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(PKCSObjectIdentifiers.safeContentsBag, data),
            new JceCMSMacCalculatorBuilder(macAlg).setAlgorithmParameters(algParams).setProvider(BC).build());

        assertTrue(ad.getOriginatorInfo().getCertificates().getMatches(null).contains(origCert));

        RecipientInformationStore recipients = ad.getRecipientInfos();

        assertEquals(ad.getMacAlgOID(), macAlg.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            JceKeyTransRecipient rec = new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate())
                .setProvider(new BouncyCastleProvider())
                .setContentProvider(new BouncyCastleProvider())
                .setMustProduceEncodableUnwrappedKey(true);
            byte[] recData = recipient.getContent(rec);

            assertEquals(PKCSObjectIdentifiers.safeContentsBag, recipient.getContentType());
            assertEquals(16, ad.getMac().length);
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
            assertTrue(Arrays.equals(data, recData));

            assertEquals(PKCSObjectIdentifiers.safeContentsBag, recipient.getContentStream(rec).getContentType());
        }
    }

    public void testPasswordAES256()
        throws Exception
    {

        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        adGen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(CMSAuthenticatedDataGenerator.AES256_CBC),
            "password".toCharArray()).setProvider(new BouncyCastleProvider()).setSaltAndIterationCount(new byte[20], 5));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ad.getRecipientInfos();

        assertEquals(ad.getMacAlgOID(),
            CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            PasswordRecipientInformation recipient = (PasswordRecipientInformation)it.next();

            PasswordRecipient pbeRep = new JcePasswordAuthenticatedRecipient("password".toCharArray()).setProvider(BC);

            byte[] recData = recipient.getContent(pbeRep);

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testNewCompressedData()
        throws Exception
    {
        byte[] compData = Base64
            .decode("MIAGCyqGSIb3DQEJEAEJoIAwgAIBADANBgsqhkiG9w0BCRADCDCABgkqhkiG9w0BBwGggCSABIIC"
                + "Hnic7ZRdb9owFIbvK/k/5PqVYPFXGK12YYyboVFASSp1vQtZGiLRACZE49/XHoUW7S/0tXP8Efux"
                + "fU5ivWnasml72XFb3gb5druui7ytN803M570nii7C5r8tfwR281hy/p/KSM3+jzH5s3+pbQ90xSb"
                + "P3VT3QbLusnt8WPIuN5vN/vaA2+DulnXTXkXvNTr8j8ouZmkCmGI/UW+ZS/C8zP0bz2dz0zwLt+1"
                + "UEk2M8mlaxjRMByAhZTj0RGYg4TvogiRASROsZgjpVcJCb1KV6QzQeDJ1XkoQ5Jm+C5PbOHZZGRi"
                + "v+ORAcshOGeCcdFJyfgFxdtCdEcmOrbinc/+BBMzRThEYpwl+jEBpciSGWQkI0TSlREmD/eOHb2D"
                + "SGLuESm/iKUFt1y4XHBO2a5oq0IKJKWLS9kUZTA7vC5LSxYmgVL46SIWxIfWBQd6AdrnjLmH94UT"
                + "vGxVibLqRCtIpp4g2qpdtqK1LiOeolpVK5wVQ5P7+QjZAlrh0cePYTx/gNZuB9Vhndtgujl9T/tg"
                + "W9ogK+3rnmg3YWygnTuF5GDS+Q/jIVLnCcYZFc6Kk/+c80wKwZjwdZIqDYWRH68MuBQSXLgXYXj2"
                + "3CAaYOBNJMliTl0X7eV5DnoKIFSKYdj3cRpD/cK/JWTHJRe76MUXnfBW8m7Hd5zhQ4ri2NrVF/WL"
                + "+kV1/3AGSlJ32bFPd2BsQD8uSzIx6lObkjdz95c0AAAAAAAAAAAAAAAA");

        byte[] uncompData = Base64
            .decode("Q29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9FREktWDEyOyBuYW1lPUdyb3VwMi54MTINCkNvbnRl"
                + "bnQtVHJhbnNmZXItRW5jb2Rpbmc6IGJpbmFyeQ0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5l"
                + "OyBmaWxlbmFtZT1Hcm91cDIueDEyDQoNCklTQSowMCpzc3Nzc3Nzc3NzKjAwKnJycnJycnJycnIqW"
                + "loqQ1lDTE9ORSAgICAgICAgKlpaKlBBUlRORVIgICAgICAgICo5NjEwMDcqMjAxMypVKjAwMjAwKj"
                + "AwMDAwMDAwMSowKlQqKg1HUypQTypTMVMxUzFTMVMxUzFTMVMqUjFSMVIxUjFSMVIxUjFSKjk2MTA"
                + "wNyoyMDEzKjAwMDAwMDAwNCpYKjAwMzA1MA1TVCo4NTAqMDAwMDQwMDAxDUJFRyowMCpCRSoyYSo0"
                + "MzMyNDIzNHY1NTIzKjk2MTAwNyoyM3RjNHZ5MjR2MmgzdmgzdmgqWloqSUVMKjA5KlJFKjA5DUNVU"
                + "ioxMSpUUk4qNTY1Nio2NSo1NjYqSU1GKjAwNio5NjEwMDcNUkVGKjZBKjQzM3IxYzNyMzRyMzRjMz"
                + "MxMnFjdGdjNTQqUmVmZXJlbmNlIE51bWJlcg1QRVIqQUEqSGFucyBHdXR0ZW4qQ1AqMS4zMjIuMzI"
                + "zLjQ0NDQqKioqKnJnZzRlZ3Y0dDQNVEFYKjR0Z3RidDR0cjR0cipHTCpnaGdoKioqKioqKioqRypD"
                + "DUZPQipUUCpDQSpVU0EqMDIqRE9NKkNDKlJlZ3VsYXIgTG9jYXRpb25zIHBlciBUZXJtcw1DVFAqR"
                + "EUqQzA0KjQ1MyoyNTAwMCpEOSpTRUwqMjMyMTQqMjM0MzI0MjM0MjMqRVMqNDIyNDM0MjMNU0FDKk"
                + "EqQjAwMCpBRSozNTQ1KjM0NDIzMDANQ1VSKjExKjc2Nyo3NzY3KjY1DVBPMSoxMTEtYWFhKjEwMDA"
                + "wMDAqQVMqOTAuMDAqQkQqQUsqMjM0MjM1djM1MzRxNmYzNTM0djQzNTM0NTN2cTNxMzIqKioqKioq"
                + "KioqKkExKnl0cmgNUE8xKjExMS1hYWEqMTAwMDAwMCpBUyo5MC4wMCpCRCpBSyoyMzQyMzV2MzUzN"
                + "HE2ZjM1MzR2NDM1MzQ1M3ZxM3EzMioqKioqKioqKioqQTEqeXRyaA1QTzEqMTExLWFhYSoxMDAwMD"
                + "AwKkFTKjkwLjAwKkJEKkFLKjIzNDIzNXYzNTM0cTZmMzUzNHY0MzUzNDUzdnEzcTMyKioqKioqKio"
                + "qKipBMSp5dHJoDVBPMSoxMTEtYWFhKjEwMDAwMDAqQVMqOTAuMDAqQkQqQUsqMjM0MjM1djM1MzRx"
                + "NmYzNTM0djQzNTM0NTN2cTNxMzIqKioqKioqKioqKkExKnl0cmgNUE8xKjExMS1hYWEqMTAwMDAwM"
                + "CpBUyo5MC4wMCpCRCpBSyoyMzQyMzV2MzUzNHE2ZjM1MzR2NDM1MzQ1M3ZxM3EzMioqKioqKioqKi"
                + "oqQTEqeXRyaA1QTzEqMTExLWFhYSoxMDAwMDAwKkFTKjkwLjAwKkJEKkFLKjIzNDIzNXYzNTM0cTZ"
                + "mMzUzNHY0MzUzNDUzdnEzcTMyKioqKioqKioqKipBMSp5dHJoDVBPMSoxMTEtYWFhKjEwMDAwMDAq"
                + "QVMqOTAuMDAqQkQqQUsqMjM0MjM1djM1MzRxNmYzNTM0djQzNTM0NTN2cTNxMzIqKioqKioqKioqK"
                + "kExKnl0cmgNUE8xKjExMS1hYWEqMTAwMDAwMCpBUyo5MC4wMCpCRCpBSyoyMzQyMzV2MzUzNHE2Zj"
                + "M1MzR2NDM1MzQ1M3ZxM3EzMioqKioqKioqKioqQTEqeXRyaA1QTzEqMTExLWFhYSoxMDAwMDAwKkF"
                + "TKjkwLjAwKkJEKkFLKjIzNDIzNXYzNTM0cTZmMzUzNHY0MzUzNDUzdnEzcTMyKioqKioqKioqKipB"
                + "MSp5dHJoDVBPMSoxMTEtYWFhKjEwMDAwMDAqQVMqOTAuMDAqQkQqQUsqMjM0MjM1djM1MzRxNmYzN"
                + "TM0djQzNTM0NTN2cTNxMzIqKioqKioqKioqKkExKnl0cmgNQ1RUKjENU0UqMjIqMDAwMDQwMDAxDUdFKjEqMDAwMDAwMDA0DUlFQSoxKjAwMDAwMDAwMQ0=");

        CMSCompressedData ed = new CMSCompressedData(new ByteArrayInputStream(compData));
        assertEquals(CMSObjectIdentifiers.compressedData, ed.getContentType());
        assertTrue(Arrays.equals(ed.toASN1Structure().getEncoded(), ed.getEncoded()));
        assertTrue(Arrays.equals(uncompData, ed.getContent(new ZlibExpanderProvider())));
    }

    public void testWorkingData()
        throws Exception
    {
        byte[] keyData = Base64.decode(
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKrAz/SQKrcQ" +
                "nj9IxHIfKDbuXsMqUpI06s2gps6fp7RDNvtUDDMOciWGFhD45YSy8GO0mPx3" +
                "Nkc7vKBqX4TLcqLUz7kXGOHGOwiPZoNF+9jBMPNROe/B0My0PkWg9tuq+nxN" +
                "64oD47+JvDwrpNOS5wsYavXeAW8Anv9ZzHLU7KwZAgMBAAECgYA/fqdVt+5K" +
                "WKGfwr1Z+oAHvSf7xtchiw/tGtosZ24DOCNP3fcTXUHQ9kVqVkNyzt9ZFCT3" +
                "bJUAdBQ2SpfuV4DusVeQZVzcROKeA09nPkxBpTefWbSDQGhb+eZq9L8JDRSW" +
                "HyYqs+MBoUpLw7GKtZiJkZyY6CsYkAnQ+uYVWq/TIQJBAP5zafO4HUV/w4KD" +
                "VJi+ua+GYF1Sg1t/dYL1kXO9GP1p75YAmtm6LdnOCas7wj70/G1YlPGkOP0V" +
                "GFzeG5KAmAUCQQCryvKU9nwWA+kypcQT9Yr1P4vGS0APYoBThnZq7jEPc5Cm" +
                "ZI82yseSxSeea0+8KQbZ5mvh1p3qImDLEH/iNSQFAkAghS+tboKPN10NeSt+" +
                "uiGRRWNbiggv0YJ7Uldcq3ZeLQPp7/naiekCRUsHD4Qr97OrZf7jQ1HlRqTu" +
                "eZScjMLhAkBNUMZCQnhwFAyEzdPkQ7LpU1MdyEopYmRssuxijZao5JLqQAGw" +
                "YCzXokGFa7hz72b09F4DQurJL/WuDlvvu4jdAkEAxwT9lylvfSfEQw4/qQgZ" +
                "MFB26gqB6Gqs1pHIZCzdliKx5BO3VDeUGfXMI8yOkbXoWbYx5xPid/+N8R//" +
                "+sxLBw==");

        byte[] envData = Base64.decode(
            "MIAGCSqGSIb3DQEHA6CAMIACAQAxgcQwgcECAQAwKjAlMRYwFAYDVQQKEw1C" +
                "b3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVQIBHjANBgkqhkiG9w0BAQEFAASB" +
                "gDmnaDZ0vDJNlaUSYyEXsgbaUH+itNTjCOgv77QTX2ImXj+kTctM19PQF2I1" +
                "0/NL0fjakvCgBTHKmk13a7jqB6cX3bysenHNrglHsgNGgeXQ7ggAq5fV/JQQ" +
                "T7rSxEtuwpbuHQnoVUZahOHVKy/a0uLr9iIh1A3y+yZTZaG505ZJMIAGCSqG" +
                "SIb3DQEHATAdBglghkgBZQMEAQIEENmkYNbDXiZxJWtq82qIRZKggAQgkOGr" +
                "1JcTsADStez1eY4+rO4DtyBIyUYQ3pilnbirfPkAAAAAAAAAAAAA");


        CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(envData);
        assertNotNull(ep.getEncryptionAlgParams());
        assertEquals(NISTObjectIdentifiers.id_aes128_CBC, ep.getContentEncryptionAlgorithm().getAlgorithm());
        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
        KeyFactory keyFact = KeyFactory.getInstance("RSA", BC);
        PrivateKey priKey = keyFact.generatePrivate(keySpec);
        byte[] data = Hex.decode("57616c6c6157616c6c6157617368696e67746f6e");

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            CMSTypedStream recData = recipient.getContentStream(new JceKeyTransEnvelopedRecipient(priKey).setProvider(BC));

            assertEquals(true, Arrays.equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
        }
    }

    public void testUnprotectedAttributes()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
        edGen.setBEREncodeRecipients(true);

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        Hashtable attrs = new Hashtable();

        attrs.put(PKCSObjectIdentifiers.id_aa_contentHint, new Attribute(PKCSObjectIdentifiers.id_aa_contentHint, new DERSet(new DERUTF8String("Hint"))));
        attrs.put(PKCSObjectIdentifiers.id_aa_receiptRequest, new Attribute(PKCSObjectIdentifiers.id_aa_receiptRequest, new DERSet(new DERUTF8String("Request"))));

        AttributeTable attrTable = new AttributeTable(attrs);

        edGen.setUnprotectedAttributeGenerator(new SimpleAttributeTableGenerator(attrTable));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = edGen.open(CMSObjectIdentifiers.data,
            bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        out.write(data);

        out.close();

        CMSEnvelopedDataParser ed = new CMSEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(data, recData));
        }

        attrTable = ed.getUnprotectedAttributes();

        assertEquals(attrs.size(), 2);

        assertEquals(new DERUTF8String("Hint"), attrTable.get(PKCSObjectIdentifiers.id_aa_contentHint).getAttrValues().getObjectAt(0));
        assertEquals(new DERUTF8String("Request"), attrTable.get(PKCSObjectIdentifiers.id_aa_receiptRequest).getAttrValues().getObjectAt(0));
    }

    public void testTwoAESKEK()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();
        SecretKey kek1 = CMSTestUtil.makeAES192Key();
        SecretKey kek2 = CMSTestUtil.makeAES192Key();

        CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

        byte[] kekId1 = new byte[]{1, 2, 3, 4, 5};
        byte[] kekId2 = new byte[]{5, 4, 3, 2, 1};

        edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId1, kek1).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId2, kek2).setProvider(BC));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = edGen.open(
            bOut,
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());
        out.write(data);

        out.close();

        CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        RecipientId recSel = new KEKRecipientId(kekId2);
        assertEquals(RecipientId.kek, recSel.getType());
        assertFalse(recSel.equals(ep));
        assertFalse(recSel.match(recSel.clone()));
        assertTrue(recSel.match(((KEKRecipientId)recSel.clone()).getKeyIdentifier()));

        RecipientInformation recipient = recipients.get(recSel);

        assertEquals(recipient.getKeyEncryptionAlgOID(), "2.16.840.1.101.3.4.1.25");

        CMSTypedStream recData = recipient.getContentStream(new JceKEKEnvelopedRecipient(kek2).setProvider(BC));

        assertEquals(true, Arrays.equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));

        ep.close();
    }

    public void testOriginatorInfo2()
        throws Exception
    {
        CMSEnvelopedDataParser env = new CMSEnvelopedDataParser(CMSSampleMessages.originatorMessage);

        OriginatorInformation origInfo = env.getOriginatorInfo();
        assertNotNull(origInfo.getCRLs());

        RecipientInformationStore recipients = env.getRecipientInfos();

        assertEquals(new X500Name("C=US,O=U.S. Government,OU=HSPD12Lab,OU=Agents,CN=user1"), ((X509CertificateHolder)origInfo.getCertificates().getMatches(null).iterator().next()).getSubject());
        assertEquals(CMSEnvelopedDataGenerator.DES_EDE3_CBC, env.getEncryptionAlgOID());

    }

    public void testKeyTransDESEDE3Short()
        throws Exception
    {
        byte[] data = new byte[]{0, 1, 2, 3};
        KeyFactory kf = KeyFactory.getInstance("RSA", BC);
        PrivateKey kPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(NewEnvelopedDataTest.tooShort3DESKey));

        CMSEnvelopedData ed = new CMSEnvelopedData(new ByteArrayInputStream(NewEnvelopedDataTest.tooShort3DES));

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();
            try
            {
                byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(kPriv).setKeySizeValidation(true).setProvider(BC));
                fail("invalid 3DES-EDE key not picked up");
            }
            catch (CMSException e)
            {
                assertEquals("Expected key size for algorithm OID not found in recipient.", e.getMessage());
            }

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(kPriv).setKeySizeValidation(false).setProvider(BC));
            assertEquals(true, Arrays.equals(data, recData));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testECKeyAgree()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF,
            _origEcKP.getPrivate(), _origEcKP.getPublic(),
            CMSAlgorithm.AES128_WRAP).addRecipient(_reciEcCert).setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        confirmDataReceived(recipients, data, _reciEcCert, _reciEcKP.getPrivate(), BC);
        confirmNumberRecipients(recipients, 1);

        final KeyAgreeRecipientInformation recInfo = (KeyAgreeRecipientInformation)recipients.getRecipients().iterator().next();
        assertNull(recInfo.getUserKeyingMaterial());
        assertTrue(recInfo.getOriginator().getOriginatorKey() != null);
        assertEquals(X9ObjectIdentifiers.prime239v1, recInfo.getOriginator().getOriginatorKey().getAlgorithm().getParameters());
    }

    private static void confirmDataReceived(RecipientInformationStore recipients,
                                            byte[] expectedData, X509Certificate reciCert, PrivateKey reciPrivKey, String provider)
        throws CMSException, NoSuchProviderException, CertificateEncodingException, IOException
    {
        RecipientId rid = new JceKeyAgreeRecipientId(reciCert);

        RecipientInformation recipient = recipients.get(rid);
        assertNotNull(recipient);

        byte[] actualData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(reciPrivKey).setProvider(provider));
        assertEquals(true, Arrays.equals(expectedData, actualData));
    }

    private static void confirmNumberRecipients(RecipientInformationStore recipients, int count)
    {
        assertEquals(count, recipients.getRecipients().size());
    }

    public void testOpenSSLVectors()
        throws Exception
    {
        PEMParser pemParser = new PEMParser(new InputStreamReader(getClass().getResourceAsStream("ecdh/ecc.key")));
        assertEquals(17, pemParser.getSupportedTypes().size());
    }
}
