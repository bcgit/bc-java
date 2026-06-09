package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import javax.crypto.Cipher;
import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.ZlibCompressor;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.CMSProcessableBodyPart;
import org.bouncycastle.mail.smime.CMSProcessableBodyPartOutbound;
import org.bouncycastle.mail.smime.SMIMECompressed;
import org.bouncycastle.mail.smime.SMIMECompressedGenerator;
import org.bouncycastle.mail.smime.SMIMECompressedParser;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedParser;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.mail.smime.SMIMEToolkit;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.mail.smime.util.CRLFOutputStream;
import org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;
import org.bouncycastle.mail.smime.validator.SignedMailValidator;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class MailGeneralTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        MailGeneralTest test = new MailGeneralTest();
        test.setUp();
        test.testSignedMessageVerificationMultipart();
        test.testParser();
        test.testCompressedSHA1WithRSA();
        test.testSelfSignedCert();
        test.testSHA1WithRSAEncapsulatedParser();
        test.testSHA1WithRSA();
        test.testDESEDE3Encrypted();
        test.testParserDESEDE3Encrypted();
        test.testIDEAEncrypted();
        test.testRC2Encrypted();
        test.testCASTEncrypted();
        test.testAES128Encrypted();
        test.testAES192Encrypted();
        test.testAES256Encrypted();
        test.testSubKeyId();
        test.testDotNetEncMailMatch();
        test.testAES128();
        test.testAES192();
        test.testAES256();
        test.testCapEncrypt();
        test.testTwoRecipients();
        test.testKDFAgreements();
    }

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    static MimeBodyPart msg;
    private static String _signDN;
    private static KeyPair _signKP;
    static String _origDN;
    static KeyPair _origKP;
    private static String _reciDN;
    private static KeyPair _reciKP;
    private static X509Certificate _reciCert;
    static X509Certificate _origCert;

    private static String _reciDN2;
    private static KeyPair _reciKP2;
    private static X509Certificate _reciCert2;

    private static KeyPair _origEcKP;
    private static KeyPair _reciEcKP;
    private static X509Certificate _reciEcCert;
    private static KeyPair _reciEcKP2;
    private static X509Certificate _reciEcCert2;
    static X509Certificate _signCert;

    private static boolean _initialised = false;

    protected interface TestExceptionOperation
    {
        void operation()
            throws Exception;
    }

    protected Exception testException(String failMessage, String exceptionClass, TestExceptionOperation operation)
    {
        try
        {
            operation.operation();
            fail(failMessage);
        }
        catch (Exception e)
        {
            if (failMessage != null)
            {
                assertTrue(e.getMessage(), e.getMessage().contains(failMessage));
            }
            assertTrue(e.getClass().getName().contains(exceptionClass));
            return e;
        }
        return null;
    }

    public void setUp()
        throws Exception
    {
        if (!_initialised)
        {
            if (Security.getProvider("BC") == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }

            _initialised = true;

            msg = SMIMETestUtil.makeMimeBodyPart("Hello world!\n");

            _signDN = "O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();

            _origDN = "O=Bouncy Castle, C=AU";
            _origKP = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

            _reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _reciDN2 = "CN=Fred, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP2 = CMSTestUtil.makeKeyPair();
            _reciCert2 = CMSTestUtil.makeCertificate(_reciKP2, _reciDN2, _signKP, _signDN);

            _origEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
            _reciEcKP2 = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert2 = CMSTestUtil.makeCertificate(_reciEcKP2, _reciDN2, _signKP, _signDN);
        }
    }

    private MimeMessage loadMessage(String name)
        throws MessagingException, FileNotFoundException
    {
        Session session = Session.getDefaultInstance(System.getProperties(), null);

        return new MimeMessage(session, getClass().getResourceAsStream(name));
    }

    private X509Certificate loadCert(String name)
        throws Exception
    {
        return (X509Certificate)CertificateFactory.getInstance("X.509", BC).generateCertificate(getClass().getResourceAsStream(name));
    }

    private PrivateKey loadKey(String name)
        throws Exception
    {
        return new JcaPEMKeyConverter().setProvider("BC").getKeyPair((PEMKeyPair)(new PEMParser(new InputStreamReader(getClass().getResourceAsStream(name)))).readObject()).getPrivate();
    }

    public void testHeaders()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();
        gen.setBerEncodeRecipients(true);
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        assertEquals("application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data", mp.getHeader("Content-Type")[0]);
        assertEquals("attachment; filename=\"smime.p7m\"", mp.getHeader("Content-Disposition")[0]);
        assertEquals("S/MIME Encrypted Message", mp.getHeader("Content-Description")[0]);
    }

    public void testDESEDE3Encrypted()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String algorithm = SMIMEEnvelopedGenerator.DES_EDE3_CBC;

        verifyAlgorithm(algorithm, msg);
    }

    public void testParserDESEDE3Encrypted()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String algorithm = SMIMEEnvelopedGenerator.DES_EDE3_CBC;

        verifyParserAlgorithm(algorithm, msg);
    }

    public void testIDEAEncrypted()
        throws Exception
    {
        if (isPresent("IDEA"))
        {
            MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
            String algorithm = SMIMEEnvelopedGenerator.IDEA_CBC;

            verifyAlgorithm(algorithm, msg);
        }
    }

    private boolean isPresent(String algorithm)
        throws Exception
    {
        try
        {
            Cipher.getInstance(algorithm, BC);

            return true;
        }
        catch (NoSuchAlgorithmException e)
        {
            return false;
        }
    }

    public void testRC2Encrypted()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String algorithm = SMIMEEnvelopedGenerator.RC2_CBC;

        verifyAlgorithm(algorithm, msg);
    }

    public void testCASTEncrypted()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String algorithm = SMIMEEnvelopedGenerator.CAST5_CBC;

        verifyAlgorithm(algorithm, msg);
    }

    public void testAES128Encrypted()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String algorithm = SMIMEEnvelopedGenerator.AES128_CBC;

        verifyAlgorithm(algorithm, msg);
    }

    public void testAES192Encrypted()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String algorithm = SMIMEEnvelopedGenerator.AES192_CBC;

        verifyAlgorithm(algorithm, msg);
    }

    public void testAES256Encrypted()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String algorithm = SMIMEEnvelopedGenerator.AES256_CBC;

        verifyAlgorithm(algorithm, msg);
    }

    public void testSubKeyId()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

        //
        // create a subject key id - this has to be done the same way as
        // it is done in the certificate associated with the private key
        //
        MessageDigest dig = MessageDigest.getInstance("SHA1", BC);
        dig.update(SubjectPublicKeyInfo.getInstance(_reciCert.getPublicKey().getEncoded()).getPublicKeyData().getBytes());


        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(dig.digest(), _reciCert.getPublicKey()).setProvider(BC));

        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        SMIMEEnveloped m = new SMIMEEnveloped(mp);

        dig.update(SubjectPublicKeyInfo.getInstance(_reciCert.getPublicKey().getEncoded()).getPublicKeyData().getBytes());

        RecipientId recId = new KeyTransRecipientId(dig.digest());

        RecipientInformationStore recipients = m.getRecipientInfos();
        RecipientInformation recipient = recipients.get(recId);

        MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        SMIMETestUtil.verifyMessageBytes(msg, res);
    }

    public void testDotNetEncMailMatch()
        throws Exception
    {
        MimeMessage message = loadMessage("dotnet_encrypted_mail.eml");

        SMIMEEnveloped env = new SMIMEEnveloped(message);

        RecipientInformationStore store = env.getRecipientInfos();

        assertNotNull(store.get(new JceKeyTransRecipientId(loadCert("dotnet_enc_cert.pem"))));
    }

    public void testAES128()
        throws Exception
    {
        MimeMessage message = loadMessage("test128.message");

        SMIMEEnveloped env = new SMIMEEnveloped(message);

        RecipientInformationStore store = env.getRecipientInfos();

        RecipientInformation recipInfo = store.get(new JceKeyTransRecipientId(loadCert("cert.pem")));

        assertNotNull(recipInfo);

        byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(loadKey("key.pem")));

        assertTrue(org.bouncycastle.util.Arrays.areEqual(NewSMIMEEnvelopedTest.testMessage, content));
    }

    public void testAES192()
        throws Exception
    {
        MimeMessage message = loadMessage("test192.message");

        SMIMEEnveloped env = new SMIMEEnveloped(message);

        RecipientInformationStore store = env.getRecipientInfos();

        RecipientInformation recipInfo = store.get(new JceKeyTransRecipientId(loadCert("cert.pem")));

        assertNotNull(recipInfo);

        byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(loadKey("key.pem")));

        assertTrue(org.bouncycastle.util.Arrays.areEqual(NewSMIMEEnvelopedTest.testMessage, content));
    }

    public void testAES256()
        throws Exception
    {
        MimeMessage message = loadMessage("test256.message");

        SMIMEEnveloped env = new SMIMEEnveloped(message);

        RecipientInformationStore store = env.getRecipientInfos();

        RecipientInformation recipInfo = store.get(new JceKeyTransRecipientId(loadCert("cert.pem")));

        assertNotNull(recipInfo);

        byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(loadKey("key.pem")));

        assertTrue(org.bouncycastle.util.Arrays.areEqual(NewSMIMEEnvelopedTest.testMessage, content));
    }

    public void testCapEncrypt()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

        //
        // create a subject key id - this has to be done the same way as
        // it is done in the certificate associated with the private key
        //
        MessageDigest dig = MessageDigest.getInstance("SHA1", BC);

        dig.update(_reciCert.getPublicKey().getEncoded());

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(dig.digest(), _reciCert.getPublicKey()).setProvider(BC));

        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //
        MimeBodyPart mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider(BC).build());

        SMIMEEnveloped m = new SMIMEEnveloped(mp);

        dig.update(_reciCert.getPublicKey().getEncoded());

        RecipientId recId = new KeyTransRecipientId(dig.digest());

        RecipientInformationStore recipients = m.getRecipientInfos();
        RecipientInformation recipient = recipients.get(recId);

        MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        SMIMETestUtil.verifyMessageBytes(msg, res);
    }

    public void testTwoRecipients()
        throws Exception
    {
        MimeBodyPart _msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert2).setProvider(BC));

        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //
        MimeBodyPart mp = gen.generate(_msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider(BC).build());

        SMIMEEnvelopedParser m = new SMIMEEnvelopedParser(mp);
        assertNotNull(m.getEncryptedContent());
        RecipientId recId = getRecipientId(_reciCert2);

        RecipientInformationStore recipients = m.getRecipientInfos();
        RecipientInformation recipient = recipients.get(recId);

        FileBackedMimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContentStream(new JceKeyTransEnvelopedRecipient(_reciKP2.getPrivate()).setProvider(BC)));

        SMIMETestUtil.verifyMessageBytes(_msg, res);

        m = new SMIMEEnvelopedParser(mp);

        res.dispose();

        recId = getRecipientId(_reciCert);

        recipients = m.getRecipientInfos();
        recipient = recipients.get(recId);

        res = SMIMEUtil.toMimeBodyPart(recipient.getContentStream(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        SMIMETestUtil.verifyMessageBytes(_msg, res);

        res.dispose();
    }

    private void verifyAlgorithm(
        String algorithmOid,
        MimeBodyPart msg)
        throws Exception
    {
        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(algorithmOid)).setProvider(BC).build());
        SMIMEEnveloped m = new SMIMEEnveloped(mp);
        RecipientId recId = getRecipientId(_reciCert);

        RecipientInformationStore recipients = m.getRecipientInfos();
        RecipientInformation recipient = recipients.get(recId);

        MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        SMIMETestUtil.verifyMessageBytes(msg, res);
    }

    private void verifyParserAlgorithm(
        String algorithmOid,
        MimeBodyPart msg)
        throws Exception
    {
        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(algorithmOid)).setProvider(BC).build());
        SMIMEEnvelopedParser m = new SMIMEEnvelopedParser(mp);
        RecipientId recId = getRecipientId(_reciCert);

        RecipientInformationStore recipients = m.getRecipientInfos();
        RecipientInformation recipient = recipients.get(recId);

        MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC)));

        SMIMETestUtil.verifyMessageBytes(msg, res);
    }

    private RecipientId getRecipientId(
        X509Certificate cert)
        throws IOException, CertificateEncodingException
    {
        RecipientId recId = new JceKeyTransRecipientId(cert);

        return recId;
    }

    public void testKDFAgreements()
        throws Exception
    {
        MimeBodyPart msg = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA1KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA224KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA256KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA384KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA512KDF, true);

        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA1KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA224KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA256KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA384KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA512KDF, true);

        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA1KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA224KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA256KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA384KDF, true);
        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA512KDF, true);

        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA1KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA224KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA256KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA384KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECDH_SHA512KDF, false);

        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA1KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA224KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA256KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA384KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECCDH_SHA512KDF, false);

        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA1KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA224KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA256KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA384KDF, false);
        doTryAgreement(msg, CMSAlgorithm.ECMQV_SHA512KDF, false);
    }

    private void doTryAgreement(MimeBodyPart data, ASN1ObjectIdentifier algorithm, boolean berEncodeRecipientSet)
        throws Exception
    {
        SMIMEEnvelopedGenerator edGen = new SMIMEEnvelopedGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(algorithm,
            _origEcKP.getPrivate(), _origEcKP.getPublic(),
            CMSAlgorithm.AES128_WRAP).addRecipient(_reciEcCert).setProvider(BC));
        edGen.setBerEncodeRecipients(berEncodeRecipientSet);
        MimeBodyPart res = edGen.generate(
            data,
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());

        SMIMEEnveloped ed = new SMIMEEnveloped(res);

        assertNotNull(ed.getEncryptedContent());

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);

        RecipientInformationStore recipients = ed.getRecipientInfos();

        IssuerAndSerialNumber issuerAndSerialNumber = SMIMEUtil.createIssuerAndSerialNumberFor(_reciCert);
        assertEquals(_reciCert.getSerialNumber(), issuerAndSerialNumber.getSerialNumber().getValue());
        assertEquals(new X500Name(_signDN), issuerAndSerialNumber.getName());
        confirmDataReceived(recipients, data, _reciEcCert, _reciEcKP.getPrivate(), BC);
        confirmNumberRecipients(recipients, 1);
    }

    private static void confirmDataReceived(RecipientInformationStore recipients,
                                            MimeBodyPart expectedData, X509Certificate reciCert, PrivateKey reciPrivKey, String provider)
        throws Exception
    {
        RecipientId rid = new JceKeyAgreeRecipientId(reciCert);

        RecipientInformation recipient = recipients.get(rid);
        assertNotNull(recipient);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        expectedData.writeTo(bOut);

        byte[] actualData = recipient.getContent(new JceKeyAgreeEnvelopedRecipient(reciPrivKey).setProvider(provider));
        assertEquals(true, Arrays.equals(bOut.toByteArray(), actualData));
    }

    private static void confirmNumberRecipients(RecipientInformationStore recipients, int count)
    {
        assertEquals(count, recipients.getRecipients().size());
    }

    public void testSHA1WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);
        SMIMESigned s = new SMIMESigned(smm);
        Session session = Session.getDefaultInstance(System.getProperties(), null);
        MimeMessage message = s.getContentAsMimeMessage(session);
        assertEquals(message.getContent(), msg.getContent());
        assertEquals(((MimeMultipart)s.getContentWithSignature()).getBodyPart(0).getContent(), msg.getContent());
        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificates(), s.getSignerInfos());

        CMSProcessableBodyPartOutbound pbpo = new CMSProcessableBodyPartOutbound(smm.getBodyPart(0));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        pbpo.write(bOut);
        assertEquals("Hello world!\r\n", new MimeBodyPart(new ByteArrayInputStream(bOut.toByteArray())).getContent());
        assertEquals("Hello world!\n", ((MimeBodyPart)pbpo.getContent()).getContent());

        CMSProcessableBodyPart pbp = new CMSProcessableBodyPart(smm.getBodyPart(0));

        bOut = new ByteArrayOutputStream();
        pbp.write(bOut);
        assertEquals("Hello world!\n", new MimeBodyPart(new ByteArrayInputStream(bOut.toByteArray())).getContent());
        assertEquals("Hello world!\n", ((MimeBodyPart)pbp.getContent()).getContent());

        pbpo = new CMSProcessableBodyPartOutbound(smm.getBodyPart(0), "binary");
        bOut = new ByteArrayOutputStream();
        CRLFOutputStream cOut = new CRLFOutputStream(bOut);
        pbpo.write(cOut);
        assertEquals("Hello world!\r\n", new MimeBodyPart(new ByteArrayInputStream(bOut.toByteArray())).getContent());
        assertEquals("Hello world!\n", ((MimeBodyPart)pbpo.getContent()).getContent());

        final MimeBodyPart sig = new MimeBodyPart();

        sig.setContent(new byte[100], "application/pkcs7-signature; name=smime.p7s; smime-type=signed-data");
        sig.addHeader("Content-Type", "application/pkcs7-signature; name=smime.p7s; smime-type=signed-data");
        sig.addHeader("Content-Disposition", "attachment; filename=\"smime.p7s\"");
        sig.addHeader("Content-Description", "S/MIME Cryptographic Signature");
        sig.addHeader("Content-Transfer-Encoding", "base64");
        StringBuffer header = new StringBuffer("signed; protocol=\"application/pkcs7-signature\"");

        List allSigners = new ArrayList();


        allSigners.add(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC)
            .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator()).build("SHA1withRSA", _signKP.getPrivate(), _signCert));

        addHashHeader(header, allSigners);

        final MimeMultipart mm = new MimeMultipart(header.toString());
        MimeBodyPart part1 = createTemplate("text/html", "7bit");
        MimeBodyPart part2 = createTemplate("text/xml", "7bit");
        mm.addBodyPart(part1);
        mm.addBodyPart(part2);

        final MimeMessage mimeMessage = makeMimeMessage(mm);
        final SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());
        final SignerInformationVerifier singerInformation = new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert);
        testException("CMS processing failure:", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                toolkit.isValidSignature(mm, singerInformation);
            }
        });

        testException("CMS processing failure:", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                toolkit.isValidSignature(mimeMessage, singerInformation);
            }
        });

        MimeBodyPart res = generateEncapsulated();

        SMIMESigned smimeSigned = new SMIMESigned(res);

        final SignerInformation signerInformation = (SignerInformation)smimeSigned.getSignerInfos().getSigners().iterator().next();
        testException("CMS processing failure:", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                toolkit.extractCertificate(mm, signerInformation);
            }
        });

        testException("CMS processing failure:", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                toolkit.extractCertificate(mimeMessage, signerInformation);
            }
        });

        testException("CMS processing failure:", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                toolkit.decrypt(mimeMessage, new JceKeyTransRecipientId(_reciCert), new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
            }
        });

        testException("CMS processing failure:", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                toolkit.decrypt(sig, new JceKeyTransRecipientId(_reciCert), new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
            }
        });



//        s = new SMIMESigned(mm);
//
//        s.getContentAsMimeMessage(session);
//        s.getContent();
    }

    private MimeBodyPart createTemplate(String contentType, String contentTransferEncoding)
        throws UnsupportedEncodingException, MessagingException
    {
        byte[] content = "<?xml version=\"1.0\"?>\n<INVOICE_CENTER>\n  <CONTENT_FRAME>\n</CONTENT_FRAME>\n</INVOICE_CENTER>\n".getBytes("US-ASCII");

        InternetHeaders ih = new InternetHeaders();
        ih.setHeader("Content-Type", contentType);
        ih.setHeader("Content-Transfer-Encoding", contentTransferEncoding);

        return new MimeBodyPart(ih, content);
    }

    private MimeMultipart generateMultiPartRsa(String algorithm, MimeBodyPart msg, Map micalgs)
        throws Exception
    {
        return generateMultiPartRsa(algorithm, msg, null, micalgs);
    }

    private MimeMultipart generateMultiPartRsa(
        String algorithm,
        MimeBodyPart msg,
        Date signingTime,
        Map micalgs)
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        Store certs = new JcaCertStore(certList);

        Store crls = new JcaCRLStore(new ArrayList());

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        if (signingTime != null)
        {
            signedAttrs.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(signingTime))));
            signedAttrs.add(new Attribute(PKCSObjectIdentifiers.id_aa_receiptRequest, new DERSet(new DERUTF8String("Request"))));
        }

        SMIMESignedGenerator gen = new SMIMESignedGenerator(micalgs);

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC)
            .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttrs))).build(algorithm, _signKP.getPrivate(), _signCert));
        gen.addCertificates(certs);
        gen.addCRLs(crls);

        MimeBodyPart mimeBodyPart = gen.generateEncapsulated(msg);
        assertNotNull(mimeBodyPart.getContent());

        return gen.generate(msg);
    }

    private void verifyMessageBytes(MimeBodyPart a, MimeBodyPart b)
        throws Exception
    {
        ByteArrayOutputStream bOut1 = new ByteArrayOutputStream();

        a.writeTo(bOut1);
        bOut1.close();

        ByteArrayOutputStream bOut2 = new ByteArrayOutputStream();

        b.writeTo(bOut2);
        bOut2.close();

        assertEquals(true, Arrays.equals(bOut1.toByteArray(), bOut2.toByteArray()));
    }

    private void verifySigners(Store certs, SignerInformationStore signers)
        throws Exception
    {
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection certCollection = certs.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)));
        }
    }

    private ASN1EncodableVector generateSignedAttributes()
    {
        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

        return signedAttrs;
    }

    public void testSHA1WithRSAEncapsulatedParser()
        throws Exception
    {
        testException("attempt to create signed data object from multipart content - use MimeMultipart constructor.", "MessagingException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMESignedParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), loadMessage("qp-soft-break.eml"));
            }
        });

        testException("attempt to create signed data object from multipart content - use MimeMultipart constructor.", "MessagingException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMESigned(loadMessage("qp-soft-break.eml"));
            }
        });

        MimeBodyPart res = generateEncapsulatedRsa("SHA1withRSA", msg);
        SMIMESignedParser s = new SMIMESignedParser(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build(), res);
        assertNotNull(s.getContentWithSignature());
        FileBackedMimeBodyPart content = (FileBackedMimeBodyPart)s.getContent();

        verifyMessageBytes(msg, content);

        content.dispose();

        verifySigners(s.getCertificates(), s.getSignerInfos());

        s.close();
    }

    private MimeBodyPart generateEncapsulatedRsa(String sigAlg, MimeBodyPart msg)
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        Store certs = new JcaCertStore(certList);

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build(sigAlg, _signKP.getPrivate(), _signCert));
        gen.addCertificates(certs);

        return gen.generateEncapsulated(msg);
    }

    public void testSelfSignedCert()
        throws Exception
    {
        String signDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        KeyPair signKP = CMSTestUtil.makeDsaKeyPair();
        ArrayList altnames = new ArrayList();
        altnames.add("test@bouncycastle.org");
        X509Certificate signCert = makeCertificate(signKP, signDN, signKP, signDN, false, "test@bouncycastle.org");

        // check basic path validation
        Set trustanchors = new HashSet();
        TrustAnchor ta = new TrustAnchor(signCert, null);
        trustanchors.add(ta);

        X509Certificate rootCert = ta.getTrustedCert();

        // init cert stores
        List certStores = new ArrayList();
        List certList = new ArrayList();
        certList.add(rootCert);
        CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
        certStores.add(store);

        // first path
        CertPath path1 = SignedMailValidator.createCertPath(rootCert, trustanchors, certStores);
        assertTrue("path size is not 1", path1.getCertificates().size() == 1);

        Object[] pathAndUserProvided = SignedMailValidator.createCertPath(rootCert, trustanchors, certStores, null);
        assertTrue("result length is not 2", pathAndUserProvided.length == 2);
        CertPath path2 = (CertPath)pathAndUserProvided[0];
        List userProvided = (List)pathAndUserProvided[1];
        assertTrue("path size is not 1", path2.getCertificates().size() == 1);
        assertTrue("user-provided size is not 1", userProvided.size() == 1);
        assertTrue("user-provided value should be false", Boolean.FALSE.equals(userProvided.get(0)));

        // check message validation
        certList = new ArrayList();

        certList.add(signCert);

        Store certs = new JcaCertStore(certList);

        Properties props = System.getProperties();
        final Session session = Session.getDefaultInstance(props, null);


        Address fromUser = new InternetAddress("\"Eric H. Echidna\"<eric@bouncycastle.org>");
        Address toUser = new InternetAddress("example@bouncycastle.org");

        final PKIXParameters params = new PKIXParameters(trustanchors);
        params.setRevocationEnabled(false);

        MimeMessage message = loadMessage("dotnet_encrypted_mail.eml");

        SMIMEEnveloped env = new SMIMEEnveloped(message);

        RecipientInformationStore ristore = env.getRecipientInfos();

        assertNotNull(ristore.get(new JceKeyTransRecipientId(loadCert("dotnet_enc_cert.pem"))));
        final MimeMessage msg = new MimeMessage(session);

        // Create a MimeMessage
        MimeMessage mimeMessage = new MimeMessage(session);

        // Set the content type to "application/pkcs7-mime"
        mimeMessage.setHeader("Content-Type", "application/pkcs7-mime");

        // Set other necessary properties and content for the MimeMessage
        mimeMessage.setSubject("Your Subject");
        mimeMessage.setFrom(new InternetAddress("sender@example.com"));
        mimeMessage.setRecipient(MimeMessage.RecipientType.TO, new InternetAddress("recipient@example.com"));
        mimeMessage.setText("Your message content");
        msg.setFrom(fromUser);
        msg.setRecipient(Message.RecipientType.TO, toUser);

        final SMIMESignedGenerator gen = new SMIMESignedGenerator();
        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        signedAttrs.add(new Attribute(PKCSObjectIdentifiers.id_aa_receiptRequest, new DERSet(new DERUTF8String("Request"))));

        assertNotNull(gen.generate(mimeMessage));
        testException("exception getting message content.", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                gen.generateEncapsulated(new MimeMessage(session));
            }
        });

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
            .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttrs))).build("SHA1withDSA", signKP.getPrivate(), signCert));
        gen.addCertificates(certs);

        MimeMultipart signedMsg = gen.generate(mimeMessage);
        msg.setContent(signedMsg, signedMsg.getContentType());

        msg.setHeader("Sender", "sender@bouncycastle.org");
        msg.saveChanges();
        SignedMailValidator validator = new SignedMailValidator(msg, params);
        SignerInformation signer = (SignerInformation)validator
            .getSignerInformationStore().getSigners().iterator().next();

        CertStore certsAndCRLS = validator.getCertsAndCRLs();
        assertEquals(1, certsAndCRLS.getCertificates(null).size());
        assertEquals(0, certsAndCRLS.getCRLs(null).size());

        SignedMailValidator.ValidationResult res = validator.getValidationResult(signer);
        assertEquals(1, res.getCertPath().getCertificates().size());
        assertEquals(1, res.getUserProvidedCerts().size());
        assertTrue(res.isVerifiedSignature());
        assertTrue(res.isValidSignature());

        testException("Malformed content..", "SignedMailValidatorException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                MimeMessage message = loadMessage("dotnet_encrypted_mail.eml");
                new SignedMailValidator(message, params);
            }
        });

        testException("MimeMessage message is not a signed message.", "SignedMailValidatorException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SignedMailValidator(new MimeMessage(session), params);
            }
        });

        final MimeMessage mm = new MimeMessage(session);
        mm.setFrom(fromUser);
        mm.setRecipient(Message.RecipientType.TO, toUser);
        mm.setContent(message, signedMsg.getContentType());
        mm.setHeader("Sender", "sender@bouncycastle.org");

        //mm.saveChanges() must throw exception
        testException("unable to save message", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMECompressedGenerator().generate(mm, new ZlibCompressor());
            }
        });

        testException("unable to save message", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMEEnvelopedGenerator().generate(mm, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC).setProvider("BC").build());
            }
        });

        testException("unable to save message", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMESignedGenerator().generate(mm);
            }
        });

        testException("unable to save message", "SMIMEException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMESignedGenerator().generateEncapsulated(mm);
            }
        });

        testException("unknown object in writeTo ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                mm.writeTo(new ByteArrayOutputStream());
            }
        });
    }

    public static X509Certificate makeCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN, boolean _ca, String subjectAltName)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        PublicKey subPub = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey issPub = issKP.getPublic();

        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            CMSTestUtil.allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        JcaContentSignerBuilder contentSignerBuilder = CMSTestUtil.makeContentSignerBuilder(issPub);

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            CMSTestUtil.createSubjectKeyId(subPub));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            CMSTestUtil.createAuthorityKeyId(issPub));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(_ca));

        GeneralNames collection = new GeneralNames(new GeneralName(1, new DERIA5String(subjectAltName)));

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERTaggedObject(1, collection));
        v3CertGen.addExtension(Extension.subjectAlternativeName, false, collection);

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    public void testCompressedSHA1WithRSA()
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(_origCert);
        certList.add(_signCert);

        Store certs = new JcaCertStore(certList);

        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));
        final Session session = Session.getDefaultInstance(System.getProperties(), null);
        MimeMessage mimeMessage = new MimeMessage(session);

        // Set the content type to "application/pkcs7-mime"
        mimeMessage.setHeader("Content-Type", "application/pkcs7-mime");

        // Set other necessary properties and content for the MimeMessage
        mimeMessage.setSubject("Your Subject");
        mimeMessage.setFrom(new InternetAddress("sender@example.com"));
        mimeMessage.setRecipient(MimeMessage.RecipientType.TO, new InternetAddress("recipient@example.com"));
        mimeMessage.setText("Your message content");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.setContentTransferEncoding("base64");
        assertNotNull(gen.generateEncapsulated(mimeMessage));
        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", _origKP.getPrivate(), _origCert));

        gen.addCertificates(certs);

        SMIMECompressedGenerator cgen = new SMIMECompressedGenerator();

        MimeBodyPart cbp = cgen.generate(mimeMessage, new ZlibCompressor());

        SMIMECompressed cm = new SMIMECompressed(cbp);

        testException("can't extract input stream:", "MessagingException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMECompressed(new MimeMessage(session));
            }
        });

        MimeMessage mimeMessage1 = new MimeMessage(session, new ByteArrayInputStream(cm.getContent(new ZlibExpanderProvider())));
        assertEquals(mimeMessage1.getContent(), mimeMessage.getContent());

        SMIMECompressedParser sc = new SMIMECompressedParser(cbp, 1024);
        assertEquals(sc.getCompressedContent(), cm.getCompressedContent());


    }

    public void testParser()
        throws Exception
    {
        final Session session = Session.getDefaultInstance(System.getProperties(), null);
        final MimeMessage mimeMessage = new MimeMessage(session);
        testException("can't extract input stream:", "MessagingException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMEEnveloped(mimeMessage);
            }
        });

        testException("can't extract input stream:", "MessagingException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMESigned(mimeMessage);
            }
        });

        testException("can't extract input stream:", "MessagingException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SMIMECompressedParser(mimeMessage, 0);
            }
        });
    }

    public void testSignedMessageVerificationMultipart()
        throws Exception
    {
        final SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);

        assertTrue(toolkit.isValidSignature(smm, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));

        MimeMessage body = makeMimeMessage(smm);

        assertTrue(toolkit.isValidSignature(body, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));

        final MimeMessage mimeMessage = new MimeMessage(Session.getDefaultInstance(System.getProperties(), null));

//        mimeMessage.setHeader("Content-Type", "multipart/signed");
//        testException("Parsing failure: ", "SMIMEException", new TestExceptionOperation()
//        {
//            @Override
//            public void operation()
//                throws Exception
//            {
//                toolkit.isValidSignature(mimeMessage, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert));
//            }
//        });
//
//        testException("Parsing failure: ", "SMIMEException", new TestExceptionOperation()
//        {
//            @Override
//            public void operation()
//                throws Exception
//            {
//                toolkit.extractCertificate(mimeMessage, null);
//            }
//        });
//
//        testException("Parsing failure: ", "SMIMEException", new TestExceptionOperation()
//        {
//            @Override
//            public void operation()
//                throws Exception
//            {
//                toolkit.decrypt(mimeMessage, new JceKeyTransRecipientId(_reciCert), new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
//
//            }
//        });
    }

    private MimeMessage makeMimeMessage(MimeMultipart mm)
        throws MessagingException, IOException
    {
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        Address fromUser = new InternetAddress("\"Eric H. Echidna\"<eric@bouncycastle.org>");
        Address toUser = new InternetAddress("example@bouncycastle.org");

        MimeMessage body = new MimeMessage(session);
        body.setFrom(fromUser);
        body.setRecipient(Message.RecipientType.TO, toUser);
        body.setSubject("example message");
        body.setContent(mm, mm.getContentType());
        body.saveChanges();

        return body;
    }

    private void addHashHeader(
        StringBuffer header,
        List signers)
    {
        int count = 0;

        //
        // build the hash header
        //
        Iterator it = signers.iterator();
        Set micAlgSet = new TreeSet();
        Map micAlgs = SMIMESignedGenerator.STANDARD_MICALGS;
        while (it.hasNext())
        {
            Object signer = it.next();
            ASN1ObjectIdentifier digestOID;

            if (signer instanceof SignerInformation)
            {
                digestOID = ((SignerInformation)signer).getDigestAlgorithmID().getAlgorithm();
            }
            else
            {
                digestOID = ((SignerInfoGenerator)signer).getDigestAlgorithm().getAlgorithm();
            }

            String micAlg = (String)micAlgs.get(digestOID);

            if (micAlg == null)
            {
                micAlgSet.add("unknown");
            }
            else
            {
                micAlgSet.add(micAlg);
            }
        }

        it = micAlgSet.iterator();

        while (it.hasNext())
        {
            String alg = (String)it.next();

            if (count == 0)
            {
                if (micAlgSet.size() != 1)
                {
                    header.append("; micalg=\"");
                }
                else
                {
                    header.append("; micalg=");
                }
            }
            else
            {
                header.append(',');
            }

            header.append(alg);

            count++;
        }

        if (count != 0)
        {
            if (micAlgSet.size() != 1)
            {
                header.append('\"');
            }
        }
    }

    private MimeBodyPart generateEncapsulated()
        throws CertificateEncodingException, OperatorCreationException, SMIMEException
    {
        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        Store certs = new JcaCertStore(certList);

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", _signKP.getPrivate(), _signCert));

        gen.addCertificates(certs);

        return gen.generateEncapsulated(msg);
    }
}
