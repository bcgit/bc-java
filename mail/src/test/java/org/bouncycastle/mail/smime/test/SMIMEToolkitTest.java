package org.bouncycastle.mail.smime.test;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEToolkit;
import org.bouncycastle.openssl.jcajce.JcaPKIXIdentityBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.pkix.jcajce.JcaPKIXIdentity;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

public class SMIMEToolkitTest
    extends TestCase
{

    static MimeBodyPart    msg;

    static MimeBodyPart    msgR;
    static MimeBodyPart    msgRN;

    static String _origDN;
    static KeyPair _origKP;
    static X509Certificate _origCert;

    static String _signDN;
    static KeyPair _signKP;
    static X509Certificate _signCert;

    static String          _reciDN;
    static KeyPair         _reciKP;
    static X509Certificate _reciCert;

    private static KeyPair         _signGostKP;
    private static X509Certificate _signGostCert;

    private static KeyPair         _signEcDsaKP;
    private static X509Certificate _signEcDsaCert;

    private static KeyPair         _signEcGostKP;
    private static X509Certificate _signEcGostCert;

    KeyPair         dsaSignKP;
    X509Certificate dsaSignCert;

    KeyPair         dsaOrigKP;
    X509Certificate dsaOrigCert;
    private static final String BC = "BC";

    static
    {
        try
        {
            if (Security.getProvider("BC") == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }

            msg      = SMIMETestUtil.makeMimeBodyPart("Hello world!\n");

            msgR     = SMIMETestUtil.makeMimeBodyPart("Hello world!\r");
            msgRN    = SMIMETestUtil.makeMimeBodyPart("Hello world!\r\n");

            _origDN = "O=Bouncy Castle, C=AU";
            _origKP = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN);

            _signDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN);

            _signGostKP   = CMSTestUtil.makeGostKeyPair();
            _signGostCert = CMSTestUtil.makeCertificate(_signGostKP, _signDN, _origKP, _origDN);

            _signEcDsaKP   = CMSTestUtil.makeEcDsaKeyPair();
            _signEcDsaCert = CMSTestUtil.makeCertificate(_signEcDsaKP, _signDN, _origKP, _origDN);

            _signEcGostKP = CMSTestUtil.makeEcGostKeyPair();
            _signEcGostCert = CMSTestUtil.makeCertificate(_signEcGostKP, _signDN, _origKP, _origDN);

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
        }
        catch (Exception e)
        {
            throw new RuntimeException("problem setting up signed test class: " + e);
        }
    }

    public void testSignedMessageRecognitionMultipart()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);

        Assert.assertTrue(toolkit.isSigned(smm));

        MimeMessage body = makeMimeMessage(smm);

        Assert.assertTrue(toolkit.isSigned(body));
    }

    public void testSignedMessageRecognitionEncapsulated()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeBodyPart res = generateEncapsulated();

        Assert.assertTrue(toolkit.isSigned(res));

        MimeMessage body = makeMimeMessage(res);

        Assert.assertTrue(toolkit.isSigned(body));
    }

    public void testEncryptedRecognition()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());
        MimeBodyPart    msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        MimeBodyPart res = gen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        Assert.assertTrue(toolkit.isEncrypted(res));

        MimeMessage body = makeMimeMessage(res);

        Assert.assertTrue(toolkit.isEncrypted(body));
    }

    public void testCertificateExtractionEncapsulated()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeBodyPart res = generateEncapsulated();

        SMIMESigned smimeSigned = new SMIMESigned(res);

        SignerInformation signerInformation = (SignerInformation)smimeSigned.getSignerInfos().getSigners().iterator().next();

        assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(res, signerInformation));

        MimeMessage body = makeMimeMessage(res);

        assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(body, signerInformation));
    }

    public void testCertificateExtractionMultipart()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);

        SMIMESigned smimeSigned = new SMIMESigned(smm);

        SignerInformation signerInformation = (SignerInformation)smimeSigned.getSignerInfos().getSigners().iterator().next();

        assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(smm, signerInformation));

        MimeMessage body = makeMimeMessage(smm);

        assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(body, signerInformation));
    }

    public void testSignedMessageVerificationMultipart()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeMultipart smm = generateMultiPartRsa("SHA1withRSA", msg, SMIMESignedGenerator.RFC3851_MICALGS);

        Assert.assertTrue(toolkit.isValidSignature(smm, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));

        MimeMessage body = makeMimeMessage(smm);

        Assert.assertTrue(toolkit.isValidSignature(body, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));
    }

    public void testSignedMessageVerificationEncapsulated()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeBodyPart res = generateEncapsulated();

        Assert.assertTrue(toolkit.isValidSignature(res, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));

        MimeMessage body = makeMimeMessage(res);

        Assert.assertTrue(toolkit.isValidSignature(body, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));
    }

    public void testSignedMessageVerificationEncapsulatedWithPKIXIdentity()
        throws Exception
    {
        JcaPKIXIdentity identity = openIdentityResource("smimeTKkey.pem", "smimeTKcert.pem");

        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        List certList = new ArrayList();

        certList.add(identity.getCertificate());

        Store certs = new CollectionStore(certList);

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", identity.getPrivateKey(), identity.getX509Certificate()));

        gen.addCertificates(certs);

        MimeBodyPart res = gen.generateEncapsulated(msg);

        Assert.assertTrue(toolkit.isValidSignature(res, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(identity.getCertificate())));

        MimeMessage body = makeMimeMessage(res);

        Assert.assertTrue(toolkit.isValidSignature(body, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(identity.getCertificate())));
        Assert.assertTrue(toolkit.isValidSignature(body, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(identity.getX509Certificate())));
    }

    public void testEncryptedMimeBodyPart()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeBodyPart res = toolkit.encrypt(msg, new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CBC).setProvider(BC).build(), new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        Assert.assertTrue(toolkit.isEncrypted(res));

        MimeBodyPart dec = toolkit.decrypt(res, new JceKeyTransRecipientId(_reciCert), new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        SMIMETestUtil.verifyMessageBytes(msg, dec);
    }

    public void testEncryptedMimeBodyPartWithPKIXIdentity()
        throws Exception
    {
        JcaPKIXIdentity identity = openIdentityResource("smimeTKkey.pem", "smimeTKcert.pem");

        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeBodyPart res = toolkit.encrypt(msg, new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CBC).setProvider(BC).build(), new JceKeyTransRecipientInfoGenerator(identity.getX509Certificate()).setProvider(BC));

        Assert.assertTrue(toolkit.isEncrypted(res));

        MimeBodyPart dec = toolkit.decrypt(res, identity.getRecipientId(), new JceKeyTransEnvelopedRecipient(identity.getPrivateKey()).setProvider(BC));

        SMIMETestUtil.verifyMessageBytes(msg, dec);
    }

    public void testEncryptedMessage()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeMessage message = makeMimeMessage(msg);
        MimeBodyPart res = toolkit.encrypt(message, new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CBC).setProvider(BC).build(), new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        Assert.assertTrue(toolkit.isEncrypted(res));

        MimeMessage body = makeMimeMessage(res);

        MimeBodyPart dec = toolkit.decrypt(body, new JceKeyTransRecipientId(_reciCert), new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        SMIMETestUtil.verifyMessageBytes(message, dec);
    }

    public void testEncryptedSignedMultipart()
        throws Exception
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeBodyPart res = signEncrypt(msg, _signKP.getPrivate(), _signCert, _reciCert);

        Assert.assertTrue(toolkit.isEncrypted(res));

        MimeMessage body = makeMimeMessage(res);

        MimeBodyPart dec = toolkit.decrypt(body, new JceKeyTransRecipientId(_reciCert), new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        Assert.assertTrue(toolkit.isSigned(dec));

        Assert.assertTrue(toolkit.isValidSignature(dec, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));

        SMIMETestUtil.verifyMessageBytes(msg, (MimeBodyPart)((MimeMultipart)dec.getContent()).getBodyPart(0));
    }

    private MimeBodyPart signEncrypt(MimeBodyPart msg, PrivateKey signerKey, X509Certificate signerCert, X509Certificate recipientCert)
        throws OperatorCreationException, CertificateEncodingException, SMIMEException, CMSException, MessagingException
    {
        SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

        MimeMultipart smm = toolkit.sign(msg, new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", signerKey, signerCert));

        return toolkit.encrypt(smm, new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CBC).setProvider(BC).build(), new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider(BC));
    }

    public void testSignedMessageGenerationMultipart()
         throws Exception
     {
         SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

         MimeMultipart smm = toolkit.sign(msg, new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", _signKP.getPrivate(), _signCert));

         Assert.assertTrue(toolkit.isValidSignature(smm, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));

         SMIMESigned smimeSigned = new SMIMESigned(smm);

         SignerInformation signerInformation = (SignerInformation)smimeSigned.getSignerInfos().getSigners().iterator().next();

         assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(smm, signerInformation));

         Properties props = System.getProperties();
         Session session = Session.getDefaultInstance(props, null);

         Address fromUser = new InternetAddress("\"Eric H. Echidna\"<eric@bouncycastle.org>");
         Address toUser = new InternetAddress("example@bouncycastle.org");

         MimeMessage body = new MimeMessage(session);
         body.setFrom(fromUser);
         body.setRecipient(Message.RecipientType.TO, toUser);
         body.setSubject("example signed message");
         body.setContent(smm, smm.getContentType());
         body.saveChanges();

         Assert.assertTrue(toolkit.isValidSignature(body, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));
     }

     public void testSignedMessageGenerationEncapsulated()
         throws Exception
     {
         SMIMEToolkit toolkit = new SMIMEToolkit(new BcDigestCalculatorProvider());

         MimeBodyPart res = toolkit.signEncapsulated(msg, new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA1withRSA", _signKP.getPrivate(), _signCert));

         Assert.assertTrue(toolkit.isValidSignature(res, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));

         SMIMESigned smimeSigned = new SMIMESigned(res);

         SignerInformation signerInformation = (SignerInformation)smimeSigned.getSignerInfos().getSigners().iterator().next();

         assertEquals(new JcaX509CertificateHolder(_signCert), toolkit.extractCertificate(res, signerInformation));

         Properties props = System.getProperties();
         Session session = Session.getDefaultInstance(props, null);

         Address fromUser = new InternetAddress("\"Eric H. Echidna\"<eric@bouncycastle.org>");
         Address toUser = new InternetAddress("example@bouncycastle.org");

         MimeMessage body = new MimeMessage(session);
         body.setFrom(fromUser);
         body.setRecipient(Message.RecipientType.TO, toUser);
         body.setSubject("example signed message");
         body.setContent(res.getContent(), res.getContentType());
         body.saveChanges();

         Assert.assertTrue(toolkit.isValidSignature(body, new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(_signCert)));
     }

    private MimeMultipart generateMultiPartRsa(
        String       algorithm,
        MimeBodyPart msg,
        Map micalgs)
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(_signCert);
        certList.add(_origCert);

        Store certs = new JcaCertStore(certList);

        SMIMESignedGenerator gen = new SMIMESignedGenerator(micalgs);

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build(algorithm, _signKP.getPrivate(), _signCert));
        gen.addCertificates(certs);

        return gen.generate(msg);
    }

    private MimeMessage makeMimeMessage(MimeBodyPart res)
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
        body.setContent(res.getContent(), res.getContentType());
        body.saveChanges();

        return body;
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

    private JcaPKIXIdentity openIdentityResource(
        String          keyFileName,
        String          certFileName)
        throws IOException, CertificateException
    {
        InputStream keyRes = this.getClass().getResourceAsStream(keyFileName);
        InputStream certRes = this.getClass().getResourceAsStream(certFileName);

        return new JcaPKIXIdentityBuilder().setProvider(BC).build(keyRes, certRes);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(SMIMEToolkitTest.class);
    }

    public static Test suite()
    {
        return new SMIMETestSetup(new TestSuite(SMIMEToolkitTest.class));
    }
}
