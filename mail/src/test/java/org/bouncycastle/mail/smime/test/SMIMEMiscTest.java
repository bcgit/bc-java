package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.ZlibCompressor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMECompressedGenerator;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class SMIMEMiscTest
    extends TestCase
{
    static MimeBodyPart    msg;

    static String          signDN;
    static KeyPair         signKP;
    static X509Certificate signCert;

    static String          origDN;
    static KeyPair         origKP;
    static X509Certificate origCert;

    static String          reciDN;
    static KeyPair         reciKP;
    static X509Certificate reciCert;

    private static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

    KeyPair         dsaSignKP;
    X509Certificate dsaSignCert;

    KeyPair         dsaOrigKP;
    X509Certificate dsaOrigCert;
    
    static
    {
        try
        {
            if (Security.getProvider("BC") == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }

            msg      = SMIMETestUtil.makeMimeBodyPart("Hello world!\n");
            
            signDN   = "O=Bouncy Castle, C=AU";
            signKP   = CMSTestUtil.makeKeyPair();
            signCert = CMSTestUtil.makeCertificate(signKP, signDN, signKP, signDN);
    
            origDN   = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
            origKP   = CMSTestUtil.makeKeyPair();
            origCert = CMSTestUtil.makeCertificate(origKP, origDN, signKP, signDN);
        }
        catch (Exception e)
        {
            throw new RuntimeException("problem setting up signed test class: " + e);
        }
    }

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public SMIMEMiscTest(String name)
    {
        super(name);
    }

    public static void main(String args[]) 
    {
        Security.addProvider(new BouncyCastleProvider());
        
        junit.textui.TestRunner.run(SMIMEMiscTest.class);
    }

    public void testSHA256WithRSAParserEncryptedWithAES()
        throws Exception
    {
        List certList = new ArrayList();
        
        certList.add(origCert);
        certList.add(signCert);
    
        Store certs = new JcaCertStore(certList);
    
        SMIMEEnvelopedGenerator  encGen = new SMIMEEnvelopedGenerator();
        
        encGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(origCert).setProvider("BC"));

        MimeBodyPart   mp = encGen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build());
        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator();
    
        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA256withRSA", origKP.getPrivate(), origCert));
        gen.addCertificates(certs);

        MimeMultipart     smm = gen.generate(mp);
        File              tmpFile = File.createTempFile("bcTest", ".mime");

        MimeMessage       msg = createMimeMessage(tmpFile, smm);
        
        SMIMESignedParser s = new SMIMESignedParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), (MimeMultipart)msg.getContent());

        certs = s.getCertificates();

        verifyMessageBytes(mp, s.getContent());
    
        verifySigners(certs, s.getSignerInfos());
        
        tmpFile.delete();
    }
    
    public void testSHA256WithRSACompressed()
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(origCert);
        certList.add(signCert);

        Store certs = new JcaCertStore(certList);

        SMIMECompressedGenerator  cGen = new SMIMECompressedGenerator();

        MimeBodyPart   mp = cGen.generate(msg, new ZlibCompressor());

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA256withRSA", origKP.getPrivate(), origCert));
        gen.addCertificates(certs);

        MimeMultipart     smm = gen.generate(mp);
        File              tmpFile = File.createTempFile("bcTest", ".mime");

        MimeMessage       msg = createMimeMessage(tmpFile, smm);

        SMIMESigned       s = new SMIMESigned((MimeMultipart)msg.getContent());

        certs = s.getCertificates();

        verifyMessageBytes(mp, s.getContent());

        verifySigners(certs, s.getSignerInfos());

        tmpFile.delete();
    }

    public void testQuotePrintableSigPreservation()
        throws Exception
    {
        MimeMessage msg = new MimeMessage((Session)null, getClass().getResourceAsStream("qp-soft-break.eml"));

        SMIMEEnvelopedGenerator  encGen = new SMIMEEnvelopedGenerator();

        encGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(origCert).setProvider("BC"));

        MimeBodyPart   mp = encGen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build());

        SMIMEEnveloped       env = new SMIMEEnveloped(mp);
        RecipientInformation ri = (RecipientInformation)env.getRecipientInfos().getRecipients().iterator().next();
        MimeBodyPart         mm = SMIMEUtil.toMimeBodyPart(ri.getContentStream(new JceKeyTransEnvelopedRecipient(origKP.getPrivate()).setProvider("BC")));
        SMIMESigned          s = new SMIMESigned((MimeMultipart)mm.getContent());
        Collection           c = s.getSignerInfos().getSigners();
        Iterator             it = c.iterator();
        Store            certs = s.getCertificates();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
        }

        ((FileBackedMimeBodyPart)mm).dispose();
    }

    public void testSHA256WithRSAParserCompressed()
        throws Exception
    {
        List certList = new ArrayList();

        certList.add(origCert);
        certList.add(signCert);

        Store certs = new JcaCertStore(certList);

        SMIMECompressedGenerator  cGen = new SMIMECompressedGenerator();

        MimeBodyPart   mp = cGen.generate(msg, new ZlibCompressor());

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA256withRSA", origKP.getPrivate(), origCert));
        gen.addCertificates(certs);

        MimeMultipart     smm = gen.generate(mp);
        File              tmpFile = File.createTempFile("bcTest", ".mime");

        MimeMessage       msg = createMimeMessage(tmpFile, smm);

        SMIMESignedParser s = new SMIMESignedParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), (MimeMultipart)msg.getContent());

        certs = s.getCertificates();

        verifyMessageBytes(mp, s.getContent());

        verifySigners(certs, s.getSignerInfos());

        tmpFile.delete();
    }

    public void testBrokenEnvelope()
        throws Exception
    {
        Session session = Session.getDefaultInstance(System.getProperties(), null);
        MimeMessage msg = new MimeMessage(session, getClass().getResourceAsStream("brokenEnv.message"));

        try
        {
            new SMIMEEnveloped(msg);
        }
        catch (CMSException e)
        {
            if (!e.getMessage().equals("Malformed content."))
            {
                fail("wrong exception on bogus envelope");
            }
        }
    }

    private void verifySigners(Store certs, SignerInformationStore signers)
        throws Exception
    {
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();
    
        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());
    
            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
    
            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
        }
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
    
    /**
     * Create a mime message representing the multipart. We need to do
     * this as otherwise no raw content stream for the message will exist.
     */
    private MimeMessage createMimeMessage(File tmpFile, MimeMultipart smm) 
        throws Exception
    {
        FileOutputStream  fOut = new FileOutputStream(tmpFile);
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

        body.writeTo(fOut);
        
        fOut.close();

        return new MimeMessage(session, new FileInputStream(tmpFile));
    }
    
    private ASN1EncodableVector generateSignedAttributes()
    {
        ASN1EncodableVector         signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector       caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));
        
        return signedAttrs;
    }
}
