package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedParser;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;

public class SMIMEEnvelopedTest 
    extends TestCase 
{
    private static String          _signDN;
    private static KeyPair         _signKP;  

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;
    
    private static String          _reciDN2;
    private static KeyPair         _reciKP2;
    private static X509Certificate _reciCert2;
    
    private static boolean         _initialised = false;

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            
            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();  

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            
            _reciDN2   = "CN=Fred, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP2   = CMSTestUtil.makeKeyPair();
            _reciCert2 = CMSTestUtil.makeCertificate(_reciKP2, _reciDN2, _signKP, _signDN);
        }
    }
 
    public SMIMEEnvelopedTest(
        String name) 
    {
        super(name);
    }

    public static void main(
        String args[]) 
    {
        junit.textui.TestRunner.run(SMIMEEnvelopedTest.class);
    }

    public static Test suite() 
        throws Exception 
    {
        return new SMIMETestSetup(new TestSuite(SMIMEEnvelopedTest.class));
    }

    public void setUp()
        throws Exception
    {
        init();
    }
    
    public void testHeaders()
        throws Exception
    {
        MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
          
        gen.addKeyTransRecipient(_reciCert);
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart mp = gen.generate(_msg, SMIMEEnvelopedGenerator.DES_EDE3_CBC, "BC");

        assertEquals("application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data", mp.getHeader("Content-Type")[0]);
        assertEquals("attachment; filename=\"smime.p7m\"", mp.getHeader("Content-Disposition")[0]);
        assertEquals("S/MIME Encrypted Message", mp.getHeader("Content-Description")[0]);
    }
    
    public void testDESEDE3Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.DES_EDE3_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }

    public void testParserDESEDE3Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.DES_EDE3_CBC;
        
        verifyParserAlgorithm(algorithm, msg);
    }
    
    public void testIDEAEncrypted()
        throws Exception
    {
        if (isPresent("IDEA"))
        {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.IDEA_CBC;
        
        verifyAlgorithm(algorithm, msg);
        }
    }

    private boolean isPresent(String algorithm)
        throws Exception
    {
        try
        {
            Cipher.getInstance(algorithm, "BC");

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
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.RC2_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }

    public void testCASTEncrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.CAST5_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }
    
    public void testAES128Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.AES128_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }
    
    public void testAES192Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.AES192_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }
    
    public void testAES256Encrypted()
        throws Exception
    {
        MimeBodyPart  msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");
        String        algorithm = SMIMEEnvelopedGenerator.AES256_CBC;
        
        verifyAlgorithm(algorithm, msg);
    }
    
    public void testSubKeyId()
        throws Exception
    {
        MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator   gen = new SMIMEEnvelopedGenerator();

        //
        // create a subject key id - this has to be done the same way as
        // it is done in the certificate associated with the private key
        //
        MessageDigest           dig = MessageDigest.getInstance("SHA1", "BC");
        dig.update(_reciCert.getPublicKey().getEncoded());

          
        gen.addKeyTransRecipient(_reciCert.getPublicKey(), dig.digest());
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart         mp = gen.generate(_msg, SMIMEEnvelopedGenerator.DES_EDE3_CBC, "BC");

        SMIMEEnveloped       m = new SMIMEEnveloped(mp);

        dig.update(_reciCert.getPublicKey().getEncoded());

        RecipientId          recId = new KeyTransRecipientId(dig.digest());

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);

        MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

        verifyMessageBytes(_msg, res);
    }

    public void testCapEncrypt()
        throws Exception
    {
        MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator   gen = new SMIMEEnvelopedGenerator();

        //
        // create a subject key id - this has to be done the same way as
        // it is done in the certificate associated with the private key
        //
        MessageDigest           dig = MessageDigest.getInstance("SHA1", "BC");
        dig.update(_reciCert.getPublicKey().getEncoded());

          
        gen.addKeyTransRecipient(_reciCert.getPublicKey(), dig.digest());
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //
        MimeBodyPart mp = gen.generate(_msg, SMIMEEnvelopedGenerator.RC2_CBC, 40, "BC");

        SMIMEEnveloped       m = new SMIMEEnveloped(mp);

        dig.update(_reciCert.getPublicKey().getEncoded());

        RecipientId          recId = new KeyTransRecipientId(dig.digest());

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);

        MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

        verifyMessageBytes(_msg, res);
    }
    
    public void testTwoRecipients()
        throws Exception
    {
        MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

        SMIMEEnvelopedGenerator   gen = new SMIMEEnvelopedGenerator();
          
        gen.addKeyTransRecipient(_reciCert);
        gen.addKeyTransRecipient(_reciCert2);
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //
        MimeBodyPart mp = gen.generate(_msg, SMIMEEnvelopedGenerator.RC2_CBC, 40, "BC");

        SMIMEEnvelopedParser       m = new SMIMEEnvelopedParser(mp);

        RecipientId                recId = getRecipientId(_reciCert2);

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);
        
        FileBackedMimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContentStream(_reciKP2.getPrivate(), "BC"));

        verifyMessageBytes(_msg, res);
        
        m = new SMIMEEnvelopedParser(mp);

        res.dispose();
        
        recId = getRecipientId(_reciCert);

        recipients = m.getRecipientInfos();
        recipient = recipients.get(recId);
 
        res = SMIMEUtil.toMimeBodyPart(recipient.getContentStream(_reciKP.getPrivate(), "BC"));

        verifyMessageBytes(_msg, res);
        
        res.dispose();
    }
    
    private void verifyAlgorithm(
        String algorithmOid,
        MimeBodyPart msg) 
        throws Exception
    {
        SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
          
        gen.addKeyTransRecipient(_reciCert);
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart   mp = gen.generate(msg, algorithmOid, "BC");
        SMIMEEnveloped m = new SMIMEEnveloped(mp);
        RecipientId    recId = getRecipientId(_reciCert);

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);

        MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

        verifyMessageBytes(msg, res);
    }
    
    private void verifyParserAlgorithm(
        String algorithmOid,
        MimeBodyPart msg) 
        throws Exception
    {
        SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
          
        gen.addKeyTransRecipient(_reciCert);
         
        //
        // generate a MimeBodyPart object which encapsulates the content
        // we want encrypted.
        //

        MimeBodyPart         mp = gen.generate(msg, algorithmOid, "BC");
        SMIMEEnvelopedParser m = new SMIMEEnvelopedParser(mp);
        RecipientId          recId = getRecipientId(_reciCert);

        RecipientInformationStore  recipients = m.getRecipientInfos();
        RecipientInformation       recipient = recipients.get(recId);

        MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

        verifyMessageBytes(msg, res);
    }

    private RecipientId getRecipientId(
        X509Certificate cert) 
        throws IOException, CertificateEncodingException
    {
        RecipientId          recId = new JceKeyTransRecipientId(cert);

        return recId;
    }

    private void verifyMessageBytes(MimeBodyPart a, MimeBodyPart b) 
        throws IOException, MessagingException
    {
        ByteArrayOutputStream _baos = new ByteArrayOutputStream();
        a.writeTo(_baos);
        _baos.close();
        byte[] _msgBytes = _baos.toByteArray();
        _baos = new ByteArrayOutputStream();
        b.writeTo(_baos);
        _baos.close();
        byte[] _resBytes = _baos.toByteArray();
        
        assertEquals(true, Arrays.equals(_msgBytes, _resBytes));
    }
}
