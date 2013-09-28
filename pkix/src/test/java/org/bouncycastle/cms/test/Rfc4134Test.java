package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class Rfc4134Test
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;    
    private static final String TEST_DATA_HOME = "bc.test.data.home";
    
    private static byte[] exContent = getRfc4134Data("ExContent.bin");
    private static byte[] sha1 = Hex.decode("406aec085279ba6e16022d9e0629c0229687dd48");

    private static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();
    private static final DigestCalculatorProvider digCalcProv;

    static
    {
        try
        {
            digCalcProv =  new JcaDigestCalculatorProviderBuilder().build();
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException("can't create default provider!!!");
        }
    }

    public Rfc4134Test(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        Security.addProvider(new BouncyCastleProvider());

        junit.textui.TestRunner.run(Rfc4134Test.class);
    }

    public static Test suite() 
        throws Exception
    {
        return new CMSTestSetup(new TestSuite(Rfc4134Test.class));
    }

    public void test4_1()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.1.bin");
        CMSSignedData signedData = new CMSSignedData(data);

        verifySignatures(signedData);

        CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

        verifySignatures(parser);
    }

    public void test4_2()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.2.bin");
        CMSSignedData signedData = new CMSSignedData(data);

        verifySignatures(signedData);

        CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

        verifySignatures(parser);
    }

    public void testRfc4_3()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.3.bin");
        CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(exContent), data);

        verifySignatures(signedData, sha1);

        CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv,
                new CMSTypedStream(new ByteArrayInputStream(exContent)),
                data);

        verifySignatures(parser);
    }

    public void test4_4()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.4.bin");
        byte[] counterSigCert = getRfc4134Data("AliceRSASignByCarl.cer");
        CMSSignedData signedData = new CMSSignedData(data);

        verifySignatures(signedData, sha1);

        verifySignerInfo4_4(getFirstSignerInfo(signedData.getSignerInfos()), counterSigCert);

        CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

        verifySignatures(parser);

        verifySignerInfo4_4(getFirstSignerInfo(parser.getSignerInfos()), counterSigCert);
    }

    public void test4_5()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.5.bin");
        CMSSignedData signedData = new CMSSignedData(data);

        verifySignatures(signedData);

        CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

        verifySignatures(parser);
    }

    public void test4_6()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.6.bin");
        CMSSignedData signedData = new CMSSignedData(data);

        verifySignatures(signedData);

        CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

        verifySignatures(parser);
    }

    public void test4_7()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.7.bin");
        CMSSignedData signedData = new CMSSignedData(data);

        verifySignatures(signedData);

        CMSSignedDataParser parser = new CMSSignedDataParser(digCalcProv, data);

        verifySignatures(parser);
    }

    public void test5_1()
        throws Exception
    {
        byte[] data = getRfc4134Data("5.1.bin");
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(data);

        verifyEnvelopedData(envelopedData, CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        CMSEnvelopedDataParser envelopedParser = new CMSEnvelopedDataParser(data);

        verifyEnvelopedData(envelopedParser, CMSEnvelopedDataGenerator.DES_EDE3_CBC);
    }

    public void test5_2()
        throws Exception
    {
        byte[] data = getRfc4134Data("5.2.bin");
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(data);

        verifyEnvelopedData(envelopedData, CMSEnvelopedDataGenerator.RC2_CBC);

        CMSEnvelopedDataParser envelopedParser = new CMSEnvelopedDataParser(data);

        verifyEnvelopedData(envelopedParser, CMSEnvelopedDataGenerator.RC2_CBC);
    }

    private void verifyEnvelopedData(CMSEnvelopedData envelopedData, String symAlgorithmOID)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, CMSException
    {
        byte[]              privKeyData = getRfc4134Data("BobPrivRSAEncrypt.pri");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyData);
        KeyFactory keyFact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = keyFact.generatePrivate(keySpec);

        RecipientInformationStore recipients = envelopedData.getRecipientInfos();

        assertEquals(envelopedData.getEncryptionAlgOID(), symAlgorithmOID);

        Collection c = recipients.getRecipients();
        assertTrue(c.size() >= 1 && c.size() <= 2);

        Iterator it = c.iterator();
        verifyRecipient((RecipientInformation)it.next(), privKey);

        if (c.size() == 2)
        {
            RecipientInformation recInfo = (RecipientInformation)it.next();

            assertEquals(PKCSObjectIdentifiers.id_alg_CMSRC2wrap.getId(), recInfo.getKeyEncryptionAlgOID());
        }
    }

    private void verifyEnvelopedData(CMSEnvelopedDataParser envelopedParser, String symAlgorithmOID)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, CMSException
    {
        byte[]              privKeyData = getRfc4134Data("BobPrivRSAEncrypt.pri");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyData);
        KeyFactory keyFact = KeyFactory.getInstance("RSA", BC);
        PrivateKey privKey = keyFact.generatePrivate(keySpec);

        RecipientInformationStore recipients = envelopedParser.getRecipientInfos();

        assertEquals(envelopedParser.getEncryptionAlgOID(), symAlgorithmOID);

        Collection c = recipients.getRecipients();
        assertTrue(c.size() >= 1 && c.size() <= 2);

        Iterator it = c.iterator();
        verifyRecipient((RecipientInformation)it.next(), privKey);

        if (c.size() == 2)
        {
            RecipientInformation recInfo = (RecipientInformation)it.next();

            assertEquals(PKCSObjectIdentifiers.id_alg_CMSRC2wrap.getId(), recInfo.getKeyEncryptionAlgOID());
        }
    }

    private void verifyRecipient(RecipientInformation recipient, PrivateKey privKey)
        throws CMSException, NoSuchProviderException
    {
        assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

        byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

        assertEquals(true, Arrays.equals(exContent, recData));
    }

    private void verifySignerInfo4_4(SignerInformation signerInfo, byte[] counterSigCert)
        throws Exception
    {
        verifyCounterSignature(signerInfo, counterSigCert);

        verifyContentHint(signerInfo);
    }

    private SignerInformation getFirstSignerInfo(SignerInformationStore store)
    {
        return (SignerInformation)store.getSigners().iterator().next();
    }

    private void verifyCounterSignature(SignerInformation signInfo, byte[] certificate)
        throws Exception
    {
        SignerInformation csi = (SignerInformation)signInfo.getCounterSignatures().getSigners().iterator().next();

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);
        X509Certificate    cert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(certificate));

        assertTrue(csi.verify(new JcaSignerInfoVerifierBuilder(digCalcProv).setProvider(BC).build(cert)));
    }

    private void verifyContentHint(SignerInformation signInfo)
    {
        AttributeTable attrTable = signInfo.getUnsignedAttributes();

        Attribute attr = attrTable.get(CMSAttributes.contentHint);

        assertEquals(1, attr.getAttrValues().size());

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String("Content Hints Description Buffer"));
        v.add(CMSObjectIdentifiers.data);
        
        assertTrue(attr.getAttrValues().getObjectAt(0).equals(new DERSequence(v)));
    }

    private void verifySignatures(CMSSignedData s, byte[] contentDigest)
        throws Exception
    {
        Store               certStore = s.getCertificates();
        SignerInformationStore  signers = s.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            verifySigner(signer, cert);

            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }
    }

    private void verifySignatures(CMSSignedData s)
        throws Exception
    {
        verifySignatures(s, null);
    }

    private void verifySignatures(CMSSignedDataParser sp)
        throws Exception
    {
        CMSTypedStream sc = sp.getSignedContent();
        if (sc != null)
        {
            sc.drain();
        }
        
        Store certs = sp.getCertificates();
        SignerInformationStore  signers = sp.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            verifySigner(signer, cert);
        }
    }

    private void verifySigner(SignerInformation signer, X509CertificateHolder certHolder)
        throws Exception
    {
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        if (cert.getPublicKey() instanceof DSAPublicKey)
        {
            DSAPublicKey key = (DSAPublicKey)cert.getPublicKey();

            if (key.getParams() == null)
            {
                assertEquals(true, signer.verify(new JcaSignerInfoVerifierBuilder(digCalcProv).setProvider(BC).build(getInheritedKey(key))));
            }
            else
            {
                assertEquals(true, signer.verify(new JcaSignerInfoVerifierBuilder(digCalcProv).setProvider(BC).build(cert)));
            }
        }
        else
        {
            assertEquals(true, signer.verify(new JcaSignerInfoVerifierBuilder(digCalcProv).setProvider(BC).build(cert)));
        }
    }

    private PublicKey getInheritedKey(DSAPublicKey key)
        throws Exception
    {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", BC);

        X509Certificate cert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(getRfc4134Data("CarlDSSSelf.cer")));

        DSAParams dsaParams = ((DSAPublicKey)cert.getPublicKey()).getParams();

        DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(
                        key.getY(), dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

        KeyFactory keyFactory = KeyFactory.getInstance("DSA", BC);

        return keyFactory.generatePublic(dsaPubKeySpec);
    }

    private static byte[] getRfc4134Data(String name)
    {
        String dataHome = System.getProperty(TEST_DATA_HOME);

        if (dataHome == null)
        {
            throw new IllegalStateException(TEST_DATA_HOME + " property not set");
        }

        try
        {
            return Streams.readAll(new FileInputStream(dataHome + "/rfc4134/" + name));
        }
        catch (IOException e)
        {
            throw new RuntimeException(e.toString());
        }
    }
}
