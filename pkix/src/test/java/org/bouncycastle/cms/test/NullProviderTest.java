package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

public class NullProviderTest
    extends TestCase
{
    static KeyPair keyPair;
    static X509Certificate keyCert;
    private static final String TEST_MESSAGE = "Hello World!";
    private static BigInteger       serialNumber;
    private JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

    static
    {
        serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        try
        {
            keyPair = generateKeyPair();
            String origDN = "O=Bouncy Castle, C=AU";
            keyCert = makeCertificate(keyPair, origDN, keyPair, origDN);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    public void testSHA1WithRSAEncapsulated()
        throws Exception
    {
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray(TEST_MESSAGE.getBytes());

        certList.add(new X509CertificateHolder(keyCert.getEncoded()));

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("SHA1withRSA").build(keyPair.getPrivate()), keyCert));

        gen.addCertificates(new CollectionStore(certList));

        CMSSignedData s = gen.generate(msg, true);

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        Store certsAndCrls = s.getCertificates();

        SignerInformationStore signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation     signer = (SignerInformation)it.next();
            Collection            certCollection = certsAndCrls.getMatches(signer.getSID());
            Iterator              certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));
        }
    }

    public void testSHA1WithRSAStream()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(new X509CertificateHolder(keyCert.getEncoded()));

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digCalcProv).build(new JcaContentSignerBuilder("SHA1withRSA").build(keyPair.getPrivate()), keyCert));

        gen.addCertificates(new CollectionStore(certList));

        OutputStream sigOut = gen.open(bOut);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser sp = new CMSSignedDataParser(digCalcProv,
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), bOut.toByteArray());

        sp.getSignedContent().drain();

        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1");

        byte[]                  contentDigest = md.digest(TEST_MESSAGE.getBytes());
        Store                   certStore = sp.getCertificates();
        SignerInformationStore  signers = sp.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert)));

            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }
    }

    public void testKeyTransDES()
        throws Exception
    {
        testKeyTrans(CMSEnvelopedDataGenerator.DES_EDE3_CBC);
    }

    public void testKeyTransAES128()
        throws Exception
    {
        testKeyTrans(CMSEnvelopedDataGenerator.AES128_CBC);
    }

    public void testKeyTransAES192()
        throws Exception
    {
        testKeyTrans(CMSEnvelopedDataGenerator.AES192_CBC);
    }

    public void testKeyTransAES256()
        throws Exception
    {
        testKeyTrans(CMSEnvelopedDataGenerator.AES256_CBC);
    }

    private void testKeyTrans(String algorithm)
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(keyCert));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(algorithm)).build());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), algorithm);

        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(keyPair.getPrivate()));

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    private static KeyPair generateKeyPair()
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        KeyPairGenerator kpg  = KeyPairGenerator.getInstance("RSA", "SunRsaSign");

        kpg.initialize(512, new SecureRandom());

        return kpg.generateKeyPair();
    }

    public static X509Certificate makeCertificate(KeyPair _subKP,
                                                  String _subDN, KeyPair _issKP, String _issDN)
        throws Exception
    {
        PublicKey _subPub = _subKP.getPublic();
        PrivateKey _issPriv = _issKP.getPrivate();
        PublicKey _issPub = _issKP.getPublic();

        X509v3CertificateBuilder _v3CertGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            _subPub);

        X509CertificateHolder _cert = _v3CertGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(_issPriv));

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(_cert);
    }

    private static BigInteger allocateSerialNumber()
    {
        BigInteger _tmp = serialNumber;
        serialNumber = serialNumber.add(BigInteger.valueOf(1));
        return _tmp;
    }

    public static Test suite()
        throws Exception
    {
        return new TestSuite(NullProviderTest.class);
    }
}
