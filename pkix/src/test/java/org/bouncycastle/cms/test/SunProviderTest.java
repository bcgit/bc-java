package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
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
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class SunProviderTest
    extends TestCase
{
    static KeyPair keyPair;
    static X509Certificate keyCert;
    private static final String TEST_MESSAGE = "Hello World!";
    private static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

    static
    {
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
        CMSProcessable msg = new CMSProcessableByteArray(TEST_MESSAGE.getBytes());

        certList.add(keyCert);

        CertStore certsAndCrls = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "SUN");

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSigner(keyPair.getPrivate(), keyCert, CMSSignedDataGenerator.DIGEST_SHA1);

        gen.addCertificatesAndCRLs(certsAndCrls);

        CMSSignedData s = gen.generate(msg, true, "SunRsaSign");

        ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

        certsAndCrls = s.getCertificatesAndCRLs("Collection", "SUN");

        SignerInformationStore signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection          certCollection = certsAndCrls.getCertificates(selectorConverter.getCertSelector(signer.getSID()));

            Iterator        certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate)certIt.next();

            assertEquals(true, signer.verify(cert, "SunRsaSign"));
        }
    }

    public void testSHA1WithRSAStream()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        certList.add(keyCert);

        CertStore           certsAndCrls = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "SUN");

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(keyPair.getPrivate(), keyCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, "SunRsaSign");

        gen.addCertificatesAndCRLs(certsAndCrls);

        OutputStream sigOut = gen.open(bOut);

        sigOut.write(TEST_MESSAGE.getBytes());

        sigOut.close();

        CMSSignedDataParser sp = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), bOut.toByteArray());

        sp.getSignedContent().drain();

        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", "SUN");

        byte[]                  contentDigest = md.digest(TEST_MESSAGE.getBytes());
        CertStore               certStore = sp.getCertificatesAndCRLs("Collection", "SUN");
        SignerInformationStore  signers = sp.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getCertificates(selectorConverter.getCertSelector(signer.getSID()));

            Iterator        certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate)certIt.next();

            assertEquals(true, signer.verify(cert, "SunRsaSign"));

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

        edGen.addKeyTransRecipient(keyCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                algorithm, "SunJCE");

        RecipientInformationStore recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), algorithm);

        Collection  c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(keyPair.getPrivate(), "SunJCE");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    private static KeyPair generateKeyPair()
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        KeyPairGenerator    kpg  = KeyPairGenerator.getInstance("RSA", "SunRsaSign");

        kpg.initialize(512, new SecureRandom());

        return kpg.generateKeyPair();
    }

    private static X509Certificate makeCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException
    {

        PublicKey subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();

        v3CertGen.reset();
        v3CertGen.setSerialNumber(BigInteger.valueOf(1));
        v3CertGen.setIssuerDN(new X509Name(_issDN));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis()));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)));
        v3CertGen.setSubjectDN(new X509Name(_subDN));
        v3CertGen.setPublicKey(subPub);

        v3CertGen.setSignatureAlgorithm("SHA1WithRSA");

        X509Certificate _cert = v3CertGen.generate(issPriv, "SunRsaSign");

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    public static Test suite()
        throws Exception
    {
        return new TestSuite(SunProviderTest.class);
    }
}
