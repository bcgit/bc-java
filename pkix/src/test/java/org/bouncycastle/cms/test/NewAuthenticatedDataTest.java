package org.bouncycastle.cms.test;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import javax.crypto.SecretKey;

import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthenticatedData;
import org.bouncycastle.cms.CMSAuthenticatedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.OriginatorInfoGenerator;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;

public class NewAuthenticatedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;

    private static String _origDN;
    private static KeyPair _origKP;
    private static X509Certificate _origCert;

    private static String _reciDN;
    private static KeyPair _reciKP;
    private static X509Certificate _reciCert;

    private static KeyPair _origEcKP;
    private static KeyPair _reciEcKP;
    private static X509Certificate _reciEcCert;

    private static boolean _initialised = false;

    public boolean DEBUG = true;

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

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
        }
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    public NewAuthenticatedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(NewAuthenticatedDataTest.class);
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(NewAuthenticatedDataTest.class));
    }

    public void testKeyTransDESede()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.DES_EDE3_CBC);
    }

    public void testKeyTransDESedeWithDigest()
        throws Exception
    {
        tryKeyTransWithDigest(CMSAlgorithm.DES_EDE3_CBC);
    }

    public void testKeyTransRC2()
        throws Exception
    {
        tryKeyTrans(CMSAlgorithm.RC2_CBC);
    }

    public void testKEKDESede()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeDesede192Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"));

        DEROctetString iv = new DEROctetString(Hex.decode("0001020304050607"));
        tryKekAlgorithm(CMSTestUtil.makeDesede192Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"), iv.getEncoded());
    }

    public void testKEKDESedeWithDigest()
        throws Exception
    {
        tryKekAlgorithmWithDigest(CMSTestUtil.makeDesede192Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"));
    }

    public void testPasswordAES256()
        throws Exception
    {
        passwordTest(CMSAuthenticatedDataGenerator.AES256_CBC);
    }

    public void testECKeyAgree()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        JceKeyAgreeRecipientInfoGenerator recipientGenerator = new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(), CMSAlgorithm.AES128_WRAP).setProvider(BC);

        recipientGenerator.addRecipient(_reciEcCert);

        adGen.addRecipientInfoGenerator(recipientGenerator);

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
            RecipientInformation recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyAgreeAuthenticatedRecipient(_reciEcKP.getPrivate()).setProvider(BC));
            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public void testEncoding()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        ad = new CMSAuthenticatedData(ad.getEncoded());

        RecipientInformationStore recipients = ad.getRecipientInfos();

        assertEquals(CMSAuthenticatedDataGenerator.DES_EDE3_CBC, ad.getMacAlgOID());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
    }

    public void testOriginatorInfo()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();
        ASN1ObjectIdentifier macAlg = CMSAlgorithm.DES_EDE3_CBC;

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

        adGen.setOriginatorInfo(new OriginatorInfoGenerator(origCert).generate());

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(macAlg).setProvider(BC).build());

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

            byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
    }

    public void testAES256CCM()
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
            new CMSProcessableByteArray(data),
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

            byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertEquals(16, ad.getMac().length);
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

        adGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

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

    private void tryKeyTrans(ASN1ObjectIdentifier macAlg)
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(macAlg).setProvider(BC).build());

        RecipientInformationStore recipients = ad.getRecipientInfos();

        assertEquals(ad.getMacAlgOID(), macAlg.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
    }

    private void tryKeyTransWithDigest(ASN1ObjectIdentifier macAlg)
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
        DigestCalculatorProvider calcProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(macAlg).setProvider(BC).build(),
            calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));

        RecipientInformationStore recipients = ad.getRecipientInfos();

        assertEquals(ad.getMacAlgOID(), macAlg.getId());

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
            assertTrue(Arrays.equals(ad.getContentDigest(), recipient.getContentDigest()));
        }
    }

    private void tryKekAlgorithm(SecretKey kek, ASN1ObjectIdentifier algOid)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, OperatorCreationException
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

        adGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        RecipientInformationStore recipients = ad.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(ad.getMacAlgOID(), CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), algOid.getId());

            byte[] recData = recipient.getContent(new JceKEKAuthenticatedRecipient(kek).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
        else
        {
            fail("no recipient found");
        }
    }

    private void tryKekAlgorithm(SecretKey kek, ASN1ObjectIdentifier algOid, byte[] encodedParameters)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, OperatorCreationException, IOException
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

        adGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

        AlgorithmParameters algParams = AlgorithmParameters.getInstance(CMSAlgorithm.DES_EDE3_CBC.getId(), "BC");

        algParams.init(encodedParameters);

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setAlgorithmParameters(algParams).setProvider(BC).build());

        RecipientInformationStore recipients = ad.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(ad.getMacAlgOID(), CMSAuthenticatedDataGenerator.DES_EDE3_CBC);
        assertEquals(ad.getMacAlgorithm().getParameters(), ASN1Primitive.fromByteArray(encodedParameters));

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), algOid.getId());

            byte[] recData = recipient.getContent(new JceKEKAuthenticatedRecipient(kek).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
        else
        {
            fail("no recipient found");
        }
    }

    private void tryKekAlgorithmWithDigest(SecretKey kek, ASN1ObjectIdentifier algOid)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, OperatorCreationException
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
        DigestCalculatorProvider calcProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

        adGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build(),
            calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));

        RecipientInformationStore recipients = ad.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(ad.getMacAlgOID(), CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), algOid.getId());

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

    private void passwordTest(String algorithm)
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        adGen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(algorithm), "password".toCharArray()).setProvider(BC).setSaltAndIterationCount(new byte[20], 5));

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
}