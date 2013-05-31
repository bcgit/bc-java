package org.bouncycastle.cms.test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import javax.crypto.SecretKey;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAuthenticatedData;
import org.bouncycastle.cms.CMSAuthenticatedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSPBEKey;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.PKCS5Scheme2PBEKey;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class AuthenticatedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String          _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;

    private static KeyPair         _origEcKP;
    private static KeyPair         _reciEcKP;
    private static X509Certificate _reciEcCert;

    private static boolean         _initialised = false;

    public boolean DEBUG = true;
    
    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;

            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
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
    
    public AuthenticatedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(AuthenticatedDataTest.class);
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(AuthenticatedDataTest.class));
    }

    public void testKeyTransDESede()
        throws Exception
    {
        tryKeyTrans(CMSAuthenticatedDataGenerator.DES_EDE3_CBC);
    }

    public void testKEKDESede()
        throws Exception
    {
        tryKekAlgorithm(CMSTestUtil.makeDesede192Key(), new DERObjectIdentifier("1.2.840.113549.1.9.16.3.6"));
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

        adGen.addKeyAgreementRecipient(CMSAuthenticatedDataGenerator.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(), _reciEcCert, CMSAuthenticatedDataGenerator.AES128_WRAP, BC);

        CMSAuthenticatedData ad = adGen.generate(
                              new CMSProcessableByteArray(data),
                              CMSAuthenticatedDataGenerator.DES_EDE3_CBC, BC);

        RecipientInformationStore  recipients = ad.getRecipientInfos();

        assertEquals(ad.getMacAlgOID(),
                CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciEcKP.getPrivate(), BC);
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
        byte[]          data     = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        adGen.addKeyTransRecipient(_reciCert);

        CMSAuthenticatedData ad = adGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSAuthenticatedDataGenerator.DES_EDE3_CBC, BC);

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

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), BC);

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
    }

    private void tryKeyTrans(String macAlg)
        throws Exception
    {
        byte[]          data     = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        adGen.addKeyTransRecipient(_reciCert);

        CMSAuthenticatedData ad = adGen.generate(
                                new CMSProcessableByteArray(data),
                                macAlg, BC);

        RecipientInformationStore recipients = ad.getRecipientInfos();

        assertEquals(ad.getMacAlgOID(), macAlg);

        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), BC);

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
    }

    private void tryKekAlgorithm(SecretKey kek, DERObjectIdentifier algOid)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        byte[]          data     = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        byte[]  kekId = new byte[] { 1, 2, 3, 4, 5 };

        adGen.addKEKRecipient(kek, kekId);

        CMSAuthenticatedData ad = adGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSAuthenticatedDataGenerator.DES_EDE3_CBC, BC);

        RecipientInformationStore recipients = ad.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        assertEquals(ad.getMacAlgOID(), CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), algOid.getId());

            byte[] recData = recipient.getContent(kek, BC);

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
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

        adGen.addPasswordRecipient(new PKCS5Scheme2PBEKey("password".toCharArray(), new byte[20], 5), algorithm);

        CMSAuthenticatedData ad = adGen.generate(
                              new CMSProcessableByteArray(data),
                              CMSAuthenticatedDataGenerator.DES_EDE3_CBC, BC);

        RecipientInformationStore  recipients = ad.getRecipientInfos();

        assertEquals(ad.getMacAlgOID(),
                                   CMSAuthenticatedDataGenerator.DES_EDE3_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        if (it.hasNext())
        {
            PasswordRecipientInformation recipient = (PasswordRecipientInformation)it.next();

            CMSPBEKey key = new PKCS5Scheme2PBEKey("password".toCharArray(),
                recipient.getKeyDerivationAlgParameters(BC));

            byte[] recData = recipient.getContent(key, BC);

            assertTrue(Arrays.equals(data, recData));
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
        else
        {
            fail("no recipient found");
        }
    }
}