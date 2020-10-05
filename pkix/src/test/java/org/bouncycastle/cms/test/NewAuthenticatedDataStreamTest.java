package org.bouncycastle.cms.test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthenticatedDataParser;
import org.bouncycastle.cms.CMSAuthenticatedDataStreamGenerator;
import org.bouncycastle.cms.OriginatorInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class NewAuthenticatedDataStreamTest
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
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

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

    public NewAuthenticatedDataStreamTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(NewAuthenticatedDataStreamTest.class);
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(NewAuthenticatedDataStreamTest.class));
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

    public void testOriginatorInfo()
        throws Exception
    {
        ASN1ObjectIdentifier macAlg = CMSAlgorithm.DES_EDE3_CBC;
        byte[]          data     = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
        ByteArrayOutputStream               bOut = new ByteArrayOutputStream();

        X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

        adGen.setOriginatorInfo(new OriginatorInfoGenerator(origCert).generate());

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        OutputStream aOut = adGen.open(bOut, new JceCMSMacCalculatorBuilder(macAlg).setProvider(BC).build());

        aOut.write(data);

        aOut.close();

        CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(bOut.toByteArray());

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

    private void tryKeyTrans(ASN1ObjectIdentifier macAlg)
        throws Exception
    {
        byte[]          data     = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
        ByteArrayOutputStream               bOut = new ByteArrayOutputStream();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        
        OutputStream aOut = adGen.open(bOut, new JceCMSMacCalculatorBuilder(macAlg).setProvider(BC).build());

        aOut.write(data);

        aOut.close();

        CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(bOut.toByteArray());

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
        byte[]          data     = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
        ByteArrayOutputStream               bOut = new ByteArrayOutputStream();
        DigestCalculatorProvider            calcProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        OutputStream aOut = adGen.open(bOut, new JceCMSMacCalculatorBuilder(macAlg).setProvider(BC).build(), calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));

        aOut.write(data);

        aOut.close();

        CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(bOut.toByteArray(), calcProvider);

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
}