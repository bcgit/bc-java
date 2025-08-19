package org.bouncycastle.cms.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedDataParser;
import org.bouncycastle.cms.CMSAuthEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Strings;

public class CMSAuthEnvelopedDataStreamGeneratorTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        CMSAuthEnvelopedDataStreamGeneratorTest test = new CMSAuthEnvelopedDataStreamGeneratorTest();
        test.setUp();
        test.testGCMCCM();
        test.testNoAuthAttributes();
        test.testNoAttributes();

    }

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final int BUFFER_SIZE = 4000;
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

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;

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

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(CMSAuthEnvelopedDataStreamGeneratorTest.class));
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    public void testGCMCCMZeroLength()
        throws Exception
    {
        GCMCCMtest(CMSAlgorithm.AES128_GCM, false, new byte[0]);
        GCMCCMtest(CMSAlgorithm.AES128_GCM, true, new byte[0]);

        GCMCCMtest(CMSAlgorithm.AES128_CCM, false, new byte[0]);
        GCMCCMtest(CMSAlgorithm.AES128_CCM, true, new byte[0]);
    }

    public void testGCMCCM()
        throws Exception
    {
        GCMCCMtest(CMSAlgorithm.AES128_GCM, false);
        GCMCCMtest(CMSAlgorithm.AES192_GCM, false);
        GCMCCMtest(CMSAlgorithm.AES256_GCM, false);
        GCMCCMtest(CMSAlgorithm.AES128_CCM, false);
        GCMCCMtest(CMSAlgorithm.AES192_CCM, false);
        GCMCCMtest(CMSAlgorithm.AES256_CCM, false);

        GCMCCMtest(CMSAlgorithm.AES128_GCM, true);
        GCMCCMtest(CMSAlgorithm.AES192_GCM, true);
        GCMCCMtest(CMSAlgorithm.AES256_GCM, true);
        GCMCCMtest(CMSAlgorithm.AES128_CCM, true);
        GCMCCMtest(CMSAlgorithm.AES192_CCM, true);
        GCMCCMtest(CMSAlgorithm.AES256_CCM, true);
    }

    private void GCMCCMtest(ASN1ObjectIdentifier oid, boolean berEncodeRecipientSet)
        throws Exception
    {
         GCMCCMtest(oid, berEncodeRecipientSet, Strings.toByteArray("Hello, world!"));
    }

    private void GCMCCMtest(ASN1ObjectIdentifier oid, boolean berEncodeRecipientSet, byte[] message)
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }

        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(oid).setProvider(BC).build();

        assertEquals(oid, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        CMSAuthEnvelopedDataStreamGenerator authGen = new CMSAuthEnvelopedDataStreamGenerator();

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));
        authGen.setBEREncodeRecipients(berEncodeRecipientSet);
        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                    new DERSet(new Time(new Date())));
                attrs.put(testAttr.getAttrType(), testAttr);
                return new AttributeTable(attrs);
            }
        });

        authGen.setUnauthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                    new DERSet(new Time(new Date())));
                attrs.put(testAttr.getAttrType(), testAttr);
                return new AttributeTable(attrs);
            }
        });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = authGen.open(bOut, (
            OutputAEADEncryptor)new JceCMSContentEncryptorBuilder(oid).setProvider(BC).build());
        out.write(message);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncryptionAlgOID().getAlgorithm(), oid);
        assertEquals(ep.getEncAlgOID(), oid.getId());
        assertNotNull(ep.getEncAlgParams());

        Collection c = recipients.getRecipients();

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "1.2.840.113549.1.1.1");

            CMSTypedStream recData = recipient.getContentStream(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(message, CMSTestUtil.streamToByteArray(recData.getContentStream())));
            assertTrue(Arrays.equals(ep.getMac(), recipient.getMac()));
            //assertEquals(1, ep.getAuthAttrs().size());
            assertEquals(1, ep.getUnauthAttrs().size());
        }
        ep.close();

        // alternate read approach
        ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        recipients = ep.getRecipientInfos();

        c = recipients.getRecipients();

        it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "1.2.840.113549.1.1.1");

            CMSTypedStream recData = recipient.getContentStream(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            byte[] buf = new byte[message.length];

            InputStream contentStream = recData.getContentStream();

            contentStream.read(buf);
            contentStream.close();
            
            assertEquals(true, Arrays.equals(message, buf));
            assertTrue(Arrays.equals(ep.getMac(), recipient.getMac()));
        }
        ep.close();
    }

    public void testNoAuthAttributes()
        throws Exception
    {
        ASN1ObjectIdentifier oid = CMSAlgorithm.AES128_GCM;
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");

        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(oid).setProvider(BC).build();

        assertEquals(oid, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        CMSAuthEnvelopedDataStreamGenerator authGen = new CMSAuthEnvelopedDataStreamGenerator();

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        authGen.setUnauthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                    new DERSet(new Time(new Date())));
                attrs.put(testAttr.getAttrType(), testAttr);
                return new AttributeTable(attrs);
            }
        });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = authGen.open(bOut, (
            OutputAEADEncryptor)new JceCMSContentEncryptorBuilder(oid).setProvider(BC).build());
        out.write(message);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        //System.err.println(ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(bOut.toByteArray())));
        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncryptionAlgOID().getAlgorithm(), oid);
        assertEquals(ep.getEncAlgOID(), oid.getId());
        assertNotNull(ep.getEncAlgParams());

        Collection c = recipients.getRecipients();

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "1.2.840.113549.1.1.1");

            CMSTypedStream recData = recipient.getContentStream(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(message, CMSTestUtil.streamToByteArray(recData.getContentStream())));
            assertTrue(Arrays.equals(ep.getMac(), recipient.getMac()));
            assertNull(ep.getAuthAttrs());
            assertEquals(1, ep.getUnauthAttrs().size());
        }
        ep.close();
    }

    public void testNoAttributes()
        throws Exception
    {
        ASN1ObjectIdentifier oid = CMSAlgorithm.AES128_GCM;
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");

        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(oid).setProvider(BC).build();

        assertEquals(oid, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        CMSAuthEnvelopedDataStreamGenerator authGen = new CMSAuthEnvelopedDataStreamGenerator();

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = authGen.open(bOut, (
            OutputAEADEncryptor)new JceCMSContentEncryptorBuilder(oid).setProvider(BC).build());
        out.write(message);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        //System.err.println(ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(bOut.toByteArray())));
        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncryptionAlgOID().getAlgorithm(), oid);
        assertEquals(ep.getEncAlgOID(), oid.getId());
        assertNotNull(ep.getEncAlgParams());

        Collection c = recipients.getRecipients();

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "1.2.840.113549.1.1.1");

            CMSTypedStream recData = recipient.getContentStream(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals(true, Arrays.equals(message, CMSTestUtil.streamToByteArray(recData.getContentStream())));
            assertTrue(Arrays.equals(ep.getMac(), recipient.getMac()));
        }
        ep.close();
    }
}
