package org.bouncycastle.cms.test;

import java.io.BufferedOutputStream;
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

import javax.crypto.SecretKey;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedDataParser;
import org.bouncycastle.cms.CMSAuthEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSAuthenticatedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.OriginatorInfoGenerator;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipientInformation;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class NewAuthEnvelopedDataStreamTest
    extends TestCase
{

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

    public NewAuthEnvelopedDataStreamTest()
    {
    }

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

    public void setUp()
        throws Exception
    {
        init();
    }

    private void verifyData(
        ByteArrayOutputStream encodedStream,
        String expectedOid,
        byte[] expectedData)
        throws Exception
    {
        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(encodedStream.toByteArray());
        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncAlgOID(), expectedOid);

        Collection c = recipients.getRecipients();

        for (Object o : c)
        {
            RecipientInformation recipient = (RecipientInformation)o;

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            CMSTypedStream recData = recipient.getContentStream(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(expectedData, CMSTestUtil.streamToByteArray(recData.getContentStream())));
        }
    }

    public void testUnprotectedAttributes()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();

        attrs.put(PKCSObjectIdentifiers.id_aa_contentHint, new Attribute(PKCSObjectIdentifiers.id_aa_contentHint, new DERSet(new DERUTF8String("Hint"))));
        attrs.put(PKCSObjectIdentifiers.id_aa_receiptRequest, new Attribute(PKCSObjectIdentifiers.id_aa_receiptRequest, new DERSet(new DERUTF8String("Request"))));

        AttributeTable attrTable = new AttributeTable(attrs);

        edGen.setUnprotectedAttributeGenerator(new SimpleAttributeTableGenerator(attrTable));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = edGen.open(
            bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM).setProvider(BC).build());

        out.write(data);

        out.close();

        CMSEnvelopedDataParser ed = new CMSEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ed.getRecipientInfos();

        Collection<RecipientInformation> c = recipients.getRecipients();

        assertEquals(1, c.size());

        for (RecipientInformation recipient : c)
        {
            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
        }

        attrTable = ed.getUnprotectedAttributes();

        assertEquals(attrs.size(), 2);

        assertEquals(new DERUTF8String("Hint"), attrTable.get(PKCSObjectIdentifiers.id_aa_contentHint).getAttrValues().getObjectAt(0));
        assertEquals(new DERUTF8String("Request"), attrTable.get(PKCSObjectIdentifiers.id_aa_receiptRequest).getAttrValues().getObjectAt(0));
    }

    public void testKeyTransAES128GCM()
        throws Exception
    {
        byte[] data = new byte[2000];

        for (int i = 0; i != 2000; i++)
        {
            data[i] = (byte)(i & 0xff);
        }

        //
        // unbuffered
        //
        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());

        for (int i = 0; i != 2000; i++)
        {
            out.write(data[i]);
        }

        out.close();

        verifyData(bOut, CMSAlgorithm.AES128_GCM.getId(), data);

        int unbufferedLength = bOut.toByteArray().length;

        //
        // Using buffered output - should be == to unbuffered
        //
        edGen = new CMSAuthEnvelopedDataStreamGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        bOut = new ByteArrayOutputStream();

        out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());

        BufferedOutputStream bfOut = new BufferedOutputStream(out, 300);

        for (int i = 0; i != 2000; i++)
        {
            bfOut.write(data[i]);
        }

        bfOut.close();

        verifyData(bOut, CMSAlgorithm.AES128_GCM.getId(), data);

        assertEquals(bOut.toByteArray().length, unbufferedLength);
    }

    public void testKeyTransAES128Der()
        throws Exception
    {
        byte[] data = new byte[2000];

        for (int i = 0; i != 2000; i++)
        {
            data[i] = (byte)(i & 0xff);
        }

        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());

        for (int i = 0; i != 2000; i++)
        {
            out.write(data[i]);
        }

        out.close();

        // convert to DER
        ASN1InputStream aIn = new ASN1InputStream(bOut.toByteArray());

        bOut.reset();

        aIn.readObject().encodeTo(bOut, ASN1Encoding.DER);

        verifyData(bOut, CMSAlgorithm.AES128_GCM.getId(), data);
    }

    public void testKeyTransAES128Throughput()
        throws Exception
    {
        byte[] data = new byte[40001];

        for (int i = 0; i != data.length; i++)
        {
            data[i] = (byte)(i & 0xff);
        }

        //
        // buffered
        //
        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        edGen.setBufferSize(BUFFER_SIZE);

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());

        for (int i = 0; i != data.length; i++)
        {
            out.write(data[i]);
        }

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());
        RecipientInformationStore recipients = ep.getRecipientInfos();
        Collection<RecipientInformation> c = recipients.getRecipients();
        Iterator<RecipientInformation> it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            CMSTypedStream recData = recipient.getContentStream(
                new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            InputStream dataStream = recData.getContentStream();
            ByteArrayOutputStream dataOut = new ByteArrayOutputStream();
            int len;
            byte[] buf = new byte[BUFFER_SIZE];
            int count = 0;

            while (count != 10 && (len = dataStream.read(buf)) > 0)
            {
                assertEquals(buf.length, len);

                dataOut.write(buf);
                count++;
            }

            len = dataStream.read(buf);
            dataOut.write(buf, 0, len);

            assertEquals(true, Arrays.equals(data, dataOut.toByteArray()));
        }
        else
        {
            fail("recipient not found.");
        }
    }

    public void testKeyTransAES128AndOriginatorInfo()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        X509CertificateHolder origCert = new X509CertificateHolder(_origCert.getEncoded());

        edGen.setOriginatorInfo(new OriginatorInfoGenerator(origCert).generate());

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());

        out.write(data);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        assertTrue(ep.getOriginatorInfo().getCertificates().getMatches(null).contains(origCert));

        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncAlgOID(), CMSAlgorithm.AES128_GCM.getId());

        Collection<RecipientInformation> c = recipients.getRecipients();

        for (RecipientInformation recipient : c)
        {
            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            CMSTypedStream recData = recipient.getContentStream(
                new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
        }

        ep.close();
    }

    public void testKeyTransAES128()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();

        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());

        out.write(data);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncAlgOID(), CMSAlgorithm.AES128_GCM.getId());

        Collection<RecipientInformation> c = recipients.getRecipients();

        for (RecipientInformation recipient : c)
        {
            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());

            CMSTypedStream recData = recipient.getContentStream(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
        }

        ep.close();
    }

    public void testAESKEK()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();
        SecretKey kek = CMSTestUtil.makeAES192Key();

        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

        edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());

        out.write(data);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncAlgOID(), CMSAlgorithm.AES128_GCM.getId());

        Collection<RecipientInformation> c = recipients.getRecipients();

        for (RecipientInformation recipient : c)
        {
            CMSTypedStream recData = recipient.getContentStream(new JceKEKAuthEnvelopedRecipient(kek).setProvider(BC));

            assertTrue(Arrays.equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
        }

        ep.close();
    }

    public void testChaCha20Poly1305KEK()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();
        SecretKey kek = CMSTestUtil.makeAES192Key();

        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

        edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.ChaCha20Poly1305);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());

        out.write(data);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncAlgOID(), CMSAlgorithm.ChaCha20Poly1305.getId());

        Collection<RecipientInformation> c = recipients.getRecipients();

        for (RecipientInformation recipient : c)
        {
            CMSTypedStream recData = recipient.getContentStream(new JceKEKAuthEnvelopedRecipient(kek).setProvider(BC));

            assertTrue(Arrays.equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));
        }

        ep.close();
    }

    public void testTwoAESKEK()
        throws Exception
    {
        byte[] data = "WallaWallaWashington".getBytes();
        SecretKey kek1 = CMSTestUtil.makeAES192Key();
        SecretKey kek2 = CMSTestUtil.makeAES192Key();

        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        byte[] kekId1 = new byte[]{1, 2, 3, 4, 5};
        byte[] kekId2 = new byte[]{5, 4, 3, 2, 1};

        edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId1, kek1).setProvider(BC));
        edGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId2, kek2).setProvider(BC));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES192_GCM);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());
        out.write(data);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncAlgOID(), CMSAlgorithm.AES192_GCM.getId());

        RecipientId recSel = new KEKRecipientId(kekId2);

        RecipientInformation recipient = recipients.get(recSel);

        CMSTypedStream recData = recipient.getContentStream(new JceKEKAuthEnvelopedRecipient(kek2).setProvider(BC));

        assertTrue(Arrays.equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));

        ep.close();
    }

    public void testECKeyAgree()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        JceKeyAgreeRecipientInfoGenerator recipientGenerator = new JceKeyAgreeRecipientInfoGenerator(
            CMSAlgorithm.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(),
            CMSAlgorithm.AES128_WRAP).setProvider(BC);

        recipientGenerator.addRecipient(_reciEcCert);

        edGen.addRecipientInfoGenerator(recipientGenerator);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_GCM);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());
        out.write(data);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncAlgOID(), CMSAlgorithm.AES128_GCM.getId());

        RecipientId recSel = new JceKeyAgreeRecipientId(_reciEcCert);

        RecipientInformation recipient = recipients.get(recSel);

        CMSTypedStream recData = recipient.getContentStream(
            new JceKeyAgreeAuthEnvelopedRecipient(_reciEcKP.getPrivate()).setProvider(BC));

        assertEquals(true, Arrays.equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));

        ep.close();
    }

    public void testECKeyAgreeChacha20Poly1305()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSAuthEnvelopedDataStreamGenerator edGen = new CMSAuthEnvelopedDataStreamGenerator();

        JceKeyAgreeRecipientInfoGenerator recipientGenerator = new JceKeyAgreeRecipientInfoGenerator(
            CMSAlgorithm.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(),
            CMSAlgorithm.AES128_WRAP).setProvider(BC);

        recipientGenerator.addRecipient(_reciEcCert);

        edGen.addRecipientInfoGenerator(recipientGenerator);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.ChaCha20Poly1305);
        OutputStream out = edGen.open(bOut, (OutputAEADEncryptor)encryptorBuilder.setProvider(BC).build());
        out.write(data);

        out.close();

        CMSAuthEnvelopedDataParser ep = new CMSAuthEnvelopedDataParser(bOut.toByteArray());

        RecipientInformationStore recipients = ep.getRecipientInfos();

        assertEquals(ep.getEncAlgOID(), CMSAlgorithm.ChaCha20Poly1305.getId());

        RecipientId recSel = new JceKeyAgreeRecipientId(_reciEcCert);

        RecipientInformation recipient = recipients.get(recSel);

        CMSTypedStream recData = recipient.getContentStream(
            new JceKeyAgreeAuthEnvelopedRecipient(_reciEcKP.getPrivate()).setProvider(BC));

        assertEquals(true, Arrays.equals(data, CMSTestUtil.streamToByteArray(recData.getContentStream())));

        ep.close();
    }

    public void testPasswordChaCha20Poly1305()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(CMSAlgorithm.ChaCha20Poly1305).setProvider(BC).build();

        assertEquals(CMSAlgorithm.ChaCha20Poly1305, candidate.getAlgorithmIdentifier().getAlgorithm());
        //assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

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

        authGen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(new ASN1ObjectIdentifier(CMSAuthenticatedDataGenerator.AES256_CBC),
            "password".toCharArray()).setProvider(BC).setSaltAndIterationCount(new byte[20], 5));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();

        if (it.hasNext())
        {
            PasswordRecipientInformation recipient = (PasswordRecipientInformation)it.next();

            PasswordRecipient pbeRep = new JcePasswordAuthEnvelopedRecipient("password".toCharArray()).setProvider(BC);

            byte[] recData = recipient.getContent(pbeRep);

            assertTrue(Arrays.equals(message, recData));
            assertTrue(Arrays.equals(authData.getMac(), recipient.getMac()));
        }
        else
        {
            fail("no recipient found");
        }
    }

    public static Test suite()
        throws Exception
    {
        return new CMSTestSetup(new TestSuite(NewAuthEnvelopedDataStreamTest.class));
    }

//    public static void main(String[] args)
//        throws Exception
//    {
//        NewAuthEnvelopedDataStreamTest test = new NewAuthEnvelopedDataStreamTest();
//        test.setUp();
//        test.testPasswordChaCha20Poly1305();
//        test.testECKeyAgreeChacha20Poly1305();
//        test.testChaCha20Poly1305KEK();
//        System.out.println("OK");
//    }
}
