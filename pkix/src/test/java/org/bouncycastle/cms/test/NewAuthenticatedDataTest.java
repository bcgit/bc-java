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
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.nist.KMACwithSHAKE128_params;
import org.bouncycastle.asn1.nist.KMACwithSHAKE256_params;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSRuntimeException;
import org.bouncycastle.cms.CMSAuthenticatedData;
import org.bouncycastle.cms.CMSAuthenticatedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.DefaultAuthenticatedAttributeTableGenerator;
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
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.jcajce.spec.KMACParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.Properties;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.CMSAuthenticatedDataParser;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Encodable;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Map;
import java.security.SecureRandom;

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

    public void testKeyTransEncodings()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        // default - outer ContentInfo uses the indefinite-length (BER) method
        byte[] enc = authEncode(data, null);

        assertEquals((byte)0x80, enc[1]);
        authDecode(enc, data);

        // DL - definite-length throughout, re-encoding as DL is the identity
        enc = authEncode(data, ASN1Encoding.DL);

        assertTrue(enc[1] != (byte)0x80);
        assertTrue(Arrays.equals(enc, ContentInfo.getInstance(enc).getEncoded(ASN1Encoding.DL)));
        authDecode(enc, data);

        // DER - canonical, re-encoding as DER is the identity
        enc = authEncode(data, ASN1Encoding.DER);

        assertTrue(Arrays.equals(enc, ContentInfo.getInstance(enc).getEncoded(ASN1Encoding.DER)));
        authDecode(enc, data);
    }

    private byte[] authEncode(byte[] data, String encoding)
        throws Exception
    {
        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        if (encoding != null)
        {
            adGen.setEncoding(encoding);
        }

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());

        return ad.getEncoded();
    }

    private void authDecode(byte[] enc, byte[] data)
        throws Exception
    {
        CMSAuthenticatedData ad = new CMSAuthenticatedData(enc);

        RecipientInformation recipient = (RecipientInformation)ad.getRecipientInfos().getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertTrue(Arrays.equals(data, recData));
        assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
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

        DEROctetString zeroIV = new DEROctetString(new byte[8]);
        tryKekAlgorithm(CMSTestUtil.makeDesede192Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"), zeroIV.getEncoded());

        // without authenticated attributes nothing covers a CBC-MAC IV, so a non-zero one is refused
        DEROctetString iv = new DEROctetString(Hex.decode("0001020304050607"));
        try
        {
            tryKekAlgorithm(CMSTestUtil.makeDesede192Key(), new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.6"), iv.getEncoded());
            fail("non-zero CBC-MAC IV accepted without authenticated attributes");
        }
        catch (CMSException e)
        {
            assertEquals(CBC_MAC_IV_REFUSED, e.getMessage());
        }
    }

    private static final String CBC_MAC_IV_REFUSED = "CBC-MAC with a non-zero IV requires authenticated attributes";

    private static final byte[] PAYMENT = Strings.toByteArray("PAY 100 EUR TO ALICE, ACCOUNT 42");

    private static final ASN1ObjectIdentifier[] CBC_MACS = { CMSAlgorithm.DES_EDE3_CBC, CMSAlgorithm.RC2_CBC };

    public void testCBCMacDefaultIVIsZero()
        throws Exception
    {
        SecretKey kek = CMSTestUtil.makeAESKey(128);
        for (int i = 0; i != CBC_MACS.length; i++)
        {
            byte[] enc = generateKek(kek, new JceCMSMacCalculatorBuilder(CBC_MACS[i]).setProvider(BC), false);

            byte[] iv = getCBCMacIV(AuthenticatedData.getInstance(ContentInfo.getInstance(enc).getContent()).getMacAlgorithm());
            assertTrue(org.bouncycastle.util.Arrays.areAllZeroes(iv, 0, iv.length));

            assertTrue(verifyKek(enc, kek, false));
            assertTrue(verifyKek(enc, kek, true));
        }
    }

    /*
     * Without authenticated attributes the MAC input is the content alone (RFC 5652 sec. 9.2). A CBC-MAC
     * starting from the IV in macAlgorithm then verifies a message whose IV and first content block are
     * changed by the same difference, so a non-zero IV is refused.
     */
    public void testCBCMacIVForgeryRejected()
        throws Exception
    {
        SecretKey kek = CMSTestUtil.makeAESKey(128);
        for (int i = 0; i != CBC_MACS.length; i++)
        {
            byte[] enc = generateKek(kek, new JceCMSMacCalculatorBuilder(CBC_MACS[i]).setProvider(BC), false);
            byte[] forged = forgeFirstBlock(enc, Strings.toByteArray("PAY 999 "), false);

            try
            {
                new CMSAuthenticatedData(forged, new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());
                fail("forged CBC-MAC IV accepted");
            }
            catch (CMSException e)
            {
                assertEquals(CBC_MAC_IV_REFUSED, e.getMessage());
            }

            try
            {
                new CMSAuthenticatedDataParser(forged, new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());
                fail("forged CBC-MAC IV accepted by parser");
            }
            catch (CMSException e)
            {
                assertEquals(CBC_MAC_IV_REFUSED, e.getMessage());
            }
        }
    }

    /*
     * Adding a digestAlgorithm, without authenticated attributes, must not take the parser past the IV check.
     */
    public void testCBCMacIVForgeryWithDigestAlgorithmRejected()
        throws Exception
    {
        SecretKey kek = CMSTestUtil.makeAESKey(128);
        byte[] enc = generateKek(kek, new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC), false);
        byte[] forged = forgeFirstBlock(enc, Strings.toByteArray("PAY 999 "), true);

        // the in-memory class refuses the structure itself: digestAlgorithm and authAttrs go together
        try
        {
            new CMSAuthenticatedData(forged, new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());
            fail("forged CBC-MAC IV accepted");
        }
        catch (CMSException e)
        {
            assertEquals("Malformed content.", e.getMessage());
        }

        // the parser refuses it when the message MAC is read first...
        try
        {
            verifyKek(forged, kek, true);
            fail("digestAlgorithm without authenticated attributes accepted by parser");
        }
        catch (IOException e)
        {
            assertEquals("authAttrs presence inconsistent with digestAlgorithm presence", e.getMessage());
        }

        // ...and the recipient MAC refuses it when asked for first
        CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(forged, new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());
        RecipientInformation recipient = (RecipientInformation)ad.getRecipientInfos().getRecipients().iterator().next();
        Streams.drain(recipient.getContentStream(new JceKEKAuthenticatedRecipient(kek).setProvider(BC)).getContentStream());
        try
        {
            recipient.getMac();
            fail("digestAlgorithm without authenticated attributes accepted by recipient");
        }
        catch (CMSRuntimeException e)
        {
            assertEquals("AuthenticatedData has a digestAlgorithm but no authenticated attributes", e.getMessage());
        }
    }

    /*
     * Messages BC wrote before the change carry a random IV: refused by default, readable with the property set.
     */
    public void testCBCMacLegacyIVProperty()
        throws Exception
    {
        SecretKey kek = CMSTestUtil.makeAESKey(128);
        for (int i = 0; i != CBC_MACS.length; i++)
        {
            byte[] enc;
            Properties.setThreadOverride(Properties.CMS_ALLOW_UNAUTHENTICATED_CBC_MAC_IV, true);
            try
            {
                enc = generateKek(kek, new JceCMSMacCalculatorBuilder(CBC_MACS[i]).setProvider(BC)
                    .setAlgorithmParameters(randomIVParameters(CBC_MACS[i])), false);

                assertTrue(verifyKek(enc, kek, false));
                assertTrue(verifyKek(enc, kek, true));
            }
            finally
            {
                Properties.removeThreadOverride(Properties.CMS_ALLOW_UNAUTHENTICATED_CBC_MAC_IV);
            }

            try
            {
                verifyKek(enc, kek, false);
                fail("legacy CBC-MAC IV accepted without the property");
            }
            catch (CMSException e)
            {
                assertEquals(CBC_MAC_IV_REFUSED, e.getMessage());
            }
        }
    }

    /*
     * With authenticated attributes the content is bound through messageDigest, so a non-zero IV is still accepted.
     */
    public void testCBCMacIVWithAuthAttrs()
        throws Exception
    {
        SecretKey kek = CMSTestUtil.makeAESKey(128);
        for (int i = 0; i != CBC_MACS.length; i++)
        {
            byte[] enc = generateKek(kek, new JceCMSMacCalculatorBuilder(CBC_MACS[i]).setProvider(BC)
                .setAlgorithmParameters(randomIVParameters(CBC_MACS[i])), true);

            byte[] iv = getCBCMacIV(AuthenticatedData.getInstance(ContentInfo.getInstance(enc).getContent()).getMacAlgorithm());
            assertFalse(org.bouncycastle.util.Arrays.areAllZeroes(iv, 0, iv.length));

            assertTrue(verifyKek(enc, kek, false));
            assertTrue(verifyKek(enc, kek, true));
        }
    }

    /*
     * RFC 5652 sec. 9.3: with authAttrs the content-type attribute MUST be present and match eContentType.
     */
    public void testContentTypeAttributeChecked()
        throws Exception
    {
        SecretKey kek = CMSTestUtil.makeAESKey(128);
        JceCMSMacCalculatorBuilder hmac = new JceCMSMacCalculatorBuilder(PKCSObjectIdentifiers.id_hmacWithSHA256).setProvider(BC);

        byte[] enc = generateKek(kek, hmac, true);
        assertTrue(verifyKek(enc, kek, false));
        assertTrue(verifyKek(enc, kek, true));

        byte[] relabelled = relabel(enc, PKCSObjectIdentifiers.id_ct_TSTInfo);
        for (int stream = 0; stream != 2; stream++)
        {
            try
            {
                verifyKek(relabelled, kek, stream == 1);
                fail("relabelled eContentType accepted");
            }
            catch (CMSRuntimeException e)
            {
                assertEquals("content-type attribute value does not match eContentType", e.getMessage());
            }
        }

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
        adGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(new byte[]{ 1, 2, 3 }, kek).setProvider(BC));
        adGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
            {
                return new DefaultAuthenticatedAttributeTableGenerator().getAttributes(parameters).remove(CMSAttributes.contentType);
            }
        });
        byte[] noContentType = adGen.generate(new CMSProcessableByteArray(PAYMENT), hmac.build(),
            new JcaDigestCalculatorProviderBuilder().setProvider(BC).build().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))).getEncoded();
        for (int stream = 0; stream != 2; stream++)
        {
            try
            {
                verifyKek(noContentType, kek, stream == 1);
                fail("missing content-type attribute accepted");
            }
            catch (CMSRuntimeException e)
            {
                assertEquals("AuthenticatedData missing or malformed content-type authenticated attribute", e.getMessage());
            }
        }
    }

    private static byte[] generateKek(SecretKey kek, JceCMSMacCalculatorBuilder macBuilder, boolean withAuthAttrs)
        throws Exception
    {
        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
        adGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(new byte[]{ 1, 2, 3 }, kek).setProvider(BC));

        if (withAuthAttrs)
        {
            return adGen.generate(new CMSProcessableByteArray(PAYMENT), macBuilder.build(),
                new JcaDigestCalculatorProviderBuilder().setProvider(BC).build().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))).getEncoded();
        }
        return adGen.generate(new CMSProcessableByteArray(PAYMENT), macBuilder.build()).getEncoded();
    }

    /*
     * Read the content through the KEK recipient and compare the recipient's MAC with the message's, in memory or streaming.
     */
    private static boolean verifyKek(byte[] enc, SecretKey kek, boolean stream)
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        if (stream)
        {
            CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(enc, digProv);
            RecipientInformation recipient = (RecipientInformation)ad.getRecipientInfos().getRecipients().iterator().next();
            CMSTypedStream content = recipient.getContentStream(new JceKEKAuthenticatedRecipient(kek).setProvider(BC));
            Streams.drain(content.getContentStream());
            byte[] mac = ad.getMac();
            return Arrays.equals(mac, recipient.getMac());
        }

        CMSAuthenticatedData ad = new CMSAuthenticatedData(enc, digProv);
        RecipientInformation recipient = (RecipientInformation)ad.getRecipientInfos().getRecipients().iterator().next();
        recipient.getContent(new JceKEKAuthenticatedRecipient(kek).setProvider(BC));
        return Arrays.equals(ad.getMac(), recipient.getMac());
    }

    private static AlgorithmParameters randomIVParameters(ASN1ObjectIdentifier macAlg)
        throws Exception
    {
        byte[] iv = new byte[8];
        new SecureRandom().nextBytes(iv);
        iv[0] |= 0x01;

        AlgorithmParameters params = AlgorithmParameters.getInstance(macAlg.getId(), BC);
        if (CMSAlgorithm.RC2_CBC.equals(macAlg))
        {
            params.init(new RC2ParameterSpec(128, iv));
        }
        else
        {
            params.init(new IvParameterSpec(iv));
        }
        return params;
    }

    private static byte[] getCBCMacIV(AlgorithmIdentifier macAlg)
    {
        if (CMSAlgorithm.RC2_CBC.equals(macAlg.getAlgorithm()))
        {
            return RC2CBCParameter.getInstance(macAlg.getParameters()).getIV();
        }
        return ASN1OctetString.getInstance(macAlg.getParameters()).getOctets();
    }

    /*
     * XOR the same difference into the CBC-MAC IV and the first content block, leaving the mac octets alone;
     * optionally add a digestAlgorithm, without authenticated attributes.
     */
    private static byte[] forgeFirstBlock(byte[] enc, byte[] newFirstBlock, boolean addDigestAlgorithm)
        throws Exception
    {
        AuthenticatedData ad = AuthenticatedData.getInstance(ContentInfo.getInstance(enc).getContent());
        byte[] content = ASN1OctetString.getInstance(ad.getEncapsulatedContentInfo().getContent()).getOctets();

        byte[] delta = new byte[8];
        for (int i = 0; i != 8; i++)
        {
            delta[i] = (byte)(content[i] ^ newFirstBlock[i]);
            content[i] ^= delta[i];
        }

        AlgorithmIdentifier macAlg = ad.getMacAlgorithm();
        byte[] iv = getCBCMacIV(macAlg);
        for (int i = 0; i != 8; i++)
        {
            iv[i] ^= delta[i];
        }

        ASN1Encodable params;
        if (CMSAlgorithm.RC2_CBC.equals(macAlg.getAlgorithm()))
        {
            RC2CBCParameter rc2 = RC2CBCParameter.getInstance(macAlg.getParameters());
            params = rc2.getRC2ParameterVersion() == null ? new RC2CBCParameter(iv) : new RC2CBCParameter(rc2.getRC2ParameterVersion().intValue(), iv);
        }
        else
        {
            params = new DEROctetString(iv);
        }

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(ad.getVersion());
        v.add(ad.getRecipientInfos());
        v.add(new AlgorithmIdentifier(macAlg.getAlgorithm(), params));
        if (addDigestAlgorithm)
        {
            v.add(new DERTaggedObject(false, 1, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)));
        }
        v.add(new ContentInfo(ad.getEncapsulatedContentInfo().getContentType(), new DEROctetString(content)));
        v.add(ad.getMac());

        return new ContentInfo(CMSObjectIdentifiers.authenticatedData, new DERSequence(v)).getEncoded();
    }

    private static byte[] relabel(byte[] enc, ASN1ObjectIdentifier contentType)
        throws Exception
    {
        AuthenticatedData ad = AuthenticatedData.getInstance(ContentInfo.getInstance(enc).getContent());
        AuthenticatedData relabelled = new AuthenticatedData(ad.getOriginatorInfo(), ad.getRecipientInfos(), ad.getMacAlgorithm(),
            ad.getDigestAlgorithm(), new ContentInfo(contentType, ad.getEncapsulatedContentInfo().getContent()),
            ad.getAuthAttrs(), ad.getMac(), ad.getUnauthAttrs());

        return new ContentInfo(CMSObjectIdentifiers.authenticatedData, relabelled).getEncoded();
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

            assertEquals(PKCSObjectIdentifiers.data, recipient.getContentType());
            assertTrue(Arrays.equals(data, recData));
            assertEquals(16, ad.getMac().length);
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
        }
    }

    public void testAES256CCMContentType()
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
            new CMSProcessableByteArray(PKCSObjectIdentifiers.safeContentsBag, data),
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

            JceKeyTransRecipient rec = new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC);
            byte[] recData = recipient.getContent(rec);

            assertEquals(PKCSObjectIdentifiers.safeContentsBag, recipient.getContentType());
            assertEquals(16, ad.getMac().length);
            assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
            assertTrue(Arrays.equals(data, recData));

            assertEquals(PKCSObjectIdentifiers.safeContentsBag, recipient.getContentStream(rec).getContentType());
        }
    }

    public void testKeyTransAES128GMAC()
        throws Exception
    {
        tryKeyTransGMAC(CMSAlgorithm.AES128_GMAC);
    }

    public void testKeyTransAES192GMAC()
        throws Exception
    {
        tryKeyTransGMAC(CMSAlgorithm.AES192_GMAC);
    }

    public void testKeyTransAES256GMAC()
        throws Exception
    {
        tryKeyTransGMAC(CMSAlgorithm.AES256_GMAC);
    }

    private void tryKeyTransGMAC(ASN1ObjectIdentifier macAlg)
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(macAlg).setProvider(BC).build());

        RecipientInformationStore recipients = ad.getRecipientInfos();

        assertEquals(macAlg.getId(), ad.getMacAlgOID());

        // RFC 9044: macAlgorithm carries GMACParameters (nonce + tag length).
        GCMParameters gmacParams = GCMParameters.getInstance(ad.getMacAlgorithm().getParameters());
        assertEquals(12, gmacParams.getNonce().length);
        assertEquals(16, gmacParams.getIcvLen());

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

    public void testKeyTransAES128GMACShortTag()
        throws Exception
    {
        // RFC 9044 permits a tag length of 12 to 16 octets; exercise the shortest.
        byte[] data = "Eric H. Echidna".getBytes();
        ASN1ObjectIdentifier macAlg = CMSAlgorithm.AES128_GMAC;
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("GCM", BC);

        algParams.init(new GCMParameters(Hex.decode("000102030405060708090a0b"), 12).getEncoded());

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(macAlg).setAlgorithmParameters(algParams).setProvider(BC).build());

        assertEquals(macAlg.getId(), ad.getMacAlgOID());

        Collection c = ad.getRecipientInfos().getRecipients();

        assertEquals(1, c.size());

        Iterator it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertTrue(Arrays.equals(data, recData));
            assertEquals(12, ad.getMac().length);
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
            Assert.assertEquals(e.getMessage(), "CMS Algorithm Protection check failed for digestAlgorithm");
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
            Assert.assertEquals(e.getMessage(), "CMS Algorithm Protection check failed for macAlgorithm");
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
            Assert.assertEquals(e.getMessage(), "CMS Algorithm Protection check failed for macAlgorithm");
        }
    }

    public void testSuppliedAlgorithmProtectionReplaced()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        // a stale attribute, as copied from a message that used another MAC
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new Attribute(CMSAttributes.cmsAlgorithmProtect, new DERSet(new CMSAlgorithmProtection(
            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), CMSAlgorithmProtection.MAC,
            new AlgorithmIdentifier(CMSAlgorithm.AES128_CBC)))));

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
        DigestCalculatorProvider calcProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        byte[] kekId = new byte[]{1, 2, 3, 4, 5};
        SecretKey kek = CMSTestUtil.makeDesede192Key();

        adGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));
        adGen.setAuthenticatedAttributeGenerator(new DefaultAuthenticatedAttributeTableGenerator(new AttributeTable(v)));

        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build(),
            calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));

        Attribute attr = ad.getAuthAttrs().get(CMSAttributes.cmsAlgorithmProtect);

        assertEquals(1, attr.getAttrValues().size());
        assertEquals(CMSAlgorithm.DES_EDE3_CBC,
            CMSAlgorithmProtection.getInstance(attr.getAttrValues().getObjectAt(0)).getMacAlgorithm().getAlgorithm());

        // the receiver's RFC 6211 check runs on parsing
        checkData(data, kek, new CMSAuthenticatedData(ad.getEncoded(), calcProvider));
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

    public void testTamperedContentIsRejected()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
        DigestCalculatorProvider calcProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        // generate with authenticated attributes (the messageDigest attribute path)
        CMSAuthenticatedData ad = adGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build(),
            calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));

        // AuthenticatedData authenticates but does not encrypt the content, so the plaintext is
        // present in the encoding. Flip one content byte to simulate an in-transit substitution,
        // leaving authAttrs and the MAC untouched.
        byte[] encoded = ad.getEncoded();
        int idx = indexOf(encoded, data);
        assertTrue("content not located in encoding", idx >= 0);
        encoded[idx] ^= 0x01;

        CMSAuthenticatedData tampered = new CMSAuthenticatedData(encoded, calcProvider);
        RecipientInformation recipient =
            (RecipientInformation)tampered.getRecipientInfos().getRecipients().iterator().next();

        // read the (tampered) content so the content digest is computed
        recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

        try
        {
            recipient.getMac();
            fail("tampered AuthenticatedData content must not yield a valid MAC");
        }
        catch (CMSRuntimeException e)
        {
            // expected: the recovered content digest no longer matches the messageDigest attribute
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.length - needle.length; i++)
        {
            int j = 0;
            while (j < needle.length && haystack[i + j] == needle[j])
            {
                j++;
            }
            if (j == needle.length)
            {
                return i;
            }
        }
        return -1;
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

    public void testKMACwithSHAKE128Default()
        throws Exception
    {
        runKMACwithSHAKERoundTrip(CMSAlgorithm.KMACwithSHAKE128, NISTObjectIdentifiers.id_KmacWithSHAKE128,
            null, 32);
    }

    public void testKMACwithSHAKE256Default()
        throws Exception
    {
        runKMACwithSHAKERoundTrip(CMSAlgorithm.KMACwithSHAKE256, NISTObjectIdentifiers.id_KmacWithSHAKE256,
            null, 64);
    }

    public void testKMACwithSHAKE128CustomParams()
        throws Exception
    {
        // RFC 8702 sec.3.4 - KMACwithSHAKE128-params: non-default output length and customization.
        KMACParameterSpec spec = new KMACParameterSpec(384, "CMSExample".getBytes());
        runKMACwithSHAKERoundTrip(CMSAlgorithm.KMACwithSHAKE128, NISTObjectIdentifiers.id_KmacWithSHAKE128,
            spec, 48);
    }

    public void testKMACwithSHAKE256CustomParams()
        throws Exception
    {
        KMACParameterSpec spec = new KMACParameterSpec(768, "ContextString".getBytes());
        runKMACwithSHAKERoundTrip(CMSAlgorithm.KMACwithSHAKE256, NISTObjectIdentifiers.id_KmacWithSHAKE256,
            spec, 96);
    }

    private void runKMACwithSHAKERoundTrip(ASN1ObjectIdentifier macOid, ASN1ObjectIdentifier expectedOid,
        KMACParameterSpec spec, int expectedMacBytes)
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        SecretKey kek = CMSTestUtil.makeAESKey(128);
        byte[] kekId = new byte[]{1, 2, 3, 4, 5};

        CMSAuthenticatedDataGenerator adGen = new CMSAuthenticatedDataGenerator();
        adGen.addRecipientInfoGenerator(new JceKEKRecipientInfoGenerator(kekId, kek).setProvider(BC));

        JceCMSMacCalculatorBuilder macBuilder = new JceCMSMacCalculatorBuilder(macOid).setProvider(BC);
        if (spec != null)
        {
            AlgorithmParameters algParams = AlgorithmParameters.getInstance(macOid.getId(), BC);
            algParams.init(spec);
            macBuilder.setAlgorithmParameters(algParams);
        }

        CMSAuthenticatedData ad = adGen.generate(new CMSProcessableByteArray(data), macBuilder.build());

        AlgorithmIdentifier macAlgId = ad.getMacAlgorithm();
        assertEquals(expectedOid, macAlgId.getAlgorithm());

        if (spec == null)
        {
            // RFC 8702 sec.3.4: when defaults are in effect, parameters MUST be absent.
            assertNull("default KMACwithSHAKE parameters must be absent", macAlgId.getParameters());
        }
        else
        {
            assertNotNull("custom KMACwithSHAKE parameters must be present", macAlgId.getParameters());
            if (macOid.equals(NISTObjectIdentifiers.id_KmacWithSHAKE128))
            {
                KMACwithSHAKE128_params parsed = KMACwithSHAKE128_params.getInstance(macAlgId.getParameters());
                assertEquals(spec.getMacSizeInBits(), parsed.getOutputLength());
                assertTrue(Arrays.equals(spec.getCustomizationString(), parsed.getCustomizationString()));
            }
            else
            {
                KMACwithSHAKE256_params parsed = KMACwithSHAKE256_params.getInstance(macAlgId.getParameters());
                assertEquals(spec.getMacSizeInBits(), parsed.getOutputLength());
                assertTrue(Arrays.equals(spec.getCustomizationString(), parsed.getCustomizationString()));
            }
        }

        assertEquals("MAC output length mismatch", expectedMacBytes, ad.getMac().length);

        // Re-parse from the encoded form and verify the recipient can pull the content back out.
        CMSAuthenticatedData decoded = new CMSAuthenticatedData(ad.getEncoded());
        RecipientInformationStore recipients = decoded.getRecipientInfos();
        Collection c = recipients.getRecipients();
        assertEquals(1, c.size());

        Iterator it = c.iterator();
        RecipientInformation recipient = (RecipientInformation)it.next();
        byte[] recData = recipient.getContent(new JceKEKAuthenticatedRecipient(kek).setProvider(BC));

        assertTrue(Arrays.equals(data, recData));
        assertTrue(Arrays.equals(decoded.getMac(), recipient.getMac()));
    }
}