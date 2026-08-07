package org.bouncycastle.cms.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthenticatedData;
import org.bouncycastle.cms.CMSAuthenticatedDataParser;
import org.bouncycastle.cms.CMSAuthenticatedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.OriginatorInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.MacCalculator;
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
        tryKeyTrans("Eric H. Echidna".getBytes(), CMSAlgorithm.DES_EDE3_CBC);
        // force multiple octet-string
        tryKeyTrans(new byte[2500], CMSAlgorithm.DES_EDE3_CBC);
    }

    public void testKeyTransDESedeWithDigest()
        throws Exception
    {
        tryKeyTransWithDigest("Eric H. Echidna".getBytes(), CMSAlgorithm.DES_EDE3_CBC);
        tryKeyTransWithDigest(new byte[2500], CMSAlgorithm.DES_EDE3_CBC);
    }

    public void testDefiniteLengthNeedsLengthUpFront()
        throws Exception
    {
        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        adGen.setEncoding(ASN1Encoding.DL);

        try
        {
            adGen.open(new ByteArrayOutputStream(), new JceCMSMacCalculatorBuilder(PKCSObjectIdentifiers.id_hmacWithSHA256).setProvider(BC).build());
            fail("definite-length without length not rejected");
        }
        catch (CMSException e)
        {
            assertEquals("definite-length encoding requires the content length up front - use open(out, inputLength, macCalculator)", e.getMessage());
        }
    }

    public void testDefiniteLengthNeedsPredictableMac()
        throws Exception
    {
        // a block-cipher based MAC's output length is a provider default, not
        // spec-fixed - the definite-length path refuses to guess.
        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        adGen.setEncoding(ASN1Encoding.DL);

        try
        {
            adGen.open(new ByteArrayOutputStream(), 5, new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());
            fail("unpredictable MAC length not rejected");
        }
        catch (CMSException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("cannot predict MAC length for "));
        }
    }

    public void testDefiniteLengthEncodings()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        // DL - definite-length throughout, re-encoding as DL is the identity
        byte[] enc = hmacEncode(data, ASN1Encoding.DL, false);

        assertTrue(enc[1] != (byte)0x80);
        assertTrue(Arrays.equals(enc, ContentInfo.getInstance(enc).getEncoded(ASN1Encoding.DL)));
        hmacDecode(enc, data);

        // DER - canonical, re-encoding as DER is the identity
        enc = hmacEncode(data, ASN1Encoding.DER, false);

        assertTrue(Arrays.equals(enc, ContentInfo.getInstance(enc).getEncoded(ASN1Encoding.DER)));
        hmacDecode(enc, data);

        // BER mode ignores the length and produces the indefinite form
        enc = hmacEncode(data, null, false);

        assertEquals((byte)0x80, enc[1]);
        hmacDecode(enc, data);
    }

    public void testDefiniteLengthEncodingsWithDigest()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        // authenticated attributes are sized with a placeholder digest and
        // regenerated with the real one at close time.
        byte[] enc = hmacEncode(data, ASN1Encoding.DL, true);

        assertTrue(enc[1] != (byte)0x80);
        assertTrue(Arrays.equals(enc, ContentInfo.getInstance(enc).getEncoded(ASN1Encoding.DL)));
        hmacDecode(enc, data);

        enc = hmacEncode(data, ASN1Encoding.DER, true);

        assertTrue(Arrays.equals(enc, ContentInfo.getInstance(enc).getEncoded(ASN1Encoding.DER)));
        hmacDecode(enc, data);
    }

    public void testDefiniteLengthUnderrunDetected()
        throws Exception
    {
        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        adGen.setEncoding(ASN1Encoding.DL);

        OutputStream aOut = adGen.open(new ByteArrayOutputStream(), 10,
            new JceCMSMacCalculatorBuilder(PKCSObjectIdentifiers.id_hmacWithSHA256).setProvider(BC).build());

        aOut.write("short".getBytes());

        try
        {
            aOut.close();
            fail("content underrun not detected");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("fewer content octets written"));
        }
    }

    private byte[] hmacEncode(byte[] data, String encoding, boolean withDigest)
        throws Exception
    {
        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
        ByteArrayOutputStream               bOut = new ByteArrayOutputStream();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        if (encoding != null)
        {
            adGen.setEncoding(encoding);
        }

        MacCalculator macCalculator = new JceCMSMacCalculatorBuilder(PKCSObjectIdentifiers.id_hmacWithSHA256).setProvider(BC).build();

        OutputStream aOut;
        if (withDigest)
        {
            DigestCalculatorProvider calcProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

            aOut = adGen.open(bOut, data.length, macCalculator,
                calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));
        }
        else
        {
            aOut = adGen.open(bOut, data.length, macCalculator);
        }

        aOut.write(data);

        aOut.close();

        return bOut.toByteArray();
    }

    private void hmacDecode(byte[] enc, byte[] data)
        throws Exception
    {
        CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(enc,
            new JcaDigestCalculatorProviderBuilder().setProvider(BC).build());

        RecipientInformationStore recipients = ad.getRecipientInfos();

        assertEquals(1, recipients.getRecipients().size());

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertTrue(Arrays.equals(data, recData));
        assertTrue(Arrays.equals(ad.getMac(), recipient.getMac()));
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

    private void tryKeyTrans(byte[] data, ASN1ObjectIdentifier macAlg)
        throws Exception
    {
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

    private void tryKeyTransWithDigest(byte[] data, ASN1ObjectIdentifier macAlg)
        throws Exception
    {
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

    // In digestAlgorithm-absent mode the MAC covers only the content, so authAttrs carried
    // in the message play no part in it - a message with digestAlgorithm absent but authAttrs
    // present would otherwise let getAuthAttrs() return attacker-inserted attributes with no
    // authentication behind them at all, from a message whose (genuinely valid) content MAC
    // makes it look fully verified. The streaming AuthenticatedDataParser has no way to notice
    // this itself (authAttrs comes later in the SEQUENCE than the digestAlgorithm choice that
    // already committed the parser to a secureReadable strategy), so CMSAuthenticatedDataParser
    // must cross-check the two once authAttrs is actually read.
    public void testDigestAbsentAuthAttrsPresentRejected()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        OutputStream aOut = adGen.open(bOut, new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build());
        aOut.write(data);
        aOut.close();

        // A genuine digestAlgorithm-absent message: no digestAlgorithm, no authAttrs, a MAC
        // computed over the content alone.
        ContentInfo original = ContentInfo.getInstance(ASN1Primitive.fromByteArray(bOut.toByteArray()));
        AuthenticatedData authData = AuthenticatedData.getInstance(original.getContent());

        // Forge in an attacker-chosen authAttrs set, leaving digestAlgorithm absent and the
        // (content-only) MAC untouched - the MAC never covered content-type either way.
        ASN1Set forgedAuthAttrs = new DERSet(
            new Attribute(CMSAttributes.contentType, new DERSet(CMSObjectIdentifiers.data)));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(authData.getVersion());
        v.add(authData.getRecipientInfos());
        v.add(authData.getMacAlgorithm());
        v.add(authData.getEncapsulatedContentInfo());
        v.add(new DERTaggedObject(false, 2, forgedAuthAttrs));
        v.add(authData.getMac());

        ContentInfo forged = new ContentInfo(CMSObjectIdentifiers.authenticatedData, new DLSequence(v));

        // The in-memory ASN.1 type rejects the pairing outright.
        try
        {
            AuthenticatedData.getInstance(forged.getContent());
            fail("AuthenticatedData must reject authAttrs without digestAlgorithm");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("digestAlgorithm and authAttrs must be set together", e.getMessage());
        }

        // ... as does the in-memory CMS wrapper over the same bytes, as a CMSException.
        try
        {
            new CMSAuthenticatedData(forged.getEncoded());
            fail("CMSAuthenticatedData must reject authAttrs without digestAlgorithm");
        }
        catch (CMSException e)
        {
            assertEquals("Malformed content.", e.getMessage());
        }

        // The streaming parser cannot see the two fields together at construction time, so it
        // cross-checks when authAttrs is finally read. Follow the path a victim application
        // takes: recover the content through the recipient (the content MAC is genuine and
        // verifies), then read the attributes the message claims are authenticated.
        CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(forged.getEncoded());

        RecipientInformation recipient = (RecipientInformation)ad.getRecipientInfos().getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertTrue(Arrays.equals(data, recData));

        try
        {
            ad.getAuthAttrs();
            fail("forged authAttrs must be rejected when digestAlgorithm is absent");
        }
        catch (IOException e)
        {
            assertEquals("authAttrs presence inconsistent with digestAlgorithm presence", e.getMessage());
        }

        // getMac() reads the attributes on the way past, so the MAC comparison a verifier
        // performs cannot succeed on the forged message either.
        try
        {
            ad.getMac();
            fail("getMac() must not return a MAC for a message with orphan authAttrs");
        }
        catch (IOException e)
        {
            assertEquals("authAttrs presence inconsistent with digestAlgorithm presence", e.getMessage());
        }
    }

    // The mirror of the above: digestAlgorithm present commits the parser to MACing DER(authAttrs),
    // so a message that then omits authAttrs entirely must not be treated as verifiable either.
    public void testDigestPresentAuthAttrsAbsentRejected()
        throws Exception
    {
        byte[] data = "Eric H. Echidna".getBytes();

        CMSAuthenticatedDataStreamGenerator adGen = new CMSAuthenticatedDataStreamGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DigestCalculatorProvider calcProvider = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        OutputStream aOut = adGen.open(bOut, new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build(),
            calcProvider.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));
        aOut.write(data);
        aOut.close();

        ContentInfo original = ContentInfo.getInstance(ASN1Primitive.fromByteArray(bOut.toByteArray()));
        AuthenticatedData authData = AuthenticatedData.getInstance(original.getContent());

        // Strip authAttrs, leave digestAlgorithm in place.
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(authData.getVersion());
        v.add(authData.getRecipientInfos());
        v.add(authData.getMacAlgorithm());
        v.add(new DERTaggedObject(false, 1, authData.getDigestAlgorithm()));
        v.add(authData.getEncapsulatedContentInfo());
        v.add(authData.getMac());

        ContentInfo forged = new ContentInfo(CMSObjectIdentifiers.authenticatedData, new DLSequence(v));

        try
        {
            AuthenticatedData.getInstance(forged.getContent());
            fail("AuthenticatedData must reject digestAlgorithm without authAttrs");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("digestAlgorithm and authAttrs must be set together", e.getMessage());
        }

        CMSAuthenticatedDataParser ad = new CMSAuthenticatedDataParser(forged.getEncoded(), calcProvider);

        RecipientInformation recipient = (RecipientInformation)ad.getRecipientInfos().getRecipients().iterator().next();

        recipient.getContent(new JceKeyTransAuthenticatedRecipient(_reciKP.getPrivate()).setProvider(BC));

        try
        {
            ad.getAuthAttrs();
            fail("missing authAttrs must be rejected when digestAlgorithm is present");
        }
        catch (IOException e)
        {
            assertEquals("authAttrs presence inconsistent with digestAlgorithm presence", e.getMessage());
        }
    }
}