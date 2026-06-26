package org.bouncycastle.cms.test;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nsri.NSRIObjectIdentifiers;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTagLengthException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

public class AuthEnvelopedDataTest
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

    private static final byte[] Sample1 = Base64.decode(
        "MIAGCyqGSIb3DQEJEAEXoIAwgAIBADGBmzCBmAIBAoABATANBgkqhkiG9w0BAQEF" +
            "AASBgG9yJPC3zFmIbPTtSrrTD+71lluua3F1/V/XzzDOczjdymy4tI4sle5HSxJ" +
            "N8yrw+m2JdWKb4s/u4frvmNqE6fcqfFtLpLEMXJneoEWWXZFKbndoqQNRMgfKGC" +
            "ncpeWhktRcSRtbEEk/H4hWggJGmVClS7f/nmCDjwyANBnI3shYMIAGCSqGSIb3D" +
            "QEHATAfBglghkgBZQMEAQYwEgQQLO0PwnuhYXRk8pLLhgik0aCABBMKvxIkbmBK" +
            "T73Oz4xtf0DNNGmdAAAAAAQMn+tzPcOldJUQWCEnAAAAAAAA");

    private static final byte[] Sample1Key = Base64.decode("MIICdAIBADANBgkqhkiG9w0BAQEFAASCAl4wggJaAgEAAoGBAMtFuFyzl4jgeuPL\n" +
        "uGp8Niqf11QGWVDTpZvE7VabLoPanzuVgjTYC8oJOq4PvVYW5V56KeGzXhsnhsDt\n" +
        "IBaRESTFuXM50uiH4mRPGsqCFJvbmokvxfhb24TPg3gQ5E2SEvmXFN425J/jvcqq\n" +
        "XpX7wQGtr9DWLIXsqPeLKhoy/qdhAgMBAAECf3xBB80spVPEggTXW2aoebwXt1pw\n" +
        "8BqzUnSWqlZaHJGdtgbxL0qNsjECX42Djj+1vzddJud0dRHvu4m8y8zlVl/Ro+fv\n" +
        "xETE9nCKzt1MlaNUG9mywZeWLjyOKZFY5fxc+yzoH+d8fcXTM7SwKG9bl6hisU0j\n" +
        "LWdramL5eV/kILECQQDxD5WuYZY2gF2DhtqAxCaf2MLgDlXzj1PcX3X1nPlrNKy3\n" +
        "G0jyMWofmZFORzUz1G0Dlyfxk3Wlc+1IIWbxH5dNAkEA196fcWJN9ZpavkuLKG3W\n" +
        "5sSWAs05Jdk2FGw/pbycoIaMOtf/3KeWJTSNxK1jKsoTQN3RUF9h2jtFhf+yqOjO\n" +
        "ZQJAGpf7jVdauPyEVIRGCrqZAD1rkkhClzISsFcfrk74/Si8fR7Xd1CYQpAwhZA5\n" +
        "gFRJCoJcd7wq2Gvnm3OD5cn0aQJAP98H8CV1CaltFgcGGqU9Q7SA6j1Mnm1BehN5\n" +
        "VZGUCk8lKLgGZYRUgZemJr5irCN0ROoc55oBOu/0pyw78YxInQJBAKjibmupsLLt\n" +
        "kUQF7vyalONmkebwEDwTHODWOGXC7xmcvXhFAnlpYkv3QCohF53X0RS+VprfojbI\n" +
        "X0T/eAP0zJA=");

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            Security.addProvider(new BouncyCastleProvider());

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

    public AuthEnvelopedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(AuthEnvelopedDataTest.class);
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(AuthEnvelopedDataTest.class));
    }

    public void testKeyTransMinimumTagSize()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");

        // generate AuthEnvelopedData with a 96-bit (12-octet) GCM tag - valid under RFC 5084
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("GCM", BC);
        algParams.init(new AEADParameterSpec(new byte[12], 96));

        OutputEncryptor enc = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM)
            .setProvider(BC).setAlgorithmParameters(algParams).build();

        assertEquals(12, GCMParameters.getInstance(enc.getAlgorithmIdentifier().getParameters()).getIcvLen());

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        byte[] encoded = authGen.generate(new CMSProcessableByteArray(message), (OutputAEADEncryptor)enc).getEncoded();

        // a minimum at or below the actual tag size recovers as normal
        RecipientInformation recipient = (RecipientInformation)new CMSAuthEnvelopedData(encoded)
            .getRecipientInfos().getRecipients().iterator().next();
        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
            .setProvider(BC).setMinimumTagSize(96));
        assertEquals("Hello, world!", Strings.fromByteArray(recData));

        // a minimum above the actual tag size is refused with CMSTagLengthException
        try
        {
            recipient = (RecipientInformation)new CMSAuthEnvelopedData(encoded)
                .getRecipientInfos().getRecipients().iterator().next();
            recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
                .setProvider(BC).setMinimumTagSize(128));

            fail("content recovered under a tag shorter than the configured minimum");
        }
        catch (CMSTagLengthException e)
        {
            // expected
        }

        // a default (128-bit) tag satisfies a 128-bit minimum
        OutputEncryptor fullEnc = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM).setProvider(BC).build();
        CMSAuthEnvelopedDataGenerator fullGen = new CMSAuthEnvelopedDataGenerator();
        fullGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        byte[] fullEncoded = fullGen.generate(new CMSProcessableByteArray(message), (OutputAEADEncryptor)fullEnc).getEncoded();

        recipient = (RecipientInformation)new CMSAuthEnvelopedData(fullEncoded)
            .getRecipientInfos().getRecipients().iterator().next();
        byte[] fullRec = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
            .setProvider(BC).setMinimumTagSize(128));
        assertEquals("Hello, world!", Strings.fromByteArray(fullRec));
    }

    // ARIA-GCM/CCM and SM4-GCM/CCM are full CMS content-encryption algorithms: the encrypt side
    // recognises them as AEAD (authEnvelopedAlgorithms), AlgorithmIdentifierFactory generates the
    // right nonce/RFC 5084 parameters, and the provider ships OID-addressable Cipher/AlgorithmParameters
    // for each. This exercises the whole generate-then-recover chain for every variant.
    public void testAriaSm4AeadRoundTrip()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }

        ASN1ObjectIdentifier[] aeadOids = new ASN1ObjectIdentifier[]{
            NSRIObjectIdentifiers.id_aria128_gcm, NSRIObjectIdentifiers.id_aria256_gcm,
            NSRIObjectIdentifiers.id_aria128_ccm, NSRIObjectIdentifiers.id_aria256_ccm,
            GMObjectIdentifiers.sms4_gcm, GMObjectIdentifiers.sms4_ccm
        };

        byte[] message = Strings.toByteArray("Hello, world!");

        for (int i = 0; i != aeadOids.length; i++)
        {
            ASN1ObjectIdentifier oid = aeadOids[i];

            // exercise both the JCA/JCE and the lightweight content-encryptor builders
            OutputEncryptor jceEnc = new JceCMSContentEncryptorBuilder(oid).setProvider(BC).build();
            OutputEncryptor bcEnc = new BcCMSContentEncryptorBuilder(oid).build();

            assertTrue("Jce not recognised as AEAD: " + oid, jceEnc instanceof OutputAEADEncryptor);
            assertTrue("Bc not recognised as AEAD: " + oid, bcEnc instanceof OutputAEADEncryptor);
            assertEquals(oid, jceEnc.getAlgorithmIdentifier().getAlgorithm());
            assertEquals(oid, bcEnc.getAlgorithmIdentifier().getAlgorithm());

            checkAeadRoundTrip(oid, message, (OutputAEADEncryptor)jceEnc);
            checkAeadRoundTrip(oid, message, (OutputAEADEncryptor)bcEnc);
        }
    }

    private void checkAeadRoundTrip(ASN1ObjectIdentifier oid, byte[] message, OutputAEADEncryptor enc)
        throws Exception
    {
        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), enc);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformation recipient = (RecipientInformation)encAuthData
            .getRecipientInfos().getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
            .setProvider(BC));

        assertTrue("round-trip failed for " + oid, Arrays.areEqual(message, recData));
    }

    public void testSample1()
        throws Exception
    {
        CMSAuthEnvelopedData authEnv = new CMSAuthEnvelopedData(Sample1);

        RecipientInformationStore recipients = authEnv.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(Sample1Key));

        byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

        assertEquals("auth-enveloped data", Strings.fromByteArray(recData));

        assertTrue(Arrays.areEqual(Sample1, authEnv.getEncoded()));
    }

    public void testGCM()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM).setProvider(BC).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_GCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

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

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }

    /*
     * End-to-end check that a malformed RFC 5084 GCMParameters carried in an AuthEnvelopedData is
     * rejected on consumption. The ICV (tag) length is rewritten to 0 octets: RFC 5084 only permits
     * 12..16, and a zero-length tag would make the AEAD integrity check vacuous, so the CMS layer
     * must refuse rather than hand back unauthenticated "plaintext".
     */
    public void testGCMRejectsZeroICVlen()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }

        byte[] message = Strings.toByteArray("Hello, world!");

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)new JceCMSContentEncryptorBuilder(
            NISTObjectIdentifiers.id_aes128_GCM).setProvider(BC).build();

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        // Surgically rebuild the structure with the content-encryption ICV length forced to 0.
        // GCMParameters' own constructor rejects 0, so the malformed parameters are hand-assembled.
        AuthEnvelopedData aed = AuthEnvelopedData.getInstance(authData.toASN1Structure().getContent());
        EncryptedContentInfo eci = aed.getAuthEncryptedContentInfo();
        AlgorithmIdentifier encAlg = eci.getContentEncryptionAlgorithm();

        byte[] nonce = GCMParameters.getInstance(encAlg.getParameters()).getNonce();

        AlgorithmIdentifier tamperedAlg = new AlgorithmIdentifier(encAlg.getAlgorithm(),
            new DERSequence(new DEROctetString(nonce), new ASN1Integer(0)));

        EncryptedContentInfo tamperedEci = new EncryptedContentInfo(
            eci.getContentType(), tamperedAlg, eci.getEncryptedContent());

        AuthEnvelopedData tampered = new AuthEnvelopedData(
            aed.getOriginatorInfo(), aed.getRecipientInfos(), tamperedEci,
            aed.getAuthAttrs(), aed.getMac(), aed.getUnauthAttrs());

        byte[] tamperedEncoding = new ContentInfo(
            CMSObjectIdentifiers.authEnvelopedData, tampered).getEncoded();

        try
        {
            CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(tamperedEncoding);

            RecipientInformation recipient = (RecipientInformation)encAuthData.getRecipientInfos()
                .getRecipients().iterator().next();

            byte[] recovered = recipient.getContent(
                new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            fail("zero-length ICV accepted, recovered " + recovered.length + " bytes");
        }
        catch (IllegalArgumentException e)
        {
            // expected - RFC 5084 ICV length validation rejects 0
        }
        catch (CMSException e)
        {
            // also acceptable - rejection surfaced as a CMS-level failure
        }
    }

    /*
     * Properties.GCM_ALLOW_SHORT_TAGS opts in to the NIST SP 800-38D 32-bit (4 octet) minimum GCM
     * tag, below the RFC 5084 floor of 12 octets. End-to-end: with the property set a 32-bit-tag
     * AuthEnvelopedData encrypts and decrypts; the very same structure is rejected once the property
     * is cleared, confirming the short tag is only honoured behind the explicit opt-in.
     */
    public void testGCMShortTagProperty()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }

        byte[] message = Strings.toByteArray("Hello, world!");
        byte[] shortTagEncoding;

        System.setProperty(Properties.GCM_ALLOW_SHORT_TAGS, "true");
        try
        {
            // a 32-bit (4 octet) GCM tag, supplied through explicit content-encryption parameters
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("GCM", BC);
            algParams.init(new AEADParameterSpec(new byte[12], 32));

            OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM)
                .setProvider(BC).setAlgorithmParameters(algParams).build();

            assertEquals(4, GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()).getIcvLen());

            CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
            authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

            CMSAuthEnvelopedData authData = authGen.generate(
                new CMSProcessableByteArray(message), (OutputAEADEncryptor)candidate);

            shortTagEncoding = authData.getEncoded();

            // round-trips while the property is set
            CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(shortTagEncoding);
            RecipientInformation recipient = (RecipientInformation)encAuthData.getRecipientInfos()
                .getRecipients().iterator().next();

            byte[] recData = recipient.getContent(
                new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            assertEquals("Hello, world!", Strings.fromByteArray(recData));
        }
        finally
        {
            System.clearProperty(Properties.GCM_ALLOW_SHORT_TAGS);
        }

        // the same well-formed short-tag structure is now rejected on consumption
        try
        {
            CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(shortTagEncoding);
            RecipientInformation recipient = (RecipientInformation)encAuthData.getRecipientInfos()
                .getRecipients().iterator().next();

            byte[] recovered = recipient.getContent(
                new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            fail("short GCM tag accepted without property, recovered " + recovered.length + " bytes");
        }
        catch (IllegalArgumentException e)
        {
            // expected - RFC 5084 ICV length validation rejects 4 octets when the opt-in is off
        }
        catch (CMSException e)
        {
            // also acceptable - rejection surfaced as a CMS-level failure
        }
    }

    public void testGCMEncodings()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }

        byte[] message = Strings.toByteArray("Hello, world!");

        // default - outer ContentInfo uses the indefinite-length (BER) method
        byte[] enc = gcmEncode(message, null);

        assertEquals((byte)0x80, enc[1]);
        gcmDecode(enc, message);

        // DL - definite-length throughout, re-encoding as DL is the identity
        enc = gcmEncode(message, ASN1Encoding.DL);

        assertTrue(enc[1] != (byte)0x80);
        assertTrue(Arrays.areEqual(enc, ContentInfo.getInstance(enc).getEncoded(ASN1Encoding.DL)));
        gcmDecode(enc, message);

        // DER - canonical, re-encoding as DER is the identity
        enc = gcmEncode(message, ASN1Encoding.DER);

        assertTrue(Arrays.areEqual(enc, ContentInfo.getInstance(enc).getEncoded(ASN1Encoding.DER)));
        gcmDecode(enc, message);
    }

    private byte[] gcmEncode(byte[] message, String encoding)
        throws Exception
    {
        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        if (encoding != null)
        {
            authGen.setEncoding(encoding);
        }

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message),
            (OutputAEADEncryptor)new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM).setProvider(BC).build());

        return authData.getEncoded();
    }

    private void gcmDecode(byte[] enc, byte[] message)
        throws Exception
    {
        CMSAuthEnvelopedData authData = new CMSAuthEnvelopedData(enc);

        RecipientInformation recipient = (RecipientInformation)authData.getRecipientInfos().getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertTrue(Arrays.areEqual(message, recData));
    }

    public void testChacha20Poly1305()
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

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }

    public void testGCMwithHKDF()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM)
            .setEnableSha256HKdf(true)
            .setProvider(BC).build();

        assertEquals(CMSObjectIdentifiers.id_alg_cek_hkdf_sha256, candidate.getAlgorithmIdentifier().getAlgorithm());

        AlgorithmIdentifier kdfParams = AlgorithmIdentifier.getInstance(candidate.getAlgorithmIdentifier().getParameters());

        assertEquals(NISTObjectIdentifiers.id_aes128_GCM, kdfParams.getAlgorithm());
        assertNotNull(GCMParameters.getInstance(kdfParams.getParameters()));

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

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }

    public void testCCM()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CCM).setProvider(BC).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_CCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

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

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
        assertTrue(java.util.Arrays.equals(authData.getMac(), recipient.getMac()));
        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }

    /*
     * CCM counterpart of testGCMRejectsZeroICVlen: a malformed RFC 5084 CCMParameters carried in an
     * AuthEnvelopedData must be rejected on consumption. The ICV (tag) length is rewritten to 0 octets
     * (RFC 5084 only permits 4,6,8,10,12,14,16); a zero-length tag would make the AEAD integrity check
     * vacuous, so the CMS layer must refuse rather than hand back unauthenticated "plaintext".
     */
    public void testCCMRejectsZeroICVlen()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }

        byte[] message = Strings.toByteArray("Hello, world!");

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)new JceCMSContentEncryptorBuilder(
            NISTObjectIdentifiers.id_aes128_CCM).setProvider(BC).build();

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        // Surgically rebuild the structure with the content-encryption ICV length forced to 0.
        // CCMParameters' own constructor rejects 0, so the malformed parameters are hand-assembled.
        AuthEnvelopedData aed = AuthEnvelopedData.getInstance(authData.toASN1Structure().getContent());
        EncryptedContentInfo eci = aed.getAuthEncryptedContentInfo();
        AlgorithmIdentifier encAlg = eci.getContentEncryptionAlgorithm();

        byte[] nonce = CCMParameters.getInstance(encAlg.getParameters()).getNonce();

        AlgorithmIdentifier tamperedAlg = new AlgorithmIdentifier(encAlg.getAlgorithm(),
            new DERSequence(new DEROctetString(nonce), new ASN1Integer(0)));

        EncryptedContentInfo tamperedEci = new EncryptedContentInfo(
            eci.getContentType(), tamperedAlg, eci.getEncryptedContent());

        AuthEnvelopedData tampered = new AuthEnvelopedData(
            aed.getOriginatorInfo(), aed.getRecipientInfos(), tamperedEci,
            aed.getAuthAttrs(), aed.getMac(), aed.getUnauthAttrs());

        byte[] tamperedEncoding = new ContentInfo(
            CMSObjectIdentifiers.authEnvelopedData, tampered).getEncoded();

        try
        {
            CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(tamperedEncoding);

            RecipientInformation recipient = (RecipientInformation)encAuthData.getRecipientInfos()
                .getRecipients().iterator().next();

            byte[] recovered = recipient.getContent(
                new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

            fail("zero-length ICV accepted, recovered " + recovered.length + " bytes");
        }
        catch (IllegalArgumentException e)
        {
            // expected - RFC 5084 ICV length validation rejects 0
        }
        catch (CMSException e)
        {
            // also acceptable - rejection surfaced as a CMS-level failure
        }
    }

    public void testCCMwithHKDF()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CCM)
                                            .setEnableSha256HKdf(true).setProvider(BC).build();

        assertEquals(CMSObjectIdentifiers.id_alg_cek_hkdf_sha256, candidate.getAlgorithmIdentifier().getAlgorithm());

        AlgorithmIdentifier kdfParams = AlgorithmIdentifier.getInstance(candidate.getAlgorithmIdentifier().getParameters());

        assertEquals(NISTObjectIdentifiers.id_aes128_CCM, kdfParams.getAlgorithm());
        assertNotNull(GCMParameters.getInstance(kdfParams.getParameters()));

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

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
        assertTrue(java.util.Arrays.equals(authData.getMac(), recipient.getMac()));
        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }

    public void testBcCCM()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new BcCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CCM).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_CCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

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

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        if (System.getProperty("java.version").indexOf("1.5.") < 0)
        {
            byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
            assertTrue(java.util.Arrays.equals(authData.getMac(), recipient.getMac()));
            assertEquals("Hello, world!", Strings.fromByteArray(recData));
        }
    }

    public void testBcAttributes()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new BcCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_GCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

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

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));
        
        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        if (System.getProperty("java.version").indexOf("1.5.") < 0)
        {
            byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
                                    
            assertEquals("Hello, world!", Strings.fromByteArray(recData));
        }
    }
}