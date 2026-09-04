package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.OtherRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * CMS AuthEnvelopedData (RFC 9629 KEMRecipientInfo, AES-256-GCM) round-trip tests exercising
 * JceKEMAuthEnvelopedRecipient across ML-KEM, FrodoKEM and Composite ML-KEM recipients.
 */
public class KEMAuthEnvelopedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final byte[] KEY_ID = Hex.decode("0102030405060708090a0b0c0d0e0f1011121314");
    private static final byte[] DATA = "AEAD-protected content for a KEM recipient".getBytes();

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testMLKemAuthEnveloped()
        throws Exception
    {
        checkRoundTrip(generate("ML-KEM", MLKEMParameterSpec.ml_kem_768));
    }

    public void testFrodoKemAuthEnveloped()
        throws Exception
    {
        checkRoundTrip(generate("FrodoKEM", FrodoKEMParameterSpec.frodokem976shake));
    }

    public void testCompositeKemAuthEnveloped()
        throws Exception
    {
        checkRoundTrip(KeyPairGenerator.getInstance("MLKEM768-ECDH-P256-SHA3-256", BC).generateKeyPair());
    }

    private void checkRoundTrip(KeyPair kp)
        throws Exception
    {
        OutputAEADEncryptor encryptor = (OutputAEADEncryptor)
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM).setProvider(BC).build();

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(
            new JceKEMRecipientInfoGenerator(KEY_ID, kp.getPublic(), CMSAlgorithm.AES256_WRAP)
                .setKDF(CMSAlgorithm.SHA256_HKDF)
                .setProvider(BC));

        byte[] encoded = authGen.generate(new CMSProcessableByteArray(DATA), encryptor).getEncoded();

        RecipientInformation recipient = (RecipientInformation)new CMSAuthEnvelopedData(encoded)
            .getRecipientInfos().getRecipients().iterator().next();

        byte[] recovered = recipient.getContent(
            new JceKEMAuthEnvelopedRecipient(kp.getPrivate()).setProvider(BC));

        assertTrue("plaintext did not round-trip", Arrays.areEqual(DATA, recovered));
    }

    /**
     * A KEMRecipientInfo whose kekLength is too large for an int, and one whose sequence size
     * disagrees with the presence of the optional [0] ukm, are both rejected while the message
     * is being parsed - before any recipient is selected. CMSAuthEnvelopedData and
     * CMSAuthEnvelopedDataParser are declared to throw CMSException, so that is what the caller
     * has to see; the AuthEnveloped pair shares its recipient decoding with EnvelopedData.
     */
    public void testMalformedKemRecipientInfo()
        throws Exception
    {
        KeyPair kp = generate("ML-KEM", MLKEMParameterSpec.ml_kem_768);
        byte[] authEnveloped = generateAuthEnveloped(kp);

        // the message as generated parses through both entry points.
        assertEquals(1, new CMSAuthEnvelopedData(authEnveloped).getRecipientInfos().size());
        assertEquals(1, new CMSAuthEnvelopedDataParser(
            new ByteArrayInputStream(authEnveloped)).getRecipientInfos().size());

        ASN1Encodable[] elements = kemRecipientInfoElements(authEnveloped);

        // RFC 9629: kekLength INTEGER (1..65535), here beyond the range of an int.
        ASN1Encodable[] oversized = new ASN1Encodable[elements.length];

        System.arraycopy(elements, 0, oversized, 0, elements.length);
        oversized[5] = new ASN1Integer(BigInteger.ONE.shiftLeft(40));

        checkMalformed(rebuildWithKemRecipientInfo(authEnveloped, toVector(oversized, oversized.length)));

        // eight elements, but element 6 is a [0] ukm: encryptedKey is off the end of the sequence.
        ASN1EncodableVector shortWithUkm = toVector(elements, 6);

        shortWithUkm.add(new DERTaggedObject(true, 0, new DEROctetString(new byte[]{9, 9})));
        shortWithUkm.add(elements[6]);

        checkMalformed(rebuildWithKemRecipientInfo(authEnveloped, shortWithUkm));

        // nine elements with no [0] ukm: a trailing element that was previously ignored.
        ASN1EncodableVector longWithoutUkm = toVector(elements, elements.length);

        longWithoutUkm.add(new DEROctetString(new byte[]{7, 7}));

        checkMalformed(rebuildWithKemRecipientInfo(authEnveloped, longWithoutUkm));
    }

    private static void checkMalformed(byte[] authEnveloped)
        throws Exception
    {
        try
        {
            new CMSAuthEnvelopedData(authEnveloped);

            fail("no exception");
        }
        catch (CMSException e)
        {
            assertEquals("Malformed content.", e.getMessage());
        }

        try
        {
            new CMSAuthEnvelopedDataParser(new ByteArrayInputStream(authEnveloped));

            fail("no exception");
        }
        catch (CMSException e)
        {
            assertEquals("Malformed content.", e.getMessage());
        }
    }

    private static byte[] generateAuthEnveloped(KeyPair kp)
        throws Exception
    {
        OutputAEADEncryptor encryptor = (OutputAEADEncryptor)
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM).setProvider(BC).build();

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(
            new JceKEMRecipientInfoGenerator(KEY_ID, kp.getPublic(), CMSAlgorithm.AES256_WRAP)
                .setKDF(CMSAlgorithm.SHA256_HKDF)
                .setProvider(BC));

        return authGen.generate(new CMSProcessableByteArray(DATA), encryptor).getEncoded();
    }

    /**
     * The elements of the message's KEMRecipientInfo, so individual fields can be rewritten:
     * [0] version, [1] rid, [2] kem, [3] kemct, [4] kdf, [5] kekLength, [6] wrap, [7] encryptedKey.
     */
    private static ASN1Encodable[] kemRecipientInfoElements(byte[] authEnveloped)
    {
        AuthEnvelopedData authEnvData = AuthEnvelopedData.getInstance(
            ContentInfo.getInstance(authEnveloped).getContent());
        RecipientInfo ri = RecipientInfo.getInstance(authEnvData.getRecipientInfos().getObjectAt(0));
        ASN1Sequence kemInfo = ASN1Sequence.getInstance(OtherRecipientInfo.getInstance(ri.getInfo()).getValue());

        ASN1Encodable[] elements = new ASN1Encodable[kemInfo.size()];

        for (int i = 0; i != elements.length; i++)
        {
            elements[i] = kemInfo.getObjectAt(i);
        }

        return elements;
    }

    private static byte[] rebuildWithKemRecipientInfo(byte[] authEnveloped, ASN1EncodableVector elements)
        throws Exception
    {
        AuthEnvelopedData authEnvData = AuthEnvelopedData.getInstance(
            ContentInfo.getInstance(authEnveloped).getContent());
        RecipientInfo ri = new RecipientInfo(
            new OtherRecipientInfo(CMSObjectIdentifiers.id_ori_kem, new DERSequence(elements)));

        return new ContentInfo(CMSObjectIdentifiers.authEnvelopedData,
            new AuthEnvelopedData(authEnvData.getOriginatorInfo(), new DERSet(ri),
                authEnvData.getAuthEncryptedContentInfo(), authEnvData.getAuthAttrs(),
                authEnvData.getMac(), authEnvData.getUnauthAttrs())).getEncoded();
    }

    private static ASN1EncodableVector toVector(ASN1Encodable[] elements, int count)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != count; i++)
        {
            v.add(elements[i]);
        }

        return v;
    }

    private KeyPair generate(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, BC);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(KEMAuthEnvelopedDataTest.class);
    }
}
