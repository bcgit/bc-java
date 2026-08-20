package org.bouncycastle.cms.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Collection;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.cms.OtherRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.KEMRecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * CMS EnvelopedData (RFC 9629 KEMRecipientInfo) round-trip tests for Classic McEliece, using the
 * OIDs and parameter sets standardised in ISO/IEC 18033-2:2006/Amd 2:2026, Clause 13. There is no
 * CMS profile for Classic McEliece as there is for ML-KEM and FrodoKEM, so the key-wrap size here
 * follows the parameter set's security level - AES-Wrap-192 for mceliece460896 (level 3) and
 * AES-Wrap-256 for the 6688128 / 6960119 / 8192128 sets (level 5) - keying the wrap with
 * HKDF-SHA256 in each case.
 * <p>
 * One set of each of the four code sizes is covered, taking in a semi-systematic key generation
 * ("f") variant and both of the ciphertext sizes a size has: the plaintext-confirmation ("pc")
 * sets append a 32 byte confirmation hash, the "f" variants do not change the ciphertext at all.
 */
public class CMCEEnvelopedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final byte[] KEY_ID = Hex.decode("0102030405060708090a0b0c0d0e0f1011121314");

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // mceliece460896 (level 3) -> AES-Wrap-192
    public void testMcEliece460896Aes192Wrap()
        throws Exception
    {
        checkRoundTrip(CMCEParameterSpec.mceliece460896, ISOIECObjectIdentifiers.mceliece460896,
            CMSAlgorithm.AES192_WRAP, 156);
    }

    // mceliece6688128f (level 5, semi-systematic keygen) -> AES-Wrap-256
    public void testMcEliece6688128fAes256Wrap()
        throws Exception
    {
        checkRoundTrip(CMCEParameterSpec.mceliece6688128f, ISOIECObjectIdentifiers.mceliece6688128f,
            CMSAlgorithm.AES256_WRAP, 208);
    }

    // mceliece6960119pc (level 5, plaintext confirmation) -> AES-Wrap-256
    public void testMcEliece6960119pcAes256Wrap()
        throws Exception
    {
        checkRoundTrip(CMCEParameterSpec.mceliece6960119pc, ISOIECObjectIdentifiers.mceliece6960119pc,
            CMSAlgorithm.AES256_WRAP, 226);
    }

    // mceliece8192128pcf (level 5, plaintext confirmation + semi-systematic keygen) -> AES-Wrap-256
    public void testMcEliece8192128pcfAes256Wrap()
        throws Exception
    {
        checkRoundTrip(CMCEParameterSpec.mceliece8192128pcf, ISOIECObjectIdentifiers.mceliece8192128pcf,
            CMSAlgorithm.AES256_WRAP, 240);
    }

    private void checkRoundTrip(CMCEParameterSpec spec, ASN1ObjectIdentifier expectedKemOid,
                               ASN1ObjectIdentifier expectedWrap, int expectedEncapsulationLength)
        throws Exception
    {
        byte[] data = "the quick brown McEliece jumped over the lazy CEK".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", BC);
        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        edGen.addRecipientInfoGenerator(
            new JceKEMRecipientInfoGenerator(KEY_ID, kp.getPublic(), expectedWrap)
                .setKDF(CMSAlgorithm.SHA256_HKDF)
                .setProvider(BC));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BC).build());

        // Inspect the encoded KEMRecipientInfo to prove the KEM / wrap / KDF mapping was applied.
        ContentInfo contentInfo = ContentInfo.getInstance(ed.getEncoded());
        EnvelopedData envelopedData = EnvelopedData.getInstance(contentInfo.getContent());
        RecipientInfo recipientInfo = RecipientInfo.getInstance(envelopedData.getRecipientInfos().getObjectAt(0));
        OtherRecipientInfo otherRecipientInfo = OtherRecipientInfo.getInstance(recipientInfo.getInfo());
        KEMRecipientInfo kemRecipientInfo = KEMRecipientInfo.getInstance(otherRecipientInfo.getValue());

        assertEquals("KEM algorithm", expectedKemOid, kemRecipientInfo.getKem().getAlgorithm());
        assertEquals("key-wrap mapping", expectedWrap, kemRecipientInfo.getWrap().getAlgorithm());
        assertEquals("KDF", PKCSObjectIdentifiers.id_alg_hkdf_with_sha256, kemRecipientInfo.getKdf().getAlgorithm());

        // Round-trip: decapsulate with the private key and confirm the plaintext is recovered.
        RecipientInformationStore recipients = ed.getRecipientInfos();
        Collection c = recipients.getRecipients();
        assertEquals(1, c.size());

        KEMRecipientInformation recipient = (KEMRecipientInformation)c.iterator().next();

        assertEquals(expectedKemOid.getId(), recipient.getKeyEncryptionAlgOID());
        assertEquals(PKCSObjectIdentifiers.id_alg_hkdf_with_sha256, recipient.getKdfAlgorithm().getAlgorithm());
        assertEquals("encapsulation length", expectedEncapsulationLength, recipient.getEncapsulation().length);

        CMSTypedStream recovered = recipient.getContentStream(
            new JceKEMEnvelopedRecipient(kp.getPrivate()).setProvider(BC));

        assertTrue("plaintext did not round-trip",
            Arrays.areEqual(data, Streams.readAll(recovered.getContentStream())));
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(CMCEEnvelopedDataTest.class);
    }
}
