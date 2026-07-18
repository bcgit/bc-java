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
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * CMS EnvelopedData (RFC 9629 KEMRecipientInfo) round-trip tests for FrodoKEM, exercising the
 * key-wrap size mapping from draft-chen-lamps-cms-frodokem: the 976 parameter sets pair with
 * AES-Wrap-192 and the 1344 parameter sets with AES-Wrap-256, in both cases keyed via HKDF-SHA256.
 */
public class FrodoKEMEnvelopedDataTest
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

    // FrodoKEM-976 (level 3) -> AES-Wrap-192
    public void testFrodoKem976Aes192Wrap()
        throws Exception
    {
        checkRoundTrip(FrodoKEMParameterSpec.frodokem976shake, ISOIECObjectIdentifiers.frodokem976_shake,
            CMSAlgorithm.AES192_WRAP);
    }

    // FrodoKEM-1344 (level 5) -> AES-Wrap-256
    public void testFrodoKem1344Aes256Wrap()
        throws Exception
    {
        checkRoundTrip(FrodoKEMParameterSpec.frodokem1344shake, ISOIECObjectIdentifiers.frodokem1344_shake,
            CMSAlgorithm.AES256_WRAP);
    }

    private void checkRoundTrip(FrodoKEMParameterSpec spec, ASN1ObjectIdentifier expectedKemOid,
                               ASN1ObjectIdentifier expectedWrap)
        throws Exception
    {
        byte[] data = "the quick brown FrodoKEM jumped over the lazy CEK".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", BC);
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

        CMSTypedStream recovered = recipient.getContentStream(
            new JceKEMEnvelopedRecipient(kp.getPrivate()).setProvider(BC));

        assertTrue("plaintext did not round-trip",
            Arrays.areEqual(data, Streams.readAll(recovered.getContentStream())));
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(FrodoKEMEnvelopedDataTest.class);
    }
}
