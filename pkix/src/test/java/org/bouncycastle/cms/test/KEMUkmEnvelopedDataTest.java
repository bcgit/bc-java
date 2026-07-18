package org.bouncycastle.cms.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.cms.OtherRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
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
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * Tests for RFC 9629 KEMRecipientInfo user keying material (UKM) on the CMS generate side.
 * The UKM is both carried in the ukm field and folded into the CMSORIforKEMOtherInfo KDF input,
 * so a matching artifact round-trips while a desynchronised ukm field fails the key unwrap.
 */
public class KEMUkmEnvelopedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final byte[] KEY_ID = Hex.decode("0102030405060708090a0b0c0d0e0f1011121314");
    private static final byte[] UKM = Hex.decode("a5a5a5a55a5a5a5a0011223344556677");
    private static final byte[] DATA = "user keying material bound into the KEM KDF".getBytes();

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testUkmRoundTripMLKem()
        throws Exception
    {
        KeyPair kp = generateKeyPair("ML-KEM", MLKEMParameterSpec.ml_kem_768);

        CMSEnvelopedData ed = envelope(kp, CMSAlgorithm.AES256_WRAP, UKM);

        // the ukm field carries exactly the material supplied by the caller
        assertTrue("ukm field mismatch", Arrays.areEqual(UKM, extractKemRecipientInfo(ed).getUkm()));

        assertTrue("plaintext did not round-trip", Arrays.areEqual(DATA, decrypt(ed, kp)));
    }

    public void testUkmRoundTripFrodoKem()
        throws Exception
    {
        KeyPair kp = generateKeyPair("FrodoKEM", FrodoKEMParameterSpec.frodokem976shake);

        CMSEnvelopedData ed = envelope(kp, CMSAlgorithm.AES192_WRAP, UKM);

        assertTrue("ukm field mismatch", Arrays.areEqual(UKM, extractKemRecipientInfo(ed).getUkm()));

        assertTrue("plaintext did not round-trip", Arrays.areEqual(DATA, decrypt(ed, kp)));
    }

    public void testNoUkmOmitsField()
        throws Exception
    {
        KeyPair kp = generateKeyPair("ML-KEM", MLKEMParameterSpec.ml_kem_512);

        // no setUserKeyingMaterial: the ukm field must be absent (backwards-compatible null path)
        CMSEnvelopedData ed = envelope(kp, CMSAlgorithm.AES256_WRAP, null);

        assertNull("ukm field should be absent when none supplied", extractKemRecipientInfo(ed).getUkm());

        assertTrue("plaintext did not round-trip", Arrays.areEqual(DATA, decrypt(ed, kp)));
    }

    public void testTamperedUkmFails()
        throws Exception
    {
        KeyPair kp = generateKeyPair("ML-KEM", MLKEMParameterSpec.ml_kem_768);

        CMSEnvelopedData ed = envelope(kp, CMSAlgorithm.AES256_WRAP, UKM);

        // Rebuild the artifact with the ukm field flipped but everything else (encapsulation, wrapped
        // key, KEK length, KDF, wrap) unchanged. Because the KEK was derived from the original UKM, the
        // unwrapper - which folds the *field* UKM into its KDF input - now derives a different KEK.
        ContentInfo contentInfo = ContentInfo.getInstance(ed.getEncoded());
        EnvelopedData env = EnvelopedData.getInstance(contentInfo.getContent());
        RecipientInfo ri = RecipientInfo.getInstance(env.getRecipientInfos().getObjectAt(0));
        KEMRecipientInfo kem = KEMRecipientInfo.getInstance(
            OtherRecipientInfo.getInstance(ri.getInfo()).getValue());

        byte[] tamperedUkm = Arrays.clone(kem.getUkm());
        tamperedUkm[0] ^= 0xFF;

        KEMRecipientInfo tampered = new KEMRecipientInfo(
            kem.getRecipientIdentifier(), kem.getKem(), kem.getKemct(), kem.getKdf(),
            ASN1Integer.valueOf(32),                    // AES-256 KEK length, unchanged
            new DEROctetString(tamperedUkm), kem.getWrap(), kem.getEncryptedKey());

        EnvelopedData tamperedEnv = new EnvelopedData(env.getOriginatorInfo(),
            new DERSet(new RecipientInfo(new OtherRecipientInfo(CMSObjectIdentifiers.id_ori_kem, tampered))),
            env.getEncryptedContentInfo(), env.getUnprotectedAttrs());

        CMSEnvelopedData tamperedEd = new CMSEnvelopedData(
            new ContentInfo(CMSObjectIdentifiers.envelopedData, tamperedEnv));

        try
        {
            decrypt(tamperedEd, kp);
            fail("decryption should fail when the ukm field is desynchronised from the KDF");
        }
        catch (Exception e)
        {
            // expected: KEK mismatch -> unwrap failure
        }
    }

    private CMSEnvelopedData envelope(KeyPair kp, ASN1ObjectIdentifier wrapAlg, byte[] ukm)
        throws Exception
    {
        JceKEMRecipientInfoGenerator gen = new JceKEMRecipientInfoGenerator(KEY_ID, kp.getPublic(), wrapAlg)
            .setKDF(CMSAlgorithm.SHA256_HKDF);
        if (ukm != null)
        {
            gen.setUserKeyingMaterial(ukm);
        }
        gen.setProvider(BC);

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        edGen.addRecipientInfoGenerator(gen);

        return edGen.generate(
            new CMSProcessableByteArray(DATA),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BC).build());
    }

    private byte[] decrypt(CMSEnvelopedData ed, KeyPair kp)
        throws Exception
    {
        RecipientInformationStore recipients = ed.getRecipientInfos();
        Collection c = recipients.getRecipients();
        assertEquals(1, c.size());

        KEMRecipientInformation recipient = (KEMRecipientInformation)c.iterator().next();

        CMSTypedStream recovered = recipient.getContentStream(
            new JceKEMEnvelopedRecipient(kp.getPrivate()).setProvider(BC));

        return Streams.readAll(recovered.getContentStream());
    }

    private static KEMRecipientInfo extractKemRecipientInfo(CMSEnvelopedData ed)
        throws Exception
    {
        ContentInfo contentInfo = ContentInfo.getInstance(ed.getEncoded());
        EnvelopedData env = EnvelopedData.getInstance(contentInfo.getContent());
        RecipientInfo ri = RecipientInfo.getInstance(env.getRecipientInfos().getObjectAt(0));
        return KEMRecipientInfo.getInstance(OtherRecipientInfo.getInstance(ri.getInfo()).getValue());
    }

    private KeyPair generateKeyPair(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, BC);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(KEMUkmEnvelopedDataTest.class);
    }
}
