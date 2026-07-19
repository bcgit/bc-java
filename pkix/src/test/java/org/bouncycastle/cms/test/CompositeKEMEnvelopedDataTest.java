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
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * CMS EnvelopedData (RFC 9629 KEMRecipientInfo) round-trip tests for the twelve Composite ML-KEM
 * parameter sets (draft-ietf-lamps-pq-composite-kem), each enveloped with AES-256-wrap + HKDF-SHA256.
 */
public class CompositeKEMEnvelopedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final byte[] KEY_ID = Hex.decode("0102030405060708090a0b0c0d0e0f1011121314");
    private static final byte[] DATA = "the composite ML-KEM cat sat on the CMS mat".getBytes();

    private static final String[] NAMES = {
        "MLKEM768-RSA2048-SHA3-256", "MLKEM768-RSA3072-SHA3-256", "MLKEM768-RSA4096-SHA3-256",
        "MLKEM768-X25519-SHA3-256", "MLKEM768-ECDH-P256-SHA3-256", "MLKEM768-ECDH-P384-SHA3-256",
        "MLKEM768-ECDH-BP256-SHA3-256", "MLKEM1024-RSA3072-SHA3-256", "MLKEM1024-ECDH-P384-SHA3-256",
        "MLKEM1024-ECDH-BP384-SHA3-256", "MLKEM1024-X448-SHA3-256", "MLKEM1024-ECDH-P521-SHA3-256"
    };

    private static final ASN1ObjectIdentifier[] OIDS = {
        IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256, IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256,
        IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256, IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256,
        IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256, IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256,
        IANAObjectIdentifiers.id_MLKEM768_ECDH_BP256_SHA3_256, IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256,
        IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256, IANAObjectIdentifiers.id_MLKEM1024_ECDH_BP384_SHA3_256,
        IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256, IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256
    };

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testCompositeKemEnveloped()
        throws Exception
    {
        for (int i = 0; i != NAMES.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(NAMES[i], BC).generateKeyPair();

            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            edGen.addRecipientInfoGenerator(
                new JceKEMRecipientInfoGenerator(KEY_ID, kp.getPublic(), CMSAlgorithm.AES256_WRAP)
                    .setKDF(CMSAlgorithm.SHA256_HKDF)
                    .setProvider(BC));

            CMSEnvelopedData ed = edGen.generate(
                new CMSProcessableByteArray(DATA),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BC).build());

            // the KEMRecipientInfo carries the composite OID and the KDF we set
            ContentInfo contentInfo = ContentInfo.getInstance(ed.getEncoded());
            EnvelopedData env = EnvelopedData.getInstance(contentInfo.getContent());
            RecipientInfo ri = RecipientInfo.getInstance(env.getRecipientInfos().getObjectAt(0));
            KEMRecipientInfo kem = KEMRecipientInfo.getInstance(
                OtherRecipientInfo.getInstance(ri.getInfo()).getValue());

            assertEquals(NAMES[i] + ": KEM OID", OIDS[i], kem.getKem().getAlgorithm());
            assertEquals(NAMES[i] + ": KDF", PKCSObjectIdentifiers.id_alg_hkdf_with_sha256, kem.getKdf().getAlgorithm());
            assertEquals(NAMES[i] + ": wrap", CMSAlgorithm.AES256_WRAP, kem.getWrap().getAlgorithm());

            RecipientInformationStore recipients = ed.getRecipientInfos();
            Collection c = recipients.getRecipients();
            assertEquals(1, c.size());

            KEMRecipientInformation recipient = (KEMRecipientInformation)c.iterator().next();
            assertEquals(NAMES[i], OIDS[i].getId(), recipient.getKeyEncryptionAlgOID());

            CMSTypedStream recovered = recipient.getContentStream(
                new JceKEMEnvelopedRecipient(kp.getPrivate()).setProvider(BC));

            assertTrue(NAMES[i] + ": plaintext did not round-trip",
                Arrays.areEqual(DATA, Streams.readAll(recovered.getContentStream())));
        }
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(CompositeKEMEnvelopedDataTest.class);
    }
}
