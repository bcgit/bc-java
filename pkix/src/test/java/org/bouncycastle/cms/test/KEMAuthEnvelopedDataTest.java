package org.bouncycastle.cms.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
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
