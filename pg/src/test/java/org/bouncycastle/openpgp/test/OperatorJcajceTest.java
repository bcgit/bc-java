package org.bouncycastle.openpgp.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.test.SimpleTest;

public class OperatorJcajceTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OperatorJcajceTest());
    }

    @Override
    public String getName()
    {
        return "OperatorJcajceTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testJcePBESecretKeyEncryptorBuilder();
        testJcaPGPContentVerifierBuilderProvider();
        testJcaPGPDigestCalculatorProviderBuilder();
        testJcePGPDataEncryptorBuilder();
        testJcaKeyFingerprintCalculator();
    }

    public void testJcaKeyFingerprintCalculator()
        throws Exception
    {
        final JcaKeyFingerprintCalculator calculator = new JcaKeyFingerprintCalculator().setProvider(new BouncyCastlePQCProvider());
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        final PGPPublicKey pubKey = converter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, kp.getPublic(), new Date());

        testException("can't find MD5", "PGPException", () -> calculator.calculateFingerprint(new PublicKeyPacket(3, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey())));
        testException("can't find SHA1", "PGPException", () -> calculator.calculateFingerprint(new PublicKeyPacket(4, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey())));
        testException("can't find SHA-256", "PGPException", () -> calculator.calculateFingerprint(new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey())));
        //JcaKeyFingerprintCalculator calculator2 = new JcaKeyFingerprintCalculator().setProvider("BC");
        JcaKeyFingerprintCalculator calculator2 = calculator.setProvider("BC");
        PublicKeyPacket pubKeyPacket = new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey());
        byte[] output = calculator2.calculateFingerprint(new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey()));
        byte[] kBytes = pubKeyPacket.getEncodedContents();
        SHA256Digest digest = new SHA256Digest();

        digest.update((byte)0x9b);

        digest.update((byte)(kBytes.length >> 24));
        digest.update((byte)(kBytes.length >> 16));
        digest.update((byte)(kBytes.length >> 8));
        digest.update((byte)kBytes.length);

        digest.update(kBytes, 0, kBytes.length);
        byte[] digBuf = new byte[digest.getDigestSize()];

        digest.doFinal(digBuf, 0);
        isTrue(areEqual(output, digBuf));

        testException("Unsupported PGP key version: ", "UnsupportedPacketVersionException", () -> calculator.calculateFingerprint(new PublicKeyPacket(7, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey())));
    }

    public void testJcePGPDataEncryptorBuilder()
        throws Exception
    {
        testException("null cipher specified", "IllegalArgumentException", () -> new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.NULL));

        testException("AEAD algorithms can only be used with AES", "IllegalStateException", () -> new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.IDEA).setWithAEAD(AEADAlgorithmTags.OCB, 6));

        testException("minimum chunkSize is 6", "IllegalArgumentException", () -> new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 5));

        isEquals(16, new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setProvider(new BouncyCastleProvider()).setWithAEAD(AEADAlgorithmTags.OCB, 6).build(new byte[32]).getBlockSize());
    }

    public void testJcaPGPDigestCalculatorProviderBuilder()
        throws Exception
    {
        PGPDigestCalculatorProvider provider = new JcaPGPDigestCalculatorProviderBuilder().setProvider(new BouncyCastlePQCProvider()).build();
        testException("exception on setup: ", "PGPException", () -> provider.get(SymmetricKeyAlgorithmTags.AES_256));
    }

    public void testJcaPGPContentVerifierBuilderProvider()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        final PGPPublicKey pubKey = converter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, kp.getPublic(), new Date());
        PGPContentVerifier verifier = new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider()).get(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256).build(pubKey);
        isTrue(verifier.getHashAlgorithm() == HashAlgorithmTags.SHA256);
        isTrue(verifier.getKeyAlgorithm() == PublicKeyAlgorithmTags.RSA_GENERAL);
        isTrue(verifier.getKeyID() == pubKey.getKeyID());
    }

    public void testJcePBESecretKeyEncryptorBuilder()
        throws Exception
    {
        final PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        testException("s2KCount value outside of range 0 to 255.", "IllegalArgumentException", () -> new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc, -1));
    }

}
