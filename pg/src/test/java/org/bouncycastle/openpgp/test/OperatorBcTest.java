package org.bouncycastle.openpgp.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.test.SimpleTest;

public class OperatorBcTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OperatorBcTest());
    }

    @Override
    public String getName()
    {
        return "OperatorBcTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testBcPGPDataEncryptorBuilder();
        testBcPGPContentVerifierBuilderProvider();
        //testBcPBESecretKeyDecryptorBuilder();
        testBcKeyFingerprintCalculator();
    }

    public void testBcKeyFingerprintCalculator()
        throws Exception
    {
        final BcKeyFingerprintCalculator calculator = new BcKeyFingerprintCalculator();
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        final PGPPublicKey pubKey = converter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, kp.getPublic(), new Date());

        PublicKeyPacket pubKeyPacket = new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey());
        byte[] output = calculator.calculateFingerprint(new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey()));
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

        final PublicKeyPacket pubKeyPacket2 = new PublicKeyPacket(5, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey());
        testException("Unsupported PGP key version: ", "UnsupportedPacketVersionException", () -> calculator.calculateFingerprint(pubKeyPacket2));
    }

//    public void testBcPBESecretKeyDecryptorBuilder()
//        throws PGPException
//    {
//        final PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(BcPGPDSAElGamalTest.pass);
//        decryptor.recoverKeyData(SymmetricKeyAlgorithmTags.CAMELLIA_256, new byte[32], new byte[12], new byte[16], 0, 16);
//    }

    public void testBcPGPContentVerifierBuilderProvider()
        throws Exception
    {
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(BcPGPDSAElGamalTest.testPubKeyRing);
        PGPPublicKeyRing pgpPub = (PGPPublicKeyRing)pgpFact.nextObject();
        PGPPublicKey pubKey = pgpPub.getPublicKey();
        BcPGPContentVerifierBuilderProvider provider = new BcPGPContentVerifierBuilderProvider();
        PGPContentVerifier contentVerifier = provider.get(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1).build(pubKey);
        isEquals(contentVerifier.getHashAlgorithm(), HashAlgorithmTags.SHA1);
        isEquals(contentVerifier.getKeyAlgorithm(), PublicKeyAlgorithmTags.DSA);
        isEquals(contentVerifier.getKeyID(), pubKey.getKeyID());
    }

    public void testBcPGPDataEncryptorBuilder()
        throws Exception
    {
        testException("null cipher specified", "IllegalArgumentException", () -> new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.NULL));

        testException("AEAD algorithms can only be used with AES", "IllegalStateException", () -> new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.IDEA).setWithAEAD(AEADAlgorithmTags.OCB, 6));

        testException("minimum chunkSize is 6", "IllegalArgumentException", () -> new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 5));

        testException("invalid parameters:", "PGPException", () -> new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).build(new byte[0]));

        isTrue(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(false).build(new byte[32]).getIntegrityCalculator() == null);

        isEquals(16, new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 6).build(new byte[32]).getBlockSize());
    }
}
