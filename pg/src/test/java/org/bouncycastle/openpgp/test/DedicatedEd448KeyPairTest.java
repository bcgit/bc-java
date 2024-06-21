package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.Ed448PublicBCPGKey;
import org.bouncycastle.bcpg.Ed448SecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Date;

public class DedicatedEd448KeyPairTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "DedicatedEd448KeyPairTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testConversionOfJcaKeyPair();
        testConversionOfBcKeyPair();
        testV4SigningVerificationWithJcaKey();
        testV4SigningVerificationWithBcKey();
    }

    private void testV4SigningVerificationWithJcaKey()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EDDSA", new BouncyCastleProvider());
        gen.initialize(new EdDSAParameterSpec("Ed448"));
        KeyPair kp = gen.generateKeyPair();
        PGPKeyPair keyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed448, kp, date);

        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

        PGPContentSignerBuilder contSigBuilder = new JcaPGPContentSignerBuilder(
                keyPair.getPublicKey().getAlgorithm(),
                HashAlgorithmTags.SHA512)
                .setProvider(new BouncyCastleProvider());
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(contSigBuilder);
        sigGen.init(PGPSignature.BINARY_DOCUMENT, keyPair.getPrivateKey());
        sigGen.update(data);
        PGPSignature signature = sigGen.generate();

        PGPContentVerifierBuilderProvider contVerBuilder = new JcaPGPContentVerifierBuilderProvider()
                .setProvider(new BouncyCastleProvider());
        signature.init(contVerBuilder, keyPair.getPublicKey());
        signature.update(data);
        isTrue(signature.verify());
    }

    private void testV4SigningVerificationWithBcKey()
            throws PGPException
    {
        Date date = currentTimeRounded();
        Ed448KeyPairGenerator gen = new Ed448KeyPairGenerator();
        gen.init(new Ed448KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        BcPGPKeyPair keyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.Ed448, kp, date);

        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

        PGPContentSignerBuilder contSigBuilder = new BcPGPContentSignerBuilder(
                keyPair.getPublicKey().getAlgorithm(),
                HashAlgorithmTags.SHA512);
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(contSigBuilder);
        sigGen.init(PGPSignature.BINARY_DOCUMENT, keyPair.getPrivateKey());
        sigGen.update(data);
        PGPSignature signature = sigGen.generate();

        PGPContentVerifierBuilderProvider contVerBuilder = new BcPGPContentVerifierBuilderProvider();
        signature.init(contVerBuilder, keyPair.getPublicKey());
        signature.update(data);
        isTrue(signature.verify());
    }

    private void testConversionOfJcaKeyPair()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException, IOException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EDDSA", new BouncyCastleProvider());
        gen.initialize(new EdDSAParameterSpec("Ed448"));
        KeyPair kp = gen.generateKeyPair();

        JcaPGPKeyPair j1 = new JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed448, kp, date);
        byte[] pubEnc = j1.getPublicKey().getEncoded();
        byte[] privEnc = j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Dedicated Ed448 public key MUST be instanceof Ed448PublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed448PublicBCPGKey);
        isTrue("Dedicated Ed448 secret key MUST be instanceof Ed448SecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed448SecretBCPGKey);

        BcPGPKeyPair b1 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated Ed448 public key MUST be instanceof Ed448PublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed448PublicBCPGKey);
        isTrue("Dedicated Ed448 secret key MUST be instanceof Ed448SecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed448SecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated Ed448 public key MUST be instanceof Ed448PublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed448PublicBCPGKey);
        isTrue("Dedicated Ed448 secret key MUST be instanceof Ed448SecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed448SecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j2);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated Ed448 public key MUST be instanceof Ed448PublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed448PublicBCPGKey);
        isTrue("Dedicated Ed448 secret key MUST be instanceof Ed448SecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed448SecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), b2.getPublicKey().getCreationTime().getTime());
    }

    private void testConversionOfBcKeyPair()
            throws PGPException, IOException
    {
        Date date = currentTimeRounded();
        Ed448KeyPairGenerator gen = new Ed448KeyPairGenerator();
        gen.init(new Ed448KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        BcPGPKeyPair b1 = new BcPGPKeyPair(PublicKeyAlgorithmTags.Ed448, kp, date);
        byte[] pubEnc = b1.getPublicKey().getEncoded();
        byte[] privEnc = b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Dedicated Ed448 public key MUST be instanceof Ed448PublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed448PublicBCPGKey);
        isTrue("Dedicated Ed448 secret key MUST be instanceof Ed448SecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed448SecretBCPGKey);

        JcaPGPKeyPair j1 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated Ed448 public key MUST be instanceof Ed448PublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed448PublicBCPGKey);
        isTrue("Dedicated Ed448 secret key MUST be instanceof Ed448SecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed448SecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated Ed448 public key MUST be instanceof Ed448PublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed448PublicBCPGKey);
        isTrue("Dedicated Ed448 secret key MUST be instanceof Ed448SecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed448SecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b2);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated Ed448 public key MUST be instanceof Ed448PublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed448PublicBCPGKey);
        isTrue("Dedicated Ed448 secret key MUST be instanceof Ed448SecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed448SecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), j2.getPublicKey().getCreationTime().getTime());
    }

    public static void main(String[] args)
    {
        runTest(new DedicatedEd448KeyPairTest());
    }
}
