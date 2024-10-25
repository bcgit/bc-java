package org.bouncycastle.openpgp.test;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.Ed25519PublicBCPGKey;
import org.bouncycastle.bcpg.Ed25519SecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class DedicatedEd25519KeyPairTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "DedicatedEd25519KeyPairTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testConversionOfJcaKeyPair();
        testConversionOfBcKeyPair();
        testV4SigningVerificationWithJcaKey();
        testV4SigningVerificationWithBcKey();

        testConversionOfTestVectorKey();
    }

    private void testConversionOfJcaKeyPair()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException, IOException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EDDSA", new BouncyCastleProvider());
        gen.initialize(new EdDSAParameterSpec("Ed25519"));
        KeyPair kp = gen.generateKeyPair();

        for (int idx = 0; idx != 2; idx ++)
        {
            int version = (idx == 0) ? PublicKeyPacket.VERSION_4 : PublicKeyPacket.VERSION_6;
            JcaPGPKeyPair j1 = new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.Ed25519, kp, date);
            byte[] pubEnc = j1.getPublicKey().getEncoded();
            byte[] privEnc = j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
            isTrue("Dedicated Ed25519 public key MUST be instanceof Ed25519PublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed25519PublicBCPGKey);
            isTrue("Dedicated Ed25519 secret key MUST be instanceof Ed25519SecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed25519SecretBCPGKey);

            BcPGPKeyPair b1 = toBcKeyPair(j1);
            isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated Ed25519 public key MUST be instanceof Ed25519PublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed25519PublicBCPGKey);
            isTrue("Dedicated Ed25519 secret key MUST be instanceof Ed25519SecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed25519SecretBCPGKey);

            JcaPGPKeyPair j2 = toJcaKeyPair(b1);
            isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated Ed25519 public key MUST be instanceof Ed25519PublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed25519PublicBCPGKey);
            isTrue("Dedicated Ed25519 secret key MUST be instanceof Ed25519SecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed25519SecretBCPGKey);

            BcPGPKeyPair b2 = toBcKeyPair(j2);
            isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated Ed25519 public key MUST be instanceof Ed25519PublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed25519PublicBCPGKey);
            isTrue("Dedicated Ed25519 secret key MUST be instanceof Ed25519SecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed25519SecretBCPGKey);

            isEquals("Creation time is preserved",
                date.getTime(), b2.getPublicKey().getCreationTime().getTime());
        }
    }

    private void testConversionOfBcKeyPair()
            throws PGPException, IOException
    {
        Date date = currentTimeRounded();
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        for (int idx = 0; idx != 2; idx ++)
        {
            int version = (idx == 0) ? PublicKeyPacket.VERSION_4 : PublicKeyPacket.VERSION_6;
            BcPGPKeyPair b1 = new BcPGPKeyPair(version, PublicKeyAlgorithmTags.Ed25519, kp, date);
            byte[] pubEnc = b1.getPublicKey().getEncoded();
            byte[] privEnc = b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
            isTrue("Dedicated Ed25519 public key MUST be instanceof Ed25519PublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed25519PublicBCPGKey);
            isTrue("Dedicated Ed25519 secret key MUST be instanceof Ed25519SecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed25519SecretBCPGKey);

            JcaPGPKeyPair j1 = toJcaKeyPair(b1);
            isEncodingEqual(pubEnc, j1.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated Ed25519 public key MUST be instanceof Ed25519PublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed25519PublicBCPGKey);
            isTrue("Dedicated Ed25519 secret key MUST be instanceof Ed25519SecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed25519SecretBCPGKey);

            BcPGPKeyPair b2 = toBcKeyPair(j1);
            isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated Ed25519 public key MUST be instanceof Ed25519PublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed25519PublicBCPGKey);
            isTrue("Dedicated Ed25519 secret key MUST be instanceof Ed25519SecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed25519SecretBCPGKey);

            JcaPGPKeyPair j2 = toJcaKeyPair(b2);
            isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
            isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
            isTrue("Dedicated Ed25519 public key MUST be instanceof Ed25519PublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof Ed25519PublicBCPGKey);
            isTrue("Dedicated Ed25519 secret key MUST be instanceof Ed25519SecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof Ed25519SecretBCPGKey);

            isEquals("Creation time is preserved",
                date.getTime(), j2.getPublicKey().getCreationTime().getTime());
        }
    }

    private void testV4SigningVerificationWithJcaKey()
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EDDSA", new BouncyCastleProvider());
        gen.initialize(new EdDSAParameterSpec("Ed25519"));
        KeyPair kp = gen.generateKeyPair();
        PGPKeyPair keyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, kp, date);

        byte[] data = Strings.toUTF8ByteArray("Hello, World!\n");

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
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        BcPGPKeyPair keyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, kp, date);

        byte[] data = Strings.toUTF8ByteArray("Hello, World!\n");

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

    private void testConversionOfTestVectorKey()
            throws PGPException, IOException
    {
        JcaPGPKeyConverter jc = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        BcPGPKeyConverter bc = new BcPGPKeyConverter();
        // ed25519 public key from https://www.rfc-editor.org/rfc/rfc9580.html#name-hashed-data-stream-for-sign
        Date creationTime = new Date(Pack.bigEndianToInt(Hex.decode("63877fe3"), 0) * 1000L);
        byte[] k = Hex.decode("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");
        for (int idx = 0; idx != 2; idx ++)
        {
            int version = (idx == 0) ? PublicKeyPacket.VERSION_4 : PublicKeyPacket.VERSION_6;
            PGPPublicKey pgpk = new PGPPublicKey(
                new PublicKeyPacket(version, PublicKeyAlgorithmTags.Ed25519, creationTime, new Ed25519PublicBCPGKey(k)),
                new BcKeyFingerprintCalculator()
            );

            // convert parsed key to Jca public key
            PublicKey jcpk = jc.getPublicKey(pgpk);
            PGPPublicKey jck = jc.getPGPPublicKey(version, PublicKeyAlgorithmTags.Ed25519, jcpk, creationTime);
            isEncodingEqual(pgpk.getEncoded(), jck.getEncoded());

            // convert parsed key to Bc public key
            AsymmetricKeyParameter bcpk = bc.getPublicKey(pgpk);
            PGPPublicKey bck = bc.getPGPPublicKey(version, PublicKeyAlgorithmTags.Ed25519, null, bcpk, creationTime);
            isEncodingEqual(pgpk.getEncoded(), bck.getEncoded());
        }
    }

    public static void main(String[] args)
    {
        runTest(new DedicatedEd25519KeyPairTest());
    }
}
