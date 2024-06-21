package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Date;

public class LegacyX25519KeyPairTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "LegacyX25519KeyPairTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testConversionOfJcaKeyPair();
        testConversionOfBcKeyPair();

        testV4MessageEncryptionDecryptionWithJcaKey();
        testV4MessageEncryptionDecryptionWithBcKey();
    }

    private void testV4MessageEncryptionDecryptionWithJcaKey()
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException
    {
        BouncyCastleProvider provider = new BouncyCastleProvider();

        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", provider);
        gen.initialize(new XDHParameterSpec("X25519"));
        KeyPair kp = gen.generateKeyPair();
        PGPKeyPair keyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, date);

        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

        PGPDataEncryptorBuilder encBuilder = new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setProvider(provider);
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder);
        PublicKeyKeyEncryptionMethodGenerator metGen = new JcePublicKeyKeyEncryptionMethodGenerator(keyPair.getPublicKey())
                .setProvider(provider);
        encGen.addMethod(metGen);
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = encGen.open(bOut, new byte[4096]);
        OutputStream litOut = litGen.open(encOut, PGPLiteralData.BINARY, "", PGPLiteralData.NOW, new byte[4096]);
        litOut.write(data);
        litGen.close();
        encGen.close();

        byte[] encrypted = bOut.toByteArray();

        ByteArrayInputStream bIn = new ByteArrayInputStream(encrypted);
        PGPObjectFactory objectFactory = new JcaPGPObjectFactory(bIn);
        PGPEncryptedDataList encDataList = (PGPEncryptedDataList) objectFactory.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encDataList.get(0);
        PublicKeyDataDecryptorFactory decFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(provider)
                .build(keyPair.getPrivateKey());
        InputStream decIn = encData.getDataStream(decFactory);
        objectFactory = new JcaPGPObjectFactory(decIn);
        PGPLiteralData lit = (PGPLiteralData) objectFactory.nextObject();
        InputStream litIn = lit.getDataStream();
        byte[] plaintext = Streams.readAll(litIn);
        litIn.close();
        decIn.close();

        isTrue(Arrays.areEqual(data, plaintext));
    }

    private void testV4MessageEncryptionDecryptionWithBcKey()
            throws PGPException, IOException {
        Date date = currentTimeRounded();
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        BcPGPKeyPair keyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, date);

        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

        PGPDataEncryptorBuilder encBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder);
        PublicKeyKeyEncryptionMethodGenerator metGen = new BcPublicKeyKeyEncryptionMethodGenerator(keyPair.getPublicKey());
        encGen.addMethod(metGen);
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = encGen.open(bOut, new byte[4096]);
        OutputStream litOut = litGen.open(encOut, PGPLiteralData.BINARY, "", PGPLiteralData.NOW, new byte[4096]);
        litOut.write(data);
        litGen.close();
        encGen.close();

        byte[] encrypted = bOut.toByteArray();

        ByteArrayInputStream bIn = new ByteArrayInputStream(encrypted);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(bIn);
        PGPEncryptedDataList encDataList = (PGPEncryptedDataList) objectFactory.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encDataList.get(0);
        PublicKeyDataDecryptorFactory decFactory = new BcPublicKeyDataDecryptorFactory(keyPair.getPrivateKey());
        InputStream decIn = encData.getDataStream(decFactory);
        objectFactory = new BcPGPObjectFactory(decIn);
        PGPLiteralData lit = (PGPLiteralData) objectFactory.nextObject();
        InputStream litIn = lit.getDataStream();
        byte[] plaintext = Streams.readAll(litIn);
        litIn.close();
        decIn.close();

        isTrue(Arrays.areEqual(data, plaintext));
    }

    private void testConversionOfJcaKeyPair()
            throws NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException, IOException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", new BouncyCastleProvider());
        gen.initialize(new XDHParameterSpec("X25519"));
        KeyPair kp = gen.generateKeyPair();

        JcaPGPKeyPair j1 = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, date);
        byte[] pubEnc = j1.getPublicKey().getEncoded();
        byte[] privEnc = j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Legacy X25519 public key MUST be instanceof ECDHPublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X25519 secret key MUST be instanceof ECSecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        BcPGPKeyPair b1 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X25519 public key MUST be instanceof ECDHPublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X25519 secret key MUST be instanceof ECSecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X25519 public key MUST be instanceof ECDHPublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X25519 secret key MUST be instanceof ECSecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j2);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X25519 public key MUST be instanceof ECDHPublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X25519 secret key MUST be instanceof ECSecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), b2.getPublicKey().getCreationTime().getTime());
    }

    private void testConversionOfBcKeyPair()
            throws PGPException, IOException
    {
        Date date = currentTimeRounded();
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        BcPGPKeyPair b1 = new BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, date);
        byte[] pubEnc = b1.getPublicKey().getEncoded();
        byte[] privEnc = b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Legacy X25519 public key MUST be instanceof ECDHPublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X25519 secret key MUST be instanceof ECSecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        JcaPGPKeyPair j1 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X25519 public key MUST be instanceof ECDHPublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X25519 secret key MUST be instanceof ECSecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X25519 public key MUST be instanceof ECDHPublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X25519 secret key MUST be instanceof ECSecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b2);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X25519 public key MUST be instanceof ECDHPublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X25519 secret key MUST be instanceof ECSecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), j2.getPublicKey().getCreationTime().getTime());
    }

    public static void main(String[] args)
    {
        runTest(new LegacyX25519KeyPairTest());
    }
}
