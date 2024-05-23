package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.bcpg.X25519SecretBCPGKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.IOException;
import java.security.*;
import java.util.Date;

public class DedicatedX25519KeyPairTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "DedicatedX25519KeyPairTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testConversionOfJcaKeyPair();
        testConversionOfBcKeyPair();
    }

    private void testConversionOfJcaKeyPair()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException, IOException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", new BouncyCastleProvider());
        gen.initialize(new XDHParameterSpec("X25519"));
        KeyPair kp = gen.generateKeyPair();

        JcaPGPKeyPair j1 = new JcaPGPKeyPair(PublicKeyAlgorithmTags.X25519, kp, date);
        byte[] pubEnc = j1.getPublicKey().getEncoded();
        byte[] privEnc = j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Dedicated X25519 public key MUST be instanceof X25519PublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof X25519PublicBCPGKey);
        isTrue("Dedicated X25519 secret key MUST be instanceof X25519SecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof X25519SecretBCPGKey);

        BcPGPKeyPair b1 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated X25519 public key MUST be instanceof X25519PublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof X25519PublicBCPGKey);
        isTrue("Dedicated X25519 secret key MUST be instanceof X25519SecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof X25519SecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated X25519 public key MUST be instanceof X25519PublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof X25519PublicBCPGKey);
        isTrue("Dedicated X25519 secret key MUST be instanceof X25519SecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof X25519SecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j2);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated X25519 public key MUST be instanceof X25519PublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof X25519PublicBCPGKey);
        isTrue("Dedicated X25519 secret key MUST be instanceof X25519SecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof X25519SecretBCPGKey);

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

        BcPGPKeyPair b1 = new BcPGPKeyPair(PublicKeyAlgorithmTags.X25519, kp, date);
        byte[] pubEnc = b1.getPublicKey().getEncoded();
        byte[] privEnc = b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Dedicated X25519 public key MUST be instanceof X25519PublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof X25519PublicBCPGKey);
        isTrue("Dedicated X25519 secret key MUST be instanceof X25519SecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof X25519SecretBCPGKey);

        JcaPGPKeyPair j1 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated X25519 public key MUST be instanceof X25519PublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof X25519PublicBCPGKey);
        isTrue("Dedicated X25519 secret key MUST be instanceof X25519SecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof X25519SecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated X25519 public key MUST be instanceof X25519PublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof X25519PublicBCPGKey);
        isTrue("Dedicated X25519 secret key MUST be instanceof X25519SecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof X25519SecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b2);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Dedicated X25519 public key MUST be instanceof X25519PublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof X25519PublicBCPGKey);
        isTrue("Dedicated X25519 secret key MUST be instanceof X25519SecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof X25519SecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), j2.getPublicKey().getCreationTime().getTime());
    }

    public static void main(String[] args)
    {
        runTest(new DedicatedX25519KeyPairTest());
    }
}
