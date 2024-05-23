package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.IOException;
import java.security.*;
import java.util.Date;

public class LegacyX448KeyPairTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "LegacyX448KeyPairTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testConversionOfJcaKeyPair();
        testConversionOfBcKeyPair();
    }

    private void testConversionOfJcaKeyPair()
            throws NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException, IOException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", new BouncyCastleProvider());
        gen.initialize(new XDHParameterSpec("X448"));
        KeyPair kp = gen.generateKeyPair();

        JcaPGPKeyPair j1 = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, date);
        byte[] pubEnc = j1.getPublicKey().getEncoded();
        byte[] privEnc = j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Legacy X448 public key MUST be instanceof ECDHPublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X448 secret key MUST be instanceof ECSecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        BcPGPKeyPair b1 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X448 public key MUST be instanceof ECDHPublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X448 secret key MUST be instanceof ECSecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X448 public key MUST be instanceof ECDHPublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X448 secret key MUST be instanceof ECSecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j2);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X448 public key MUST be instanceof ECDHPublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X448 secret key MUST be instanceof ECSecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), b2.getPublicKey().getCreationTime().getTime());
    }

    private void testConversionOfBcKeyPair()
            throws PGPException, IOException
    {
        Date date = currentTimeRounded();
        X448KeyPairGenerator gen = new X448KeyPairGenerator();
        gen.init(new X448KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        BcPGPKeyPair b1 = new BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, date);
        byte[] pubEnc = b1.getPublicKey().getEncoded();
        byte[] privEnc = b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Legacy X448 public key MUST be instanceof ECDHPublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X448 secret key MUST be instanceof ECSecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        JcaPGPKeyPair j1 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X448 public key MUST be instanceof ECDHPublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X448 secret key MUST be instanceof ECSecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X448 public key MUST be instanceof ECDHPublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X448 secret key MUST be instanceof ECSecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b2);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy X448 public key MUST be instanceof ECDHPublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof ECDHPublicBCPGKey);
        isTrue("Legacy X448 secret key MUST be instanceof ECSecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof ECSecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), j2.getPublicKey().getCreationTime().getTime());
    }

    public static void main(String[] args)
    {
        runTest(new LegacyX448KeyPairTest());
    }
}
