package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.IOException;
import java.security.*;
import java.util.Date;

public class LegacyEd25519KeyPairTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "LegacyEd25519KeyPairTest";
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
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EDDSA", new BouncyCastleProvider());
        gen.initialize(new EdDSAParameterSpec("Ed25519"));
        KeyPair kp = gen.generateKeyPair();

        JcaPGPKeyPair j1 = new JcaPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, kp, date);
        byte[] pubEnc = j1.getPublicKey().getEncoded();
        byte[] privEnc = j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Legacy Ed25519 public key MUST be instanceof EdDSAPublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof EdDSAPublicBCPGKey);
        isTrue("Legacy Ed25519 secret key MUST be instanceof EdSecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof EdSecretBCPGKey);

        BcPGPKeyPair b1 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy Ed25519 public key MUST be instanceof EdDSAPublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof EdDSAPublicBCPGKey);
        isTrue("Legacy Ed25519 secret key MUST be instanceof EdSecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof EdSecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy Ed25519 public key MUST be instanceof EdDSAPublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof EdDSAPublicBCPGKey);
        isTrue("Legacy Ed25519 secret key MUST be instanceof EdSecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof EdSecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j2);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy Ed25519 public key MUST be instanceof EdDSAPublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof EdDSAPublicBCPGKey);
        isTrue("Legacy Ed25519 secret key MUST be instanceof EdSecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof EdSecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), b2.getPublicKey().getCreationTime().getTime());
    }

    private void testConversionOfBcKeyPair()
            throws PGPException, IOException
    {
        Date date = currentTimeRounded();
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        BcPGPKeyPair b1 = new BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, kp, date);
        byte[] pubEnc = b1.getPublicKey().getEncoded();
        byte[] privEnc = b1.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("Legacy Ed25519 public key MUST be instanceof EdDSAPublicBCPGKey",
                b1.getPublicKey().getPublicKeyPacket().getKey() instanceof EdDSAPublicBCPGKey);
        isTrue("Legacy Ed25519 secret key MUST be instanceof EdSecretBCPGKey",
                b1.getPrivateKey().getPrivateKeyDataPacket() instanceof EdSecretBCPGKey);

        JcaPGPKeyPair j1 = toJcaKeyPair(b1);
        isEncodingEqual(pubEnc, j1.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j1.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy Ed25519 public key MUST be instanceof EdDSAPublicBCPGKey",
                j1.getPublicKey().getPublicKeyPacket().getKey() instanceof EdDSAPublicBCPGKey);
        isTrue("Legacy Ed25519 secret key MUST be instanceof EdSecretBCPGKey",
                j1.getPrivateKey().getPrivateKeyDataPacket() instanceof EdSecretBCPGKey);

        BcPGPKeyPair b2 = toBcKeyPair(j1);
        isEncodingEqual(pubEnc, b2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, b2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy Ed25519 public key MUST be instanceof EdDSAPublicBCPGKey",
                b2.getPublicKey().getPublicKeyPacket().getKey() instanceof EdDSAPublicBCPGKey);
        isTrue("Legacy Ed25519 secret key MUST be instanceof EdSecretBCPGKey",
                b2.getPrivateKey().getPrivateKeyDataPacket() instanceof EdSecretBCPGKey);

        JcaPGPKeyPair j2 = toJcaKeyPair(b2);
        isEncodingEqual(pubEnc, j2.getPublicKey().getEncoded());
        isEncodingEqual(privEnc, j2.getPrivateKey().getPrivateKeyDataPacket().getEncoded());
        isTrue("Legacy Ed25519 public key MUST be instanceof EdDSAPublicBCPGKey",
                j2.getPublicKey().getPublicKeyPacket().getKey() instanceof EdDSAPublicBCPGKey);
        isTrue("Legacy Ed25519 secret key MUST be instanceof EdSecretBCPGKey",
                j2.getPrivateKey().getPrivateKeyDataPacket() instanceof EdSecretBCPGKey);

        isEquals("Creation time is preserved",
                date.getTime(), j2.getPublicKey().getCreationTime().getTime());
    }

    public static void main(String[] args)
    {
        runTest(new LegacyEd25519KeyPairTest());
    }
}
