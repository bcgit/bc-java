package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.*;
import java.util.Date;

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

        testConversionOfTestVectorKey();
    }

    private void testConversionOfJcaKeyPair()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException, IOException
    {
        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EDDSA", new BouncyCastleProvider());
        gen.initialize(new EdDSAParameterSpec("Ed25519"));
        KeyPair kp = gen.generateKeyPair();

        JcaPGPKeyPair j1 = new JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, kp, date);
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

    private void testConversionOfBcKeyPair()
            throws PGPException, IOException
    {
        Date date = currentTimeRounded();
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        BcPGPKeyPair b1 = new BcPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, kp, date);
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

    private void testConversionOfTestVectorKey() throws PGPException, IOException {
        JcaPGPKeyConverter jc = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        BcPGPKeyConverter bc = new BcPGPKeyConverter();
        // ed25519 public key from https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-hashed-data-stream-for-sign
        //  just adapted to be a version 4 key.
        Date creationTime = new Date(Pack.bigEndianToInt(Hex.decode("63877fe3"), 0) * 1000L);
        byte[] k = Hex.decode("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");
        PGPPublicKey v4k = new PGPPublicKey(
                new PublicKeyPacket(PublicKeyAlgorithmTags.Ed25519, creationTime, new Ed25519PublicBCPGKey(k)),
                new BcKeyFingerprintCalculator()
        );

        // convert parsed key to Jca public key
        PublicKey jcpk = jc.getPublicKey(v4k);
        PGPPublicKey jck = jc.getPGPPublicKey(PublicKeyAlgorithmTags.Ed25519, jcpk, creationTime);
        isEncodingEqual(v4k.getEncoded(), jck.getEncoded());

        // convert parsed key to Bc public key
        AsymmetricKeyParameter bcpk = bc.getPublicKey(v4k);
        PGPPublicKey bck = bc.getPGPPublicKey(PublicKeyAlgorithmTags.Ed25519, null, bcpk, creationTime);
        isEncodingEqual(v4k.getEncoded(), bck.getEncoded());
    }

    public static void main(String[] args)
    {
        runTest(new DedicatedEd25519KeyPairTest());
    }
}
