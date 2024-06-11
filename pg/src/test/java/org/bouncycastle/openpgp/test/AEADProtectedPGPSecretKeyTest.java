package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

public class AEADProtectedPGPSecretKeyTest
        extends AbstractPgpKeyPairTest
{

    @Override
    public String getName()
    {
        return "Argon2ProtectedPGPSecretKeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        unlockTestVector();
        lockGeneratedV4Key();
    }

    private void unlockTestVector()
            throws IOException, PGPException
    {
        // AEAD encrypted test vector extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-locked-v6-secret-key
        String armoredVector = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xYIGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP9JgkC\n" +
                "FARdb9ccngltHraRe25uHuyuAQQVtKipJ0+r5jL4dacGWSAheCWPpITYiyfyIOPS\n" +
                "3gIDyg8f7strd1OB4+LZsUhcIjOMpVHgmiY/IutJkulneoBYwrEGHxsKAAAAQgWC\n" +
                "Y4d/4wMLCQcFFQoOCAwCFgACmwMCHgkiIQbLGGxPBgmml+TVLfpscisMHx4nwYpW\n" +
                "cI9lJewnutmsyQUnCQIHAgAAAACtKCAQPi19In7A5tfORHHbNr/JcIMlNpAnFJin\n" +
                "7wV2wH+q4UWFs7kDsBJ+xP2i8CMEWi7Ha8tPlXGpZR4UruETeh1mhELIj5UeM8T/\n" +
                "0z+5oX1RHu11j8bZzFDLX9eTsgOdWATHggZjh3/jGQAAACCGkySDZ/nlAV25Ivj0\n" +
                "gJXdp4SYfy1ZhbEvutFsr15ENf0mCQIUBA5hhGgp2oaavg6mFUXcFMwBBBUuE8qf\n" +
                "9Ock+xwusd+GAglBr5LVyr/lup3xxQvHXFSjjA2haXfoN6xUGRdDEHI6+uevKjVR\n" +
                "v5oAxgu7eJpaXNjCmwYYGwoAAAAsBYJjh3/jApsMIiEGyxhsTwYJppfk1S36bHIr\n" +
                "DB8eJ8GKVnCPZSXsJ7rZrMkAAAAABAEgpukYbZ1ZNfyP5WMUzbUnSGpaUSD5t2Ki\n" +
                "Nacp8DkBClZRa2c3AMQzSDXa9jGhYzxjzVb5scHDzTkjyRZWRdTq8U6L4da+/+Kt\n" +
                "ruh8m7Xo2ehSSFyWRSuTSZe5tm/KXgYG\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        char[] passphrase = "correct horse battery staple".toCharArray();
        // Plaintext vectors extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-secret-key-transf
        byte[] plainPrimaryKey = Hex.decode("1972817b12be707e8d5f586ce61361201d344eb266a2c82fde6835762b65b0b7");
        byte[] plainSubkey = Hex.decode("4d600a4f794d44775c57a26e0feefed558e9afffd6ad0d582d57fb2ba2dcedb8");

        ByteArrayInputStream bIn = new ByteArrayInputStream(armoredVector.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFact = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing keys = (PGPSecretKeyRing) objFact.nextObject();

        Iterator<PGPSecretKey> it = keys.getSecretKeys();
        PGPSecretKey primaryKey = it.next();
        PGPSecretKey subkey = it.next();

        // Test Bouncy Castle implementation
        BcPBESecretKeyDecryptorBuilder bcDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
        PGPPrivateKey privPrimaryKey = primaryKey.extractPrivateKey(bcDecryptor.build(passphrase));
        isEncodingEqual(plainPrimaryKey, privPrimaryKey.getPrivateKeyDataPacket().getEncoded());

        // Test Jca/Jce implementation
        JcePBESecretKeyDecryptorBuilder jceDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider());
        PGPPrivateKey privSubKey = subkey.extractPrivateKey(jceDecryptor.build(passphrase));
        isEncodingEqual(plainSubkey, privSubKey.getPrivateKeyDataPacket().getEncoded());
    }

    private void lockGeneratedV4Key() throws PGPException {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        Date creationTime = currentTimeRounded();
        PGPKeyPair keyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, kp, creationTime);

        BcAEADSecretKeyEncryptorBuilder encBuilder = new BcAEADSecretKeyEncryptorBuilder(
                AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256,
                S2K.Argon2Params.memoryConstrainedParameters()
        );

        PGPSecretKey sk = new PGPSecretKey(
                keyPair.getPrivateKey(),
                keyPair.getPublicKey(),
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                true,
                encBuilder.build("Hello".toCharArray(), keyPair.getPublicKey().getPublicKeyPacket()));

        isEquals(SecretKeyPacket.USAGE_AEAD, sk.getS2KUsage());
        isEquals(S2K.ARGON_2, sk.getS2K().getType());
        isEquals(3, sk.getS2K().getPasses());
        isEquals(4, sk.getS2K().getParallelism());
        isEquals(16, sk.getS2K().getMemorySizeExponent());

        BcPBESecretKeyDecryptorBuilder decBuilder = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());

        PGPPrivateKey dec = sk.extractPrivateKey(decBuilder.build("Hello".toCharArray()));
        isEncodingEqual(keyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded(), dec.getPrivateKeyDataPacket().getEncoded());
    }

    public static void main(String[] args)
    {
        runTest(new AEADProtectedPGPSecretKeyTest());
    }
}
