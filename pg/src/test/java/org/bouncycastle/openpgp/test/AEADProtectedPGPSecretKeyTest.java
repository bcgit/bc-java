package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaAEADSecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class AEADProtectedPGPSecretKeyTest
    extends AbstractPgpKeyPairTest
{

    @Override
    public String getName()
    {
        return "AEADProtectedPGPSecretKeyTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        unlockTestVector();

        generateAndLockUnlockEd25519v4Key();
        generateAndLockUnlockEd25519v6Key();

        testUnlockKeyWithWrongPassphraseBc();
        testUnlockKeyWithWrongPassphraseJca();

        reencryptKey();
    }

    private void unlockTestVector()
        throws IOException, PGPException
    {
        // AEAD encrypted test vector extracted from here:
        // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-locked-v6-secret-key
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
        // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-v6-secret-key-transf
        byte[] plainPrimaryKey = Hex.decode("1972817b12be707e8d5f586ce61361201d344eb266a2c82fde6835762b65b0b7");
        byte[] plainSubkey = Hex.decode("4d600a4f794d44775c57a26e0feefed558e9afffd6ad0d582d57fb2ba2dcedb8");

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(armoredVector));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFact = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing keys = (PGPSecretKeyRing) objFact.nextObject();

        Iterator<PGPSecretKey> it = keys.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)it.next();
        PGPSecretKey subkey = (PGPSecretKey)it.next();

        // Test Bouncy Castle KeyDecryptor implementation
        BcPBESecretKeyDecryptorBuilder bcDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
        PGPPrivateKey privPrimaryKey = primaryKey.extractPrivateKey(bcDecryptor.build(passphrase));
        isEncodingEqual(plainPrimaryKey, privPrimaryKey.getPrivateKeyDataPacket().getEncoded());

        // Test Jca/Jce KeyDecryptor implementation
        JcePBESecretKeyDecryptorBuilder jceDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider());
        PGPPrivateKey privSubKey = subkey.extractPrivateKey(jceDecryptor.build(passphrase));
        isEncodingEqual(plainSubkey, privSubKey.getPrivateKeyDataPacket().getEncoded());

        // Test Jca/Jce ProtectionRemover implementation
        JcePBEProtectionRemoverFactory jceProtectionRemover = new JcePBEProtectionRemoverFactory(passphrase).setProvider(new BouncyCastleProvider());
        PGPPrivateKey privSubKey2 = subkey.extractPrivateKey(jceProtectionRemover.createDecryptor(""));
        isEncodingEqual(plainSubkey, privSubKey2.getPrivateKeyDataPacket().getEncoded());
    }

    private void generateAndLockUnlockEd25519v4Key()
        throws PGPException
    {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        Date creationTime = currentTimeRounded();
        PGPKeyPair keyPair = new BcPGPKeyPair(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.Ed25519, kp, creationTime);

        String passphrase = "a$$word";

        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.AES_128, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_128, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.AES_128, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.AES_128, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_128, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.AES_128, passphrase, passphrase);

        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.AES_192, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_192, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.AES_192, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.AES_192, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_192, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.AES_192, passphrase, passphrase);

        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);


        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.CAMELLIA_128, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.CAMELLIA_128, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.CAMELLIA_128, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.CAMELLIA_128, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.CAMELLIA_128, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.CAMELLIA_128, passphrase, passphrase);

        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.CAMELLIA_192, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.CAMELLIA_192, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.CAMELLIA_192, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.CAMELLIA_192, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.CAMELLIA_192, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.CAMELLIA_192, passphrase, passphrase);

        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.CAMELLIA_256, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.CAMELLIA_256, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.CAMELLIA_256, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.CAMELLIA_256, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.CAMELLIA_256, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.CAMELLIA_256, passphrase, passphrase);
    }

    private void generateAndLockUnlockEd25519v6Key()
        throws PGPException
    {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        Date creationTime = currentTimeRounded();

        String passphrase = "a$$word";
        
        PGPKeyPair keyPair = new BcPGPKeyPair(PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.Ed25519, kp, creationTime);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyBc(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.EAX, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
        lockUnlockKeyJca(keyPair, AEADAlgorithmTags.GCM, SymmetricKeyAlgorithmTags.AES_256, passphrase, passphrase);
         
    }

    private void testUnlockKeyWithWrongPassphraseBc()
        throws PGPException
    {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        Date creationTime = currentTimeRounded();
        
        for (int idx = 0; idx != 2; idx ++)
        {
            int version = (idx == 0) ? PublicKeyPacket.VERSION_4 : PublicKeyPacket.VERSION_6;
            PGPKeyPair keyPair = new BcPGPKeyPair(version, PublicKeyAlgorithmTags.Ed25519, kp, creationTime);

            BcAEADSecretKeyEncryptorBuilder bcEncBuilder = new BcAEADSecretKeyEncryptorBuilder(
                AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256,
                S2K.Argon2Params.memoryConstrainedParameters());

            PGPDigestCalculatorProvider digestProv = new BcPGPDigestCalculatorProvider();

            PGPSecretKey sk = new PGPSecretKey(
                keyPair.getPrivateKey(),
                keyPair.getPublicKey(),
                digestProv.get(HashAlgorithmTags.SHA1),
                true,
                bcEncBuilder.build(
                    "passphrase".toCharArray(),
                    keyPair.getPublicKey().getPublicKeyPacket()));

            BcPBESecretKeyDecryptorBuilder bcDecBuilder = new BcPBESecretKeyDecryptorBuilder(digestProv);
            try
            {
                sk.extractPrivateKey(bcDecBuilder.build("password".toCharArray()));
                fail("Expected PGPException due to mismatched passphrase");
            }
            catch (PGPException e)
            {
                // expected
            }
        }
    }

    private void testUnlockKeyWithWrongPassphraseJca()
        throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        BouncyCastleProvider prov = new BouncyCastleProvider();
        KeyPairGenerator eddsaGen = KeyPairGenerator.getInstance("EdDSA", prov);

        eddsaGen.initialize(new ECNamedCurveGenParameterSpec("ed25519"));
        KeyPair kp = eddsaGen.generateKeyPair();
        Date creationTime = currentTimeRounded();

        for (int idx = 0; idx != 2; idx ++)
        {
            int version = (idx == 0) ? PublicKeyPacket.VERSION_4 : PublicKeyPacket.VERSION_6;
            PGPKeyPair keyPair = new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.Ed25519, kp, creationTime);
            
            JcaAEADSecretKeyEncryptorBuilder jcaEncBuilder = new JcaAEADSecretKeyEncryptorBuilder(
                AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256,
                S2K.Argon2Params.memoryConstrainedParameters())
                .setProvider(prov);

            PGPDigestCalculatorProvider digestProv = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(prov)
                .build();

            PGPSecretKey sk = new PGPSecretKey(
                keyPair.getPrivateKey(),
                keyPair.getPublicKey(),
                digestProv.get(HashAlgorithmTags.SHA1),
                true,
                jcaEncBuilder.build(
                    "Yin".toCharArray(),
                    keyPair.getPublicKey().getPublicKeyPacket()));

            JcePBESecretKeyDecryptorBuilder jceDecBuilder = new JcePBESecretKeyDecryptorBuilder(digestProv).setProvider(prov);
            try
            {
                sk.extractPrivateKey(jceDecBuilder.build("Yang".toCharArray()));
                fail("Expected PGPException due to wrong passphrase");
            }
            catch (PGPException e)
            {
                // expected
            }
        }
    }

    private void lockUnlockKeyBc(
        PGPKeyPair keyPair,
        int aeadAlgorithm,
        int encAlgorithm,
        String encryptionPassphrase,
        String decryptionPassphrase)
        throws PGPException
    {
        BcAEADSecretKeyEncryptorBuilder bcEncBuilder = new BcAEADSecretKeyEncryptorBuilder(
            aeadAlgorithm, encAlgorithm,
            S2K.Argon2Params.memoryConstrainedParameters());

        PGPDigestCalculatorProvider digestProv = new BcPGPDigestCalculatorProvider();

        PGPSecretKey sk = new PGPSecretKey(
            keyPair.getPrivateKey(),
            keyPair.getPublicKey(),
            digestProv.get(HashAlgorithmTags.SHA1),
            true,
            bcEncBuilder.build(
                encryptionPassphrase.toCharArray(),
                keyPair.getPublicKey().getPublicKeyPacket()));

        isEquals("S2KUsage mismatch", SecretKeyPacket.USAGE_AEAD, sk.getS2KUsage());
        isEquals("S2K type mismatch", S2K.ARGON_2, sk.getS2K().getType());
        isEquals("Argon2 passes parameter mismatch", 3, sk.getS2K().getPasses());
        isEquals("Argon2 parallelism parameter mismatch", 4, sk.getS2K().getParallelism());
        isEquals("Argon2 memory exponent parameter mismatch", 16, sk.getS2K().getMemorySizeExponent());
        isEquals("Symmetric key encryption algorithm mismatch", encAlgorithm, sk.getKeyEncryptionAlgorithm());
        isEquals("AEAD key encryption algorithm mismatch", aeadAlgorithm, sk.getAEADKeyEncryptionAlgorithm());

        BcPBESecretKeyDecryptorBuilder bcDecBuilder = new BcPBESecretKeyDecryptorBuilder(digestProv);
        PGPPrivateKey dec = sk.extractPrivateKey(bcDecBuilder.build(decryptionPassphrase.toCharArray()));
        isEncodingEqual("Decrypted key encoding mismatch",
            keyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded(), dec.getPrivateKeyDataPacket().getEncoded());
    }

    private void lockUnlockKeyJca(
        PGPKeyPair keyPair,
        int aeadAlgorithm,
        int encAlgorithm,
        String encryptionPassphrase,
        String decryptionPassphrase)
        throws PGPException
    {
        BouncyCastleProvider prov = new BouncyCastleProvider();
        JcaAEADSecretKeyEncryptorBuilder jcaEncBuilder = new JcaAEADSecretKeyEncryptorBuilder(
            aeadAlgorithm, encAlgorithm,
            S2K.Argon2Params.memoryConstrainedParameters())
            .setProvider(prov);

        PGPDigestCalculatorProvider digestProv = new JcaPGPDigestCalculatorProviderBuilder()
            .setProvider(prov)
            .build();

        PGPSecretKey sk = new PGPSecretKey(
            keyPair.getPrivateKey(),
            keyPair.getPublicKey(),
            digestProv.get(HashAlgorithmTags.SHA1),
            true,
            jcaEncBuilder.build(
                encryptionPassphrase.toCharArray(),
                keyPair.getPublicKey().getPublicKeyPacket()));

        isEquals("S2KUsage mismatch", SecretKeyPacket.USAGE_AEAD, sk.getS2KUsage());
        isEquals("S2K type mismatch", S2K.ARGON_2, sk.getS2K().getType());
        isEquals("Argon2 passes parameter mismatch", 3, sk.getS2K().getPasses());
        isEquals("Argon2 parallelism parameter mismatch", 4, sk.getS2K().getParallelism());
        isEquals("Argon2 memory exponent parameter mismatch", 16, sk.getS2K().getMemorySizeExponent());
        isEquals("Symmetric key encryption algorithm mismatch", encAlgorithm, sk.getKeyEncryptionAlgorithm());
        isEquals("AEAD algorithm mismatch", aeadAlgorithm, sk.getAEADKeyEncryptionAlgorithm());

        JcePBESecretKeyDecryptorBuilder jceDecBuilder = new JcePBESecretKeyDecryptorBuilder(digestProv).setProvider(prov);
        PGPPrivateKey dec = sk.extractPrivateKey(jceDecBuilder.build(decryptionPassphrase.toCharArray()));
        isEncodingEqual("Decrypted key encoding mismatch",
            keyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded(), dec.getPrivateKeyDataPacket().getEncoded());
    }

    private void reencryptKey() throws PGPException {
        reencryptKeyBc();
        reencryptKeyJca();
    }

    private void reencryptKeyJca()
    {

    }

    private void reencryptKeyBc()
            throws PGPException
    {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        Date creationTime = currentTimeRounded();
        String passphrase = "recycle";
        PGPKeyPair keyPair = new BcPGPKeyPair(PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.Ed25519, kp, creationTime);

        PBESecretKeyEncryptor cfbEncBuilder = new BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128)
                .build(passphrase.toCharArray());
        PGPDigestCalculatorProvider digestProv = new BcPGPDigestCalculatorProvider();

        // Encrypt key using CFB mode
        PGPSecretKey cfbEncKey = new PGPSecretKey(
                keyPair.getPrivateKey(),
                keyPair.getPublicKey(),
                digestProv.get(HashAlgorithmTags.SHA1),
                true,
                cfbEncBuilder);

        PBESecretKeyDecryptor cfbDecryptor = new BcPBESecretKeyDecryptorBuilder(digestProv)
                .build(passphrase.toCharArray());

        BcAEADSecretKeyEncryptorBuilder aeadEncBuilder = new BcAEADSecretKeyEncryptorBuilder(
                AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_128,
                S2K.Argon2Params.memoryConstrainedParameters());

        // Reencrypt key using AEAD
        PGPSecretKey aeadEncKey = PGPSecretKey.copyWithNewPassword(
                cfbEncKey,
                cfbDecryptor,
                aeadEncBuilder.build(
                        passphrase.toCharArray(),
                        cfbEncKey.getPublicKey().getPublicKeyPacket()));

        PBESecretKeyDecryptor aeadDecryptor = new BcPBESecretKeyDecryptorBuilder(digestProv)
                .build(passphrase.toCharArray());
        isNotNull(aeadEncKey.extractPrivateKey(aeadDecryptor));
    }

    public static void main(String[] args)
    {
        runTest(new AEADProtectedPGPSecretKeyTest());
    }
}