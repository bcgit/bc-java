package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;

public class PGPv6KeyTest
    extends SimpleTest
{

    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-09.html#name-sample-v6-certificate-trans
    private static final String ARMORED_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n" +
        "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n" +
        "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n" +
        "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n" +
        "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n" +
        "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n" +
        "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n" +
        "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n" +
        "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n" +
        "-----END PGP PUBLIC KEY BLOCK-----";

    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-09.html#name-sample-v6-secret-key-transf
    private static final String ARMORED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
        "\n" +
        "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
        "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
        "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
        "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
        "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
        "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
        "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
        "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
        "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
        "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
        "k0mXubZvyl4GBg==\n" +
        "-----END PGP PRIVATE KEY BLOCK-----";

    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-09.html#name-sample-locked-v6-secret-key
    private static final String ARMORED_ENCRYPTED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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

    private static final byte[] PRIMARY_FINGERPRINT = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
    private static final byte[] SUBKEY_FINGERPRINT = Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885");

    private static final String PASSPHRASE = "correct horse battery staple";

    private static final KeyFingerPrintCalculator bcFpCalc = new BcKeyFingerprintCalculator();
    private static final KeyFingerPrintCalculator jcaFpCalc = new JcaKeyFingerprintCalculator();

    @Override
    public String getName()
    {
        return getClass().getName();
    }

    @Override
    public void performTest()
        throws Exception
    {
        lockAndUnlockKeyWithArgon2();
        // Parse certificate
        testCertificateParsing(bcFpCalc);
        testCertificateParsing(jcaFpCalc);

        // Parse unencrypted key
        testKeyParsing(bcFpCalc);
        testKeyParsing(jcaFpCalc);

        // Parse encrypted key
        testEncryptedKeyParsing(bcFpCalc);
        testEncryptedKeyParsing(jcaFpCalc);
    }

    private void testCertificateParsing(KeyFingerPrintCalculator fingerPrintCalculator) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_CERT.getBytes());
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        BCPGInputStream bcIn = new BCPGInputStream(armorIn);

        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(bcIn, fingerPrintCalculator);

        Iterator<PGPPublicKey> pIt = publicKeys.getPublicKeys();
        PGPPublicKey key = pIt.next();
        isTrue(Arrays.areEqual(PRIMARY_FINGERPRINT, key.getFingerprint()));
        key = pIt.next();
        isTrue(Arrays.areEqual(SUBKEY_FINGERPRINT, key.getFingerprint()));
    }

    private void testKeyParsing(KeyFingerPrintCalculator fingerPrintCalculator) throws IOException, PGPException {
        ByteArrayInputStream bIn;
        ArmoredInputStream armorIn;
        BCPGInputStream bcIn;

        bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes());
        armorIn = new ArmoredInputStream(bIn);
        bcIn = new BCPGInputStream(armorIn);

        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(bcIn, fingerPrintCalculator);

        Iterator<PGPSecretKey> sIt = secretKeys.getSecretKeys();
        PGPSecretKey sKey = sIt.next();
        isTrue(Arrays.areEqual(PRIMARY_FINGERPRINT, sKey.getFingerprint()));

        sKey = sIt.next();
        isTrue(Arrays.areEqual(SUBKEY_FINGERPRINT, sKey.getFingerprint()));
    }

    private void testEncryptedKeyParsing(KeyFingerPrintCalculator fingerPrintCalculator) throws IOException, PGPException {
        ByteArrayInputStream bIn;
        ArmoredInputStream armorIn;
        BCPGInputStream bcIn;

        bIn = new ByteArrayInputStream(ARMORED_ENCRYPTED_KEY.getBytes());
        armorIn = new ArmoredInputStream(bIn);
        bcIn = new BCPGInputStream(armorIn);

        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(bcIn, fingerPrintCalculator);

        Iterator<PGPSecretKey> sIt = secretKeys.getSecretKeys();
        PGPSecretKey sKey = sIt.next();
        isTrue(Arrays.areEqual(PRIMARY_FINGERPRINT, sKey.getFingerprint()));
        isEquals(SecretKeyPacket.USAGE_AEAD, sKey.getS2KUsage());
        isEquals(SymmetricKeyAlgorithmTags.AES_256, sKey.getKeyEncryptionAlgorithm());
        isEquals(AEADAlgorithmTags.OCB, sKey.getAEADKeyEncryptionAlgorithm());
        PGPPrivateKey pKey = bcUnlock(sKey, PASSPHRASE);
        PGPPrivateKey pKey2 = jceUnlock(sKey, PASSPHRASE);
        isTrue(Arrays.areEqual(pKey.getPrivateKeyDataPacket().getEncoded(), pKey2.getPrivateKeyDataPacket().getEncoded()));

        sKey = sIt.next();
        isTrue(Arrays.areEqual(SUBKEY_FINGERPRINT, sKey.getFingerprint()));
        isEquals(SecretKeyPacket.USAGE_AEAD, sKey.getS2KUsage());
        isEquals(SymmetricKeyAlgorithmTags.AES_256, sKey.getKeyEncryptionAlgorithm());
        isEquals(AEADAlgorithmTags.OCB, sKey.getAEADKeyEncryptionAlgorithm());
        pKey = bcUnlock(sKey, PASSPHRASE);
        pKey2 = jceUnlock(sKey, PASSPHRASE);
        isTrue(Arrays.areEqual(pKey.getPrivateKeyDataPacket().getEncoded(), pKey2.getPrivateKeyDataPacket().getEncoded()));
    }

    private void lockAndUnlockKeyWithArgon2() throws IOException, PGPException {
        KeyFingerPrintCalculator fingerprintCalculator = new BcKeyFingerprintCalculator();
        PGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
        String passphrase = "sw0rdf1sh";

        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes());
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        BCPGInputStream bcIn = new BCPGInputStream(armorIn);
        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(bcIn, fingerprintCalculator);
        PGPPrivateKey unlockedPrimaryKey = unlockWith(null, secretKeys.getSecretKey());

        PGPSecretKeyRing lockedKeyRing = PGPSecretKeyRing.copyWithNewPassword(secretKeys, null,
                new BcPBESecretKeyEncryptorBuilder(
                        SymmetricKeyAlgorithmTags.AES_256,
                        AEADAlgorithmTags.OCB,
                        S2K.Argon2Params.memoryConstrainedParameters()
                ).build(passphrase.toCharArray()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(bOut);
        lockedKeyRing.encode(armorOut);
        armorOut.close();

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        armorIn = new ArmoredInputStream(bIn);
        BCPGInputStream bcpgInputStream = new BCPGInputStream(armorIn);
        PGPSecretKeyRing parsed = new PGPSecretKeyRing(bcpgInputStream, fingerprintCalculator);

        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider)
                .build(passphrase.toCharArray());
        PGPPrivateKey decryptedPrimaryKey = unlockWith(decryptor, parsed.getSecretKey());

        isTrue(Arrays.areEqual(
                unlockedPrimaryKey.getPrivateKeyDataPacket().getEncoded(),
                decryptedPrimaryKey.getPrivateKeyDataPacket().getEncoded()));
    }

    private PGPPrivateKey unlockWith(PBESecretKeyDecryptor decryptor, PGPSecretKey secretKey)
            throws PGPException {
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(decryptor);
        return privateKey;
    }

    private PGPPrivateKey bcUnlock(PGPSecretKey secretKey, String passphrase) throws PGPException {
        BcPGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();
        PBESecretKeyDecryptor decryptor = passphrase == null ? null : new BcPBESecretKeyDecryptorBuilder(calculatorProvider)
                .build(passphrase.toCharArray());
        return unlockWith(decryptor, secretKey);
    }

    private PGPPrivateKey jceUnlock(PGPSecretKey secretKey, String passphrase) throws PGPException {
        PGPDigestCalculatorProvider digestCalculatorProvider = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(new BouncyCastleProvider())
                .build();
        PBESecretKeyDecryptor decryptor = passphrase == null ? null : new JcePBESecretKeyDecryptorBuilder(digestCalculatorProvider)
                .setProvider(new BouncyCastleProvider())
                .build(passphrase.toCharArray());
        return unlockWith(decryptor, secretKey);
    }

    public static void main(String[] args)
    {
        runTest(new PGPv6KeyTest());
    }
}