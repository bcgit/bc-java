package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PGPv6KeyTest
    extends AbstractPgpKeyPairTest
{

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
    // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-locked-version-6-sec
    private static final String ARMORED_PROTECTED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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
    private static final Date CREATION_TIME = parseUTCTimestamp("2022-11-30 16:08:03 UTC");

    private static final byte[] PRIMARY_FINGERPRINT = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
    private static final byte[] SUBKEY_FINGERPRINT = Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885");
    private static final long PRIMARY_KEYID = -3812177997909612905L;
    private static final long SUBKEY_KEYID = 1353401087992750856L;

    private static final KeyFingerPrintCalculator fingerPrintCalculator = new BcKeyFingerprintCalculator();

    @Override
    public String getName()
    {
        return getClass().getName();
    }

    @Override
    public void performTest()
        throws Exception
    {
        parseUnprotectedCertTest();
        parseUnprotectedKeyTest();
        testJcaFingerprintCalculation();
        parseProtectedKeyTest();

        generatePlainV6RSAKey_bc();
    }

    private void generatePlainV6RSAKey_bc()
            throws PGPException, IOException
    {
        String uid = "Alice <alice@example.com>";
        Date creationTime = currentTimeRounded();
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        rsaGen.init(new RSAKeyGenerationParameters(
                BigInteger.valueOf(0x10001),
                CryptoServicesRegistrar.getSecureRandom(),
                4096,
                100));
        AsymmetricCipherKeyPair rsaKp = rsaGen.generateKeyPair();

        PGPKeyPair pgpKp = new BcPGPKeyPair(
                PublicKeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.RSA_GENERAL,
                rsaKp,
                creationTime);
        PGPPublicKey primaryKey = pgpKp.getPublicKey();

        PGPSignatureGenerator dkSigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(primaryKey.getAlgorithm(), HashAlgorithmTags.SHA3_512),
                primaryKey);
        dkSigGen.init(PGPSignature.DIRECT_KEY, pgpKp.getPrivateKey());
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setIssuerFingerprint(true, primaryKey);
        hashed.setSignatureCreationTime(true, creationTime);
        hashed.setFeature(false, (byte) (Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));
        hashed.setPreferredAEADCiphersuites(false, new PreferredAEADCiphersuites.Combination[]{
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB),
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_192, AEADAlgorithmTags.OCB),
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB)
        });
        hashed.setPreferredHashAlgorithms(false,
                new int[]
                {
                        HashAlgorithmTags.SHA3_512, HashAlgorithmTags.SHA3_256,
                        HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256
                }
        );
        hashed.setPreferredSymmetricAlgorithms(false,
                new int[]
                {
                        SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
                }
        );

        dkSigGen.setHashedSubpackets(hashed.generate());
        PGPSignature dkSig = dkSigGen.generateCertification(primaryKey);

        PGPSignatureGenerator uidSigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(primaryKey.getAlgorithm(), HashAlgorithmTags.SHA3_512),
                primaryKey);
        uidSigGen.init(PGPSignature.POSITIVE_CERTIFICATION, pgpKp.getPrivateKey());

        hashed = new PGPSignatureSubpacketGenerator();
        hashed.setIssuerFingerprint(true, primaryKey);
        hashed.setSignatureCreationTime(true, creationTime);

        PGPSignature uidSig = uidSigGen.generateCertification(uid, primaryKey);

        primaryKey = PGPPublicKey.addCertification(primaryKey, dkSig);
        primaryKey = PGPPublicKey.addCertification(primaryKey, uid, uidSig);

        PGPSecretKey primarySecKey = new PGPSecretKey(
                pgpKp.getPrivateKey(),
                primaryKey,
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                true,
                null);

        PGPPublicKeyRing certificate = new PGPPublicKeyRing(Collections.singletonList(primaryKey));
        PGPSecretKeyRing secretKey = new PGPSecretKeyRing(Collections.singletonList(primarySecKey));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        certificate.encode(pOut);
        pOut.close();
        aOut.close();
        System.out.println(bOut);

        bOut = new ByteArrayOutputStream();
        aOut = new ArmoredOutputStream(bOut);
        pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        secretKey.encode(pOut);
        pOut.close();
        aOut.close();
        System.out.println(bOut);
    }

    private void parseUnprotectedCertTest()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_CERT.getBytes());
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        BCPGInputStream bcIn = new BCPGInputStream(armorIn);

        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(bcIn, fingerPrintCalculator);

        Iterator<PGPPublicKey> pIt = publicKeys.getPublicKeys();
        PGPPublicKey key = (PGPPublicKey)pIt.next();
        isTrue("Primary key fingerprint mismatch", key.hasFingerprint(PRIMARY_FINGERPRINT));
        isEquals("Primary key-ID mismatch", PRIMARY_KEYID, key.getKeyID());
        isEquals("Primary key version mismatch", PublicKeyPacket.VERSION_6, key.getVersion());
        isEquals("Primary key creation time mismatch", CREATION_TIME, key.getCreationTime());
        isEquals("Primary key bit-strength mismatch", 256, key.getBitStrength());

        key = (PGPPublicKey)pIt.next();
        isTrue("Subkey fingerprint mismatch", key.hasFingerprint(SUBKEY_FINGERPRINT));
        isEquals("Subkey key-ID mismatch", SUBKEY_KEYID, key.getKeyID());
        isEquals("Subkey version mismatch", PublicKeyPacket.VERSION_6, key.getVersion());
        isEquals("Subkey creation time mismatch", CREATION_TIME, key.getCreationTime());
        isEquals("Subkey bit-strength mismatch", 256, key.getBitStrength());

        isFalse("Unexpected key object in key ring", pIt.hasNext());
    }

    private void parseUnprotectedKeyTest()
            throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes());
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        BCPGInputStream bcIn = new BCPGInputStream(armorIn);

        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(bcIn, fingerPrintCalculator);

        Iterator<PGPSecretKey> sIt = secretKeys.getSecretKeys();
        PGPSecretKey key = (PGPSecretKey)sIt.next();
        isEncodingEqual("Primary key fingerprint mismatch", PRIMARY_FINGERPRINT, key.getFingerprint());
        isEquals("Primary key-ID mismatch", PRIMARY_KEYID, key.getKeyID());
        isEquals("Primary key version mismatch", PublicKeyPacket.VERSION_6, key.getPublicKey().getVersion());
        isEquals("Primary key creation time mismatch", CREATION_TIME, key.getPublicKey().getCreationTime());
        isEquals("Primary key S2K-usage mismatch", SecretKeyPacket.USAGE_NONE, key.getS2KUsage());
        isNull("Primary key S2K MUST be null", key.getS2K());

        key = (PGPSecretKey)sIt.next();
        isEncodingEqual("Subkey fingerprint mismatch", SUBKEY_FINGERPRINT, key.getFingerprint());
        isEquals("Subkey key-ID mismatch", SUBKEY_KEYID, key.getKeyID());
        isEquals("Subkey version mismatch", PublicKeyPacket.VERSION_6, key.getPublicKey().getVersion());
        isEquals("Subkey creation time mismatch", CREATION_TIME, key.getPublicKey().getCreationTime());
        isEquals("Subkey S2K-usage mismatch", SecretKeyPacket.USAGE_NONE, key.getS2KUsage());
        isNull("Subkey S2K MUST be null", key.getS2K());

        isFalse("Unexpected key object in key ring", sIt.hasNext());
    }

    private void testJcaFingerprintCalculation()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_CERT.getBytes());
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        BCPGInputStream bcIn = new BCPGInputStream(armorIn);

        JcaKeyFingerprintCalculator fpCalc =  new JcaKeyFingerprintCalculator();
        fpCalc.setProvider(new BouncyCastleProvider());
        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(bcIn, fpCalc);

        Iterator<PGPPublicKey> pIt = publicKeys.getPublicKeys();
        PGPPublicKey key = (PGPPublicKey)pIt.next();
        isTrue("Primary key fingerprint mismatch", key.hasFingerprint(PRIMARY_FINGERPRINT));
        isEquals("Primary key-ID mismatch", PRIMARY_KEYID, key.getKeyID());
        key = (PGPPublicKey)pIt.next();
        isTrue("Subkey fingerprint mismatch", key.hasFingerprint(SUBKEY_FINGERPRINT));
        isEquals("Subkey key-ID mismatch", SUBKEY_KEYID, key.getKeyID());
    }

    private void parseProtectedKeyTest()
            throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_PROTECTED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);

        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(pIn, fingerPrintCalculator);
        Iterator<PGPSecretKey> sIt = secretKeys.getSecretKeys();

        PGPSecretKey key = (PGPSecretKey)sIt.next();
        isEncodingEqual("Primary key fingerprint mismatch", PRIMARY_FINGERPRINT, key.getFingerprint());
        isEquals("Primary key ID mismatch", PRIMARY_KEYID, key.getKeyID());
        isEquals("Primary key algorithm mismatch",
                PublicKeyAlgorithmTags.Ed25519, key.getPublicKey().getAlgorithm());
        isEquals("Primary key version mismatch", PublicKeyPacket.VERSION_6, key.getPublicKey().getVersion());
        isEquals("Primary key creation time mismatch", CREATION_TIME, key.getPublicKey().getCreationTime());
        isEquals("Primary key S2K-Usage mismatch", SecretKeyPacket.USAGE_AEAD, key.getS2KUsage());
        isEquals("Primary key AEAD algorithm mismatch",
                AEADAlgorithmTags.OCB, key.getAEADKeyEncryptionAlgorithm());
        isEquals("Primary key protection algorithm mismatch",
                SymmetricKeyAlgorithmTags.AES_256, key.getKeyEncryptionAlgorithm());
        isEncodingEqual("Primary key S2K salt mismatch",
                Hex.decode("5d6fd71c9e096d1eb6917b6e6e1eecae"), key.getS2K().getIV());

        key = (PGPSecretKey)sIt.next();
        isEncodingEqual("Subkey fingerprint mismatch", SUBKEY_FINGERPRINT, key.getFingerprint());
        isEquals("Subkey ID mismatch", SUBKEY_KEYID, key.getKeyID());
        isEquals("Subkey algorithm mismatch",
                PublicKeyAlgorithmTags.X25519, key.getPublicKey().getAlgorithm());
        isEquals("Subkey version mismatch", PublicKeyPacket.VERSION_6, key.getPublicKey().getVersion());
        isEquals("Subkey creation time mismatch", CREATION_TIME, key.getPublicKey().getCreationTime());
        isEquals("Subkey S2K-Usage mismatch", SecretKeyPacket.USAGE_AEAD, key.getS2KUsage());
        isEquals("Subkey AEAD algorithm mismatch",
                AEADAlgorithmTags.OCB, key.getAEADKeyEncryptionAlgorithm());
        isEquals("Subkey protection algorithm mismatch",
                SymmetricKeyAlgorithmTags.AES_256, key.getKeyEncryptionAlgorithm());
        isEncodingEqual("Subkey S2K salt mismatch",
                Hex.decode("0e61846829da869abe0ea61545dc14cc"), key.getS2K().getIV());

        isFalse("Unexpected key in key ring", sIt.hasNext());
    }

    public static void main(String[] args)
    {
        runTest(new PGPv6KeyTest());
    }
}