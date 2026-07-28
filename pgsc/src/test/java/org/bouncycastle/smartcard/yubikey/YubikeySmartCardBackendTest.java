package org.bouncycastle.smartcard.yubikey;

import com.yubico.yubikit.core.keys.PublicKeyValues;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Test conversion of Bouncy Castles {@link BCPGKey} public keys to and from YubiKit's {@link PublicKeyValues}.
 * <p>
 * This test does not require a Yubikey device to be present, as the conversion is done in software.
 */
public class YubikeySmartCardBackendTest
        extends SimpleTest
{
    private final OpenPGPApi api = new BcOpenPGPApi();

    @Override
    public String getName()
    {
        return "YubikeySmartCardBackendTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        YubikeySmartCardBackend backend = YubikeySmartCardBackend.createInstance();

        testLegacyX25519KeyConversion(backend);
        testLegacyEd25519KeyConversion(backend);

        testX25519KeyConversion(backend);
        testEd25519KeyConversion(backend);

        testRSA2048KeyConversion(backend);
        testRSA3072KeyConversion(backend);
        testRSA4096KeyConversion(backend);

        testNistP256ECDSAKeyConversion(backend);
        testNistP384ECDSAKeyConversion(backend);
        testNistP521ECDSAKeyConversion(backend);

        testNistP256ECDHKeyConversion(backend);
        testNistP384ECDHKeyConversion(backend);
        testNistP521ECDHKeyConversion(backend);
    }

    private void testLegacyX25519KeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of legacy Ed25519 key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyX25519KeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testLegacyEd25519KeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of legacy Ed25519 key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testX25519KeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of X25519 key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateX25519KeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testEd25519KeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Ed25519 key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd25519KeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testRSA2048KeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of 2048-bit RSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(2048))
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testRSA3072KeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of 3072-bit RSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(3072))
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testRSA4096KeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of 4096-bit RSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(4096))
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testNistP256ECDSAKeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P256 ECDSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testNistP384ECDSAKeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P384 ECDSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testNistP521ECDSAKeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P521 ECDSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testNistP256ECDHKeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P256 ECDH key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDHKeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testNistP384ECDHKeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P384 ECDH key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDHKeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testNistP521ECDHKeyConversion(YubikeySmartCardBackend backend)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P521 ECDH key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDHKeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testConversionOfKey(YubikeySmartCardBackend backend,
                                     PGPPublicKey originalPGPPublicKey)
            throws PGPException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        BCPGKey originalBCPGKey = originalPGPPublicKey.getPublicKeyPacket().getKey();
        PublicKeyValues convertedPublicKeyValues = backend.convertPublicKey(originalPGPPublicKey);
        PGPPublicKey convertedPGPPublicKey = backend.convertPublicKey(convertedPublicKeyValues, originalPGPPublicKey.getFingerprint(), originalPGPPublicKey.getCreationTime());
        BCPGKey convertedBCPGKey = convertedPGPPublicKey.getPublicKeyPacket().getKey();

        isTrue(Arrays.areEqual(originalBCPGKey.getEncoded(), convertedBCPGKey.getEncoded()));
    }

    public static void main(String[] args)
    {
        runTest(new YubikeySmartCardBackendTest());
    }
}
