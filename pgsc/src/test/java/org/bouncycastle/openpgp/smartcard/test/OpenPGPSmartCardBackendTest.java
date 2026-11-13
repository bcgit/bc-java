package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.util.Arrays;

import java.security.PublicKey;

public class OpenPGPSmartCardBackendTest
        extends AbstractOpenPGPSmartCardTest
{
    public OpenPGPSmartCardBackendTest(OpenPGPSmartCardManager manager, TestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "OpenPGPSmartCardBackendTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        for (OpenPGPSmartCardBackend<?> backend : manager.getBackends())
        {
            performTestOn(backend);
        }
    }

    private void performTestOn(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        testLegacyX25519KeyConversion(backend);
        testLegacyEd25519KeyConversion(backend);

        testX25519KeyConversion(backend);
        testEd25519KeyConversion(backend);

        testX448KeyConversion(backend);
        testEd448KeyConversion(backend);

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

    private void testLegacyX25519KeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of legacy X25519 key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyX25519KeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testLegacyEd25519KeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of legacy Ed25519 key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testX25519KeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of X25519 key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateX25519KeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testEd25519KeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Ed25519 key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd25519KeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testX448KeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of X448 key");
        OpenPGPKey k = api.generateKey(6)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd448KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateX448KeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testEd448KeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Ed448 key");
        OpenPGPKey k = api.generateKey(6)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd448KeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testRSA2048KeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of 2048-bit RSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(2048))
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testRSA3072KeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of 3072-bit RSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(3072))
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testRSA4096KeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of 4096-bit RSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) generator -> generator.generateRsaKeyPair(4096))
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testNistP256ECDSAKeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P256 ECDSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testNistP384ECDSAKeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P384 ECDSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testNistP521ECDSAKeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P521 ECDSA key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .build();
        testConversionOfKey(backend, k.getPrimaryKey().getPGPPublicKey());
    }

    private void testNistP256ECDHKeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P256 ECDH key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDHKeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testNistP384ECDHKeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P384 ECDH key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDHKeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testNistP521ECDHKeyConversion(OpenPGPSmartCardBackend<?> backend)
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test conversion of Nist-P521 ECDH key");
        OpenPGPKey k = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDHKeyPair)
                .build();
        testConversionOfKey(backend, k.getEncryptionKeys().get(0).getPGPPublicKey());
    }

    private void testConversionOfKey(OpenPGPSmartCardBackend<?> backend, PGPPublicKey originalPGPPublicKey)
            throws PGPException
    {
        BCPGKey originalBCPGKey = originalPGPPublicKey.getPublicKeyPacket().getKey();
        PublicKey convertedPublicKeyValues = backend.convertPublicKey(originalPGPPublicKey);
        PGPPublicKey convertedPGPPublicKey = backend.convertPublicKey(convertedPublicKeyValues, originalPGPPublicKey.getFingerprint(), originalPGPPublicKey.getCreationTime());
        BCPGKey convertedBCPGKey = convertedPGPPublicKey.getPublicKeyPacket().getKey();

        isTrue(Arrays.areEqual(originalBCPGKey.getEncoded(), convertedBCPGKey.getEncoded()));
    }
}
