package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestProperties;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class SmartCardMessageDecryptionTest
        extends AbstractOpenPGPSmartCardTest
{
    public SmartCardMessageDecryptionTest(OpenPGPSmartCardManager manager,
                                          SmartCardTestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "SmartCardMessageDecryptionTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testX25519Key();
        testLegacyX25519Key();

        testRSA2048Key();
        testRSA3072Key();
        testRSA4096Key();

        testNISTP256ECDHKey();
        testNISTP384ECDHKey();
        testNISTP521ECDHKey();
    }

    private void testRSA2048Key()
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with 2048-bit RSA key");
        OpenPGPKey rsaKey = api.generateKey(4)
                .compositeRSAKey(2048, "Alice <alice@example.org>")
                .build();
        testDecryptionWithExternalKey(rsaKey);
    }

    private void testRSA3072Key()
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with 3072-bit RSA key");
        OpenPGPKey rsaKey = api.generateKey(4)
                .compositeRSAKey(3072, "Alice <alice@example.org>")
                .build();
        testDecryptionWithExternalKey(rsaKey);
    }

    private void testRSA4096Key()
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with 4096-bit RSA key");
        OpenPGPKey rsaKey = api.generateKey(4)
                .compositeRSAKey(4096, "Alice <alice@example.org>")
                .build();
        testDecryptionWithExternalKey(rsaKey);
    }

    private void testNISTP256ECDHKey()
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with NIST-P256 ECDH key");
        OpenPGPKey ecdhKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDHKeyPair)
                .build();
        testDecryptionWithExternalKey(ecdhKey);
    }

    private void testNISTP384ECDHKey()
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with NIST-P384 ECDH key");
        OpenPGPKey ecdhKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDHKeyPair)
                .build();
        testDecryptionWithExternalKey(ecdhKey);
    }

    private void testNISTP521ECDHKey()
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with NIST-P521 ECDH key");
        OpenPGPKey ecdhKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDHKeyPair)
                .build();
        testDecryptionWithExternalKey(ecdhKey);
    }

    private void testLegacyX25519Key()
            throws PGPException, IOException, CardException
    {
        // -DM System.out.println
        System.out.println("Test decryption with legacy X25519 key");
        OpenPGPKey x25519Key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyX25519KeyPair)
                .build();
        testDecryptionWithExternalKey(x25519Key);
    }

    private void testX25519Key()
            throws PGPException, IOException, CardException
    {
        // -DM System.out.println
        System.out.println("Test decryption with X25519 key");
        OpenPGPKey x25519Key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd25519KeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateX25519KeyPair)
                .build();
        testDecryptionWithExternalKey(x25519Key);
    }

    private void testDecryptionWithExternalKey(OpenPGPKey softwareKey)
            throws PGPException, IOException, CardException
    {
        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        // -DM System.out.println
        System.out.println("Test on " + card.getCardType() + " " + card.getVersion());
        card.reset();
        // -DM System.out.println
        System.out.println(softwareKey.toAsciiArmoredString());

        char[] adminPin = properties.getAdminPin();

        OpenPGPKey externalKey = toExternalKey(softwareKey, null);

        // Upload keys to card
        OpenPGPKey.OpenPGPSecretKey decryptionKey = softwareKey.getSecretKey(softwareKey.getEncryptionKeys().get(0));
        card.uploadDecryptionKey(decryptionKey.unlock(), adminPin);

        // Generate encrypted message
        byte[] plaintext = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addEncryptionCertificate(softwareKey.toCertificate())
                .open(bOut);
        mOut.write(plaintext);
        mOut.close();

        // -DM System.out.println
        System.out.println(bOut);

        // Decrypt message using card
        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addDecryptionKey(externalKey, properties.getUserPin())
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .process(bIn);
        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, bOut);
        mIn.close();

        isTrue("Decrypted plaintext mismatch",
                Arrays.areEqual(plaintext, bOut.toByteArray()));
    }

    public static void main(String[] args)
            throws CardException
    {
        SmartCardTestProperties p;
        OpenPGPSmartCardManager m;
        try
        {
            p = new YubikeyTestProperties();
            m = YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager(p);
            runTest(new SmartCardMessageDecryptionTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SmartCardMessageDecryptionTest on Yubikey.");
        }

        SimulatorSmartCardBackend sim = new SimulatorSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, 1312));
        m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        p = new SmartCardTestProperties(1312);
        runTest(new SmartCardMessageDecryptionTest(m, p));
    }
}
