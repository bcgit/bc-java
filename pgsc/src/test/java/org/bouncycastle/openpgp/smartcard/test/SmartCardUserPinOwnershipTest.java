package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeySmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestProperties;
import org.bouncycastle.openpgp.smartcard.yubikey.operator.bc.BcYubikeyPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.yubikey.operator.jcajce.JceYubikeyPublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A card user PIN fetched from a {@link KeyPassphraseProvider} stays owned by the provider.
 * <p>
 * Both {@link KeyPassphraseProvider} implementations BC ships hand out the array the application
 * registered rather than a copy of it - {@code DefaultKeyPassphraseProvider} returns the
 * {@code char[]} held in its cache, and the anonymous provider inside {@code OpenPGPApi.editKey}
 * returns the caller's array verbatim - and every other consumer of
 * {@link KeyPassphraseProvider#getKeyPassword} borrows the array and leaves it alone. The two
 * YubiKey decryptor factories instead zeroized what they were handed, in a finally block after
 * every private-key operation, so the first decryption destroyed the application's PIN: the next
 * private-key operation presented an all-zero PIN to the card, which fails and costs a PIN retry.
 * They now clear a copy of their own, which is the rule {@code ECJPAKEParticipant} and
 * {@code JPAKEParticipant} state for a password they mean to clear.
 * <p>
 * The two factory cases need no token. The PIN handling brackets the card call - the PIN is fetched
 * before the session is opened and cleared in a finally block after it - so driving a factory with
 * no card exercises that handling in full, and only the card operation in between fails. Each case
 * asserts the PIN really was fetched, so it cannot pass by failing ahead of the fetch.
 * <p>
 * The simulator case then locks the borrowing convention on the backend that runs with no hardware
 * present: it unlocks the key it holds through the {@link KeyPassphraseProvider} it is handed, so a
 * PIN is presented on every private-key operation as it is on a real card.
 */
public class SmartCardUserPinOwnershipTest
        extends AbstractOpenPGPSmartCardTest
{
    public SmartCardUserPinOwnershipTest(OpenPGPSmartCardManager manager,
                                        SmartCardTestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "SmartCardUserPinOwnershipTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testPinSurvivesTwoConsecutiveDecryptions();
        testBcYubikeyFactoryBorrowsProvidersPin();
        testJceYubikeyFactoryBorrowsProvidersPin();
    }

    /**
     * Decrypt two messages in a row against one cached PIN array, the shape an application gets from
     * {@code OpenPGPMessageProcessor} for free: the PIN it registers is cached and handed to the
     * card backend on every private-key operation, so a backend that zeroized it would destroy the
     * application's PIN during the first message and present zeros during the second.
     */
    private void testPinSurvivesTwoConsecutiveDecryptions()
            throws PGPException, IOException, CardException
    {
        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        // -DM System.out.println
        System.out.println("Test user PIN ownership over two messages on " + card.getCardType() + " " + card.getVersion() + " (" + card.getBackend().getName() + ")");

        char[] expectedPin = properties.getUserPin();
        char[] applicationPin = properties.getUserPin();

        OpenPGPKey softwareKey = keyOnCard(card, expectedPin);
        OpenPGPKey externalKey = toExternalKey(softwareKey, null);

        isTrue("the stripped key must be marked external",
                externalKey.getSecretKey(externalKey.getEncryptionKeys().get(0))
                        .getPGPSecretKey().isExternalKey());

        RecordingPinProvider pinProvider = new RecordingPinProvider(applicationPin);

        for (int i = 1; i <= 2; i++)
        {
            byte[] plaintext = ("Message " + i + " to a card-held key.\n").getBytes(StandardCharsets.UTF_8);

            isTrue("message " + i + ": decrypted plaintext mismatch",
                    Arrays.areEqual(plaintext, decrypt(externalKey, pinProvider, encrypt(softwareKey, plaintext))));
            isTrue("message " + i + ": the application's PIN buffer must be intact after decryption",
                    Arrays.areEqual(expectedPin, applicationPin));
        }

        isEquals("the card must be presented the PIN once per message", 2, pinProvider.presentations.size());
        for (int i = 0; i != pinProvider.presentations.size(); i++)
        {
            isTrue("presentation " + (i + 1) + " must carry the real PIN rather than a cleared buffer",
                    Arrays.areEqual(expectedPin, pinProvider.presentations.get(i)));
        }
    }

    private void testBcYubikeyFactoryBorrowsProvidersPin()
            throws PGPException, InvalidCipherTextException
    {
        // -DM System.out.println
        System.out.println("Test BcYubikeyPublicKeyDataDecryptorFactory borrows the PIN it is given");

        char[] expectedPin = properties.getUserPin();
        char[] applicationPin = properties.getUserPin();
        RecordingPinProvider pinProvider = new RecordingPinProvider(applicationPin);

        BcYubikeyPublicKeyDataDecryptorFactory factory =
                new BcYubikeyPublicKeyDataDecryptorFactory(externalDecryptionKey(), null, pinProvider);

        try
        {
            factory.getExternalKeyCryptoCallback().decryptRSA(
                    PublicKeyAlgorithmTags.RSA_GENERAL, new byte[]{(byte)0xAA}, (AsymmetricKeyParameter)null);
            fail("a private-key operation with no card present must fail");
        }
        catch (RuntimeException e)
        {
            // expected: there is no card to open a session on
        }

        implTestPinBorrowed("BcYubikeyPublicKeyDataDecryptorFactory", pinProvider, expectedPin, applicationPin);
    }

    private void testJceYubikeyFactoryBorrowsProvidersPin()
            throws PGPException
    {
        // -DM System.out.println
        System.out.println("Test JceYubikeyPublicKeyDataDecryptorFactoryBuilder borrows the PIN it is given");

        char[] expectedPin = properties.getUserPin();
        char[] applicationPin = properties.getUserPin();
        RecordingPinProvider pinProvider = new RecordingPinProvider(applicationPin);

        PublicKeyDataDecryptorFactory factory =
                new JceYubikeyPublicKeyDataDecryptorFactoryBuilder(null, pinProvider).build(externalDecryptionKey());

        try
        {
            factory.recoverSessionData(PublicKeyAlgorithmTags.RSA_GENERAL,
                    new byte[][]{new byte[]{0, 8, (byte)0xAA}}, PublicKeyEncSessionPacket.VERSION_3);
            fail("a private-key operation with no card present must fail");
        }
        catch (RuntimeException e)
        {
            // expected: there is no card to open a session on
        }

        implTestPinBorrowed("JceYubikeyPublicKeyDataDecryptorFactoryBuilder", pinProvider, expectedPin, applicationPin);
    }

    private void implTestPinBorrowed(String label,
                                     RecordingPinProvider pinProvider,
                                     char[] expectedPin,
                                     char[] applicationPin)
    {
        isEquals(label + ": the PIN must be fetched from the provider exactly once",
                1, pinProvider.presentations.size());
        isTrue(label + ": the PIN handed to the card must be the registered one",
                Arrays.areEqual(expectedPin, pinProvider.presentations.get(0)));
        isTrue(label + ": the provider's PIN array must survive the operation",
                Arrays.areEqual(expectedPin, applicationPin));
    }

    /**
     * Generate a key protected with the card's user PIN, move its decryption key onto the card and
     * return the software copy the message is encrypted to.
     */
    private OpenPGPKey keyOnCard(OpenPGPSmartCard card, char[] userPin)
            throws PGPException, CardException
    {
        card.reset();

        // build(char[]) clears the array it is given, so it gets a copy
        OpenPGPKey softwareKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateX25519KeyPair)
                .build(Arrays.clone(userPin));

        OpenPGPKey.OpenPGPSecretKey decryptionKey =
                softwareKey.getSecretKey(softwareKey.getEncryptionKeys().get(0));
        card.uploadDecryptionKey(decryptionKey.unlock(Arrays.clone(userPin)), properties.getAdminPin());

        return softwareKey;
    }

    /**
     * An externally-backed decryption key, which is all either factory needs to be built. No card is
     * involved: the private key material is simply absent.
     */
    private OpenPGPKey.OpenPGPSecretKey externalDecryptionKey()
            throws PGPException
    {
        OpenPGPKey softwareKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateX25519KeyPair)
                .build();
        OpenPGPKey externalKey = toExternalKey(softwareKey, null);

        return externalKey.getSecretKey(externalKey.getEncryptionKeys().get(0));
    }

    private byte[] encrypt(OpenPGPKey recipient, byte[] plaintext)
            throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addEncryptionCertificate(recipient.toCertificate())
                .open(bOut);
        mOut.write(plaintext);
        mOut.close();

        return bOut.toByteArray();
    }

    private byte[] decrypt(OpenPGPKey externalKey, KeyPassphraseProvider pinProvider, byte[] message)
            throws PGPException, IOException
    {
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addDecryptionKey(externalKey)
                .setMissingOpenPGPKeyPassphraseProvider(pinProvider)
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .process(new ByteArrayInputStream(message));
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, plainOut);
        mIn.close();

        return plainOut.toByteArray();
    }

    /**
     * Hands out one cached array on every call, as
     * {@code KeyPassphraseProvider.DefaultKeyPassphraseProvider} does, and records a snapshot of what
     * each call returned so the PIN the card was presented can be checked afterwards.
     */
    private static class RecordingPinProvider
            implements KeyPassphraseProvider
    {
        final char[] pin;
        final List<char[]> presentations = new ArrayList<char[]>();

        RecordingPinProvider(char[] pin)
        {
            this.pin = pin;
        }

        public char[] getKeyPassword(OpenPGPKey.OpenPGPSecretKey key)
        {
            presentations.add(Arrays.clone(pin));
            return pin;
        }
    }

    public static void main(String[] args)
        throws CardException
    {
        SmartCardTestProperties p;
        OpenPGPSmartCardManager m;

        // BCYK
        try
        {
            p = new YubikeyTestProperties();
            m = YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager(p, YubikeySmartCardBackend.bcImpl());
            runTest(new SmartCardUserPinOwnershipTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SmartCardUserPinOwnershipTest on BC Yubikey.");
        }

        // JCYK
        try
        {
            p = new YubikeyTestProperties();
            m = YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager(p, YubikeySmartCardBackend.jceImpl());
            runTest(new SmartCardUserPinOwnershipTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SmartCardUserPinOwnershipTest on JCE Yubikey.");
        }


        SimulatorSmartCardBackend sim = new SimulatorSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, 1312));
        m = new OpenPGPSmartCardManager().addBackend(sim);

        runTest(new SmartCardUserPinOwnershipTest(m, new SmartCardTestProperties(1312)));
    }
}
