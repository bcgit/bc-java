package org.bouncycastle.openpgp.smartcard.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * A card user PIN fetched from a {@link KeyPassphraseProvider} stays owned by the provider.
 * <p>
 * Both {@link KeyPassphraseProvider} implementations BC ships hand out the array the application
 * registered rather than a copy of it - {@code DefaultKeyPassphraseProvider} returns the
 * {@code char[]} held in its cache, and the anonymous provider inside {@code OpenPGPApi.editKey}
 * returns the caller's array verbatim - and every other consumer of
 * {@link KeyPassphraseProvider#getKeyPassword} borrows the array and leaves it alone.
 * {@link OpenPGPSmartCard#requireUserPin} therefore returns a copy: every card operation clears
 * the PIN it was given in a finally block, and clearing the provider's array would destroy the
 * application's PIN, so that the next private-key operation would present an all-zero PIN to the
 * card and spend a PIN retry.
 */
public class SmartCardUserPinOwnershipTest
    extends AbstractOpenPGPSmartCardTest
{
    public SmartCardUserPinOwnershipTest(OpenPGPSmartCardManager manager,
                                        TestProperties properties)
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
        testRequireUserPinReturnsACopy();
        testPinSurvivesTwoConsecutiveDecryptions();
    }

    /**
     * The fetch itself, driven directly: no card operation is needed to establish that what comes
     * back is not the provider's own array, which is what the finally blocks around every card
     * operation rely on.
     */
    private void testRequireUserPinReturnsACopy()
        throws PGPException, CardException
    {
        // -DM System.out.println
        System.out.println("Test OpenPGPSmartCard.requireUserPin() returns a copy of the provider's PIN");

        OpenPGPKey key = api.generateKey()
            .withPrimaryKey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateEd25519KeyPair)
            .addEncryptionSubkey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateX25519KeyPair)
            .build();
        OpenPGPKey.OpenPGPSecretKey secretKey = key.getSecretKey(key.getEncryptionKeys().get(0));

        char[] providerPin = properties.getUserPin();
        char[] expectedPin = properties.getUserPin();
        RecordingPinProvider pinProvider = new RecordingPinProvider(providerPin);

        SimulatorOpenPGPSmartCardBackend backend = new SimulatorOpenPGPSmartCardBackend();
        PinProbeSmartCard card = new PinProbeSmartCard(backend, 1313);

        char[] fetched = card.fetchUserPin(pinProvider, secretKey);

        isEquals("the provider must have been asked for the PIN", 1, pinProvider.fetches);
        isTrue("the PIN fetched must carry the provider's value", Arrays.areEqual(expectedPin, fetched));
        isTrue("the PIN fetched must not be the provider's own array", fetched != providerPin);

        // this is what every card operation does with it once the card has verified it
        Arrays.fill(fetched, (char)0);

        isTrue("clearing the fetched PIN must leave the provider's array intact",
            Arrays.areEqual(expectedPin, providerPin));
    }

    /**
     * Two messages in a row against one PIN array, the shape an application gets from
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

        card.reset();

        OpenPGPKey softwareKey = api.generateKey()
            .withPrimaryKey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateEd25519KeyPair)
            .addEncryptionSubkey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateX25519KeyPair)
            .build();
        OpenPGPKey externalKey = cardUtils.toExternalKey(softwareKey);

        card.uploadDecryptionKey(softwareKey.getSecretKey(softwareKey.getEncryptionKeys().get(0)).unlock(),
            k -> properties.getAdminPin());

        char[] expectedPin = properties.getUserPin();
        char[] applicationPin = properties.getUserPin();

        for (int i = 1; i <= 2; i++)
        {
            byte[] plaintext = ("Message " + i + " to a card-held key.\n").getBytes(StandardCharsets.UTF_8);

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addEncryptionCertificate(softwareKey.toCertificate())
                .open(bOut);
            mOut.write(plaintext);
            mOut.close();

            OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addDecryptionKey(externalKey, applicationPin)
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .process(new ByteArrayInputStream(bOut.toByteArray()));
            ByteArrayOutputStream recovered = new ByteArrayOutputStream();
            Streams.pipeAll(mIn, recovered);
            mIn.close();

            isTrue("message " + i + ": decrypted plaintext mismatch",
                Arrays.areEqual(plaintext, recovered.toByteArray()));
            isTrue("message " + i + ": the application's PIN buffer must be intact after decryption",
                Arrays.areEqual(expectedPin, applicationPin));
        }
    }

    /**
     * Hands out the array it was constructed with, as the providers BC ships do, and counts the
     * fetches so a test cannot pass by never reaching one.
     */
    private static class RecordingPinProvider
        implements KeyPassphraseProvider
    {
        private final char[] pin;
        int fetches = 0;

        RecordingPinProvider(char[] pin)
        {
            this.pin = pin;
        }

        public char[] getKeyPassword(OpenPGPKey.OpenPGPSecretKey key)
        {
            fetches++;
            return pin;
        }
    }

    /**
     * Exposes the protected fetch so it can be driven without a card operation.
     */
    private static class PinProbeSmartCard
        extends SimulatorOpenPGPSmartCard
    {
        PinProbeSmartCard(SimulatorOpenPGPSmartCardBackend backend, int serialNumber)
        {
            super(backend, serialNumber);
        }

        char[] fetchUserPin(KeyPassphraseProvider userPinProvider, OpenPGPKey.OpenPGPSecretKey key)
            throws KeyPassphraseException
        {
            return requireUserPin(userPinProvider, key);
        }
    }
}
