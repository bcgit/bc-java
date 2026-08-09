package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorSmartCardBackend;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

/**
 * Decrypt a message addressed to an <em>anonymous</em> (wildcard) recipient with an externally-backed key.
 * <p>
 * RFC 9580 sec. 5.1 lets a v3 PKESK carry an all-zero key ID, and a v6 PKESK a zero-length key
 * fingerprint, to hide who a message is for. {@code OpenPGPMessageProcessor} handles those separately
 * from key-identified PKESKs: it cannot look a key up, so it tries every decryption key it holds in turn.
 * That loop used to unlock each candidate secret key directly - which for a key marked
 * {@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_EXTERNAL} yields no private key material at all, so
 * it threw a {@link NullPointerException} (not a {@link PGPException}, hence straight out of the
 * decrypt call) instead of consulting the registered
 * {@link org.bouncycastle.openpgp.api.PublicKeyDataDecryptorFactoryProvider}s. A card-held key was
 * therefore unusable for exactly the messages the external-secrets draft's best-effort lookup describes.
 * <p>
 * The test asserts the PKESK really is a wildcard one before decrypting, so it cannot quietly stop
 * covering the anonymous path if the generator's default recipient handling ever changes.
 */
public class AnonymousRecipientSmartCardDecryptionTest
        extends AbstractOpenPGPSmartCardTest
{
    public AnonymousRecipientSmartCardDecryptionTest(OpenPGPSmartCardManager manager,
                                                     SmartCardTestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "AnonymousRecipientSmartCardDecryptionTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testAnonymousRecipientX25519Key();
        testAnonymousRecipientRSAKey();
        testAnonymousRecipientNistP256Key();
    }

    private void testAnonymousRecipientX25519Key()
            throws PGPException, IOException, CardException
    {
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateEd25519KeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateX25519KeyPair)
                .build();
        implTestAnonymousRecipient("X25519", key);
    }

    private void testAnonymousRecipientRSAKey()
            throws PGPException, IOException, CardException
    {
        OpenPGPKey key = api.generateKey(4)
                .compositeRSAKey(2048, "Alice <alice@example.org>")
                .build();
        implTestAnonymousRecipient("RSA-2048", key);
    }

    private void testAnonymousRecipientNistP256Key()
            throws PGPException, IOException, CardException
    {
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback)PGPKeyPairGenerator::generateNistP256ECDHKeyPair)
                .build();
        implTestAnonymousRecipient("NIST P-256 ECDH", key);
    }

    private void implTestAnonymousRecipient(String label, OpenPGPKey softwareKey)
            throws PGPException, IOException, CardException
    {
        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        card.reset();

        // move the decryption key onto the card, then strip the private key material from our copy
        OpenPGPKey.OpenPGPSecretKey decryptionKey =
                softwareKey.getSecretKey(softwareKey.getEncryptionKeys().get(0));
        card.uploadDecryptionKey(decryptionKey.unlock(), properties.getAdminPin());
        OpenPGPKey externalKey = toExternalKey(softwareKey, null);

        isTrue(label + ": the stripped key must be marked external",
                externalKey.getSecretKey(externalKey.getEncryptionKeys().get(0))
                        .getPGPSecretKey().isExternalKey());

        // encrypt to an ANONYMOUS recipient - the PKESK carries a wildcard key identifier
        byte[] plaintext = ("Hello, anonymous " + label + "!\n").getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addEncryptionCertificate(softwareKey.toCertificate(), true)
                .open(bOut);
        mOut.write(plaintext);
        mOut.close();

        byte[] message = bOut.toByteArray();
        isTrue(label + ": message should carry a wildcard PKESK", hasOnlyWildcardPkesks(message));

        // decrypt through the card: the wildcard path has to consult the registered provider
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addDecryptionKey(externalKey, properties.getUserPin())
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .process(new ByteArrayInputStream(message));
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, plainOut);
        mIn.close();

        isTrue(label + ": decrypted plaintext mismatch",
                Arrays.areEqual(plaintext, plainOut.toByteArray()));
    }

    /**
     * Confirm every public-key encrypted session key in the message hides its recipient, i.e. that this
     * really does drive the anonymous branch of the processor.
     */
    private boolean hasOnlyWildcardPkesks(byte[] message)
            throws IOException, PGPException
    {
        // the generator emits ASCII armor, so decode before looking at packets
        PGPObjectFactory objFac = new PGPObjectFactory(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(message)),
                new BcKeyFingerprintCalculator());
        Object o;
        while ((o = objFac.nextObject()) != null)
        {
            if (!(o instanceof PGPEncryptedDataList))
            {
                continue;
            }

            PGPEncryptedDataList encDataList = (PGPEncryptedDataList)o;
            int pkeskCount = 0;
            for (Iterator it = encDataList.getEncryptedDataObjects(); it.hasNext(); )
            {
                PGPEncryptedData encData = (PGPEncryptedData)it.next();
                if (!(encData instanceof PGPPublicKeyEncryptedData))
                {
                    continue;
                }

                pkeskCount++;
                if (!((PGPPublicKeyEncryptedData)encData).getKeyIdentifier().isWildcard())
                {
                    return false;
                }
            }
            return pkeskCount > 0;
        }
        return false;
    }

    public static void main(String[] args)
    {
        SimulatorSmartCardBackend sim = new SimulatorSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, 1312));
        OpenPGPSmartCardManager m = new OpenPGPSmartCardManager().addBackend(sim);

        runTest(new AnonymousRecipientSmartCardDecryptionTest(m, new SmartCardTestProperties(1312)));
    }
}
