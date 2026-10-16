package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.ExternalOpenPGPKeyUtils;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * Register multiple {@link SimulatorOpenPGPSmartCardBackend} instances, each managing
 * a different {@link SimulatorOpenPGPSmartCard} (one v4, one v6).
 * Next, sign and encrypt a message using multiple hardware keys, then decrypt and verify.
 */
public class MultiBackendTest extends SimpleTest
{
    private final ExternalOpenPGPKeyUtils cardUtils = new ExternalOpenPGPKeyUtils(new BcOpenPGPImplementation());

    @Override
    public String getName()
    {
        return "MultiBackendTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        OpenPGPApi api = new BcOpenPGPApi();
        OpenPGPSmartCardManager manager = new OpenPGPSmartCardManager();

        // Alice' v4 key on card #1
        OpenPGPKey aliceKey = api.generateKey(4)
                .ed25519x25519Key("Alice <alice@example.org>")
                .build();
        OpenPGPKey aliceExt = cardUtils.toExternalKey(aliceKey);

        SimulatorOpenPGPSmartCardBackend b1 = new SimulatorOpenPGPSmartCardBackend();
        SimulatorOpenPGPSmartCard c1 = SimulatorOpenPGPSmartCard.createSimulatedCardFrom(b1, 12345, aliceKey);
        b1.addSmartCard(c1);
        manager.addBackend(b1);

        // Bobs v6 key on card #2
        OpenPGPKey bobKey = api.generateKey(6)
                .ed25519x25519Key("Bob <bob@example.org>")
                .build();
        OpenPGPKey bobExt = cardUtils.toExternalKey(bobKey);

        SimulatorOpenPGPSmartCardBackend b2 = new SimulatorOpenPGPSmartCardBackend();
        SimulatorOpenPGPSmartCard c2 = SimulatorOpenPGPSmartCard.createSimulatedCardFrom(b2, 98765, bobKey);
        b2.addSmartCard(c2);
        manager.addBackend(b2);

        // Sign and encrypt with both keys
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addCustomPGPContentSignerBuilderProviderFactory(manager)
                .addSigningKey(aliceExt, k -> SimulatorOpenPGPSmartCard.DEFAULT_USER_PIN)
                .addSigningKey(bobExt, k -> SimulatorOpenPGPSmartCard.DEFAULT_USER_PIN)
                .addEncryptionCertificate(aliceExt)
                .addEncryptionCertificate(bobExt)
                .open(bOut);
        mOut.write("Hello, World!".getBytes());
        mOut.close();

        // Decrypt and verify
        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addVerificationCertificate(aliceExt)
                .addVerificationCertificate(bobExt)
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .addDecryptionKey(aliceExt, SimulatorOpenPGPSmartCard.DEFAULT_USER_PIN)
                .addDecryptionKey(bobExt, SimulatorOpenPGPSmartCard.DEFAULT_USER_PIN)
                .process(bIn);
        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, bOut);
        mIn.close();
        OpenPGPMessageInputStream.Result result = mIn.getResult();

        isTrue(result.getSignatures().size() == 2);
        for (OpenPGPSignature.OpenPGPDocumentSignature sig : result.getSignatures())
        {
            isTrue(sig.isValid());
        }
    }

    public static void main(String[] args)
    {
        runTest(new MultiBackendTest());
    }
}
