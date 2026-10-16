package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.ExternalOpenPGPKeyUtils;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public class FailingBackendTest
        extends SimpleTest
{
    @Override
    public String getName()
    {
        return "FailingBackendTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        OpenPGPApi api = new BcOpenPGPApi();
        ExternalOpenPGPKeyUtils keyUtils = new ExternalOpenPGPKeyUtils(api.getImplementation());
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback)  PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyX25519KeyPair)
                .build();
        OpenPGPKey externalKey = keyUtils.toExternalKey(key);

        OpenPGPSmartCardManager manager = new OpenPGPSmartCardManager();
        SimulatorOpenPGPSmartCardBackend failingBackend = new SimulatorOpenPGPSmartCardBackend() {
            @Override
            public String getName()
            {
                return "FailingSimulatorOpenPGPSmartCardBackend";
            }

            @Override
            public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
                    OpenPGPKey.OpenPGPSecretKey decryptionKeyStub,
                    KeyPassphraseProvider userPinProvider)
                    throws PGPException
            {
                throw new PGPException("Fail to provide PublicKeyDataDecryptorFactory");
            }

            @Override
            public PGPContentSignerBuilderProvider getPGPContentSignerBuilderProvider(
                    OpenPGPKey.OpenPGPSecretKey signingKey,
                    KeyPassphraseProvider userPinProvider,
                    int hashAlgorithmId)
                    throws PGPException
            {
                throw new PGPException("Fail to provide PGPContentSignerBuilderProvider");
            }
        };

        SimulatorOpenPGPSmartCardBackend workingBackend = new SimulatorOpenPGPSmartCardBackend() {
            @Override
            public String getName()
            {
                return "WorkingSimulatorOpenPGPSmartCard";
            }
        };
        workingBackend.addSmartCard(SimulatorOpenPGPSmartCard.createSimulatedCardFrom(workingBackend, key));

        manager.addBackend(failingBackend);
        manager.addBackend(workingBackend);

        byte[] message = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addCustomPGPContentSignerBuilderProviderFactory(manager)
                .addSigningKey(externalKey, k -> SimulatorOpenPGPSmartCard.DEFAULT_USER_PIN)
                .addEncryptionCertificate(key.toCertificate())
                .open(bOut);
        mOut.write(message);
        mOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .addVerificationCertificate(key.toCertificate())
                .addDecryptionKey(externalKey, SimulatorOpenPGPSmartCard.DEFAULT_USER_PIN)
                .process(bIn);
        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, bOut);
        mIn.close();
        isTrue(Arrays.areEqual(message, bOut.toByteArray()));
        isTrue(mIn.getResult().getSignatures().get(0).isValid());
    }

    public static void main(String[] args)
    {
        runTest(new FailingBackendTest());
    }
}
