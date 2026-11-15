package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.JcaOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPHardwareKey;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.card.SupportedAlgorithms;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.util.List;

public class SmartCardKeyGenerationTest
        extends AbstractOpenPGPSmartCardTest
{

    public SmartCardKeyGenerationTest(OpenPGPSmartCardManager manager, TestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "SmartCardKeyGenerationTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        for (OpenPGPSmartCardBackend backend : manager.getBackends())
        {
            performTestOn(backend);
        }
    }

    private void performTestOn(OpenPGPSmartCardBackend backend)
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Run SmartCardKeyGenerationTest on backend " + backend.getName());
        List<OpenPGPSmartCard> cards = backend.listSmartCards();
        for (OpenPGPSmartCard card : cards)
        {
            // -DM System.out.println
            System.out.println("Run test on " + card.getCardType() + " (" + card.getSerialNumber() + ")");
            SupportedAlgorithms cardAlgorithms = card.getSupportedAlgorithms();
            for (byte keyRef : new byte[]{OpenPGPHardwareKey.KEY_REF_SIGNATURE, OpenPGPHardwareKey.KEY_REF_DECRYPTION})
            {
                SupportedAlgorithms keyAlgorithms = cardAlgorithms.filter(keyRef);
                isTrue("no algorithms advertised for key slot " + keyRef, !keyAlgorithms.getAlgorithms().isEmpty());
                for (SupportedAlgorithms.Algorithm alg : keyAlgorithms.getAlgorithms())
                {
                    // -DM System.out.println
                    System.out.println("Generate key " + alg.toString());
                    PGPPublicKey publicKey = card.generateKey(
                            alg,
                            4,
                            alg.algorithmId,
                            true,
                            c -> properties.getAdminPin());

                    isTrue(alg + ": algorithm ID " + publicKey.getAlgorithm(), alg.algorithmId == publicKey.getAlgorithm());
                    isTrue(alg + ": not a subkey", !publicKey.isMasterKey());

                    // the card reports the new key, and it can be rebuilt from the card's own record of it
                    OpenPGPHardwareKey hwKey = card.getKeyByKeyRef(keyRef);
                    isTrue(alg + ": no key reported in slot " + keyRef, hwKey != null);
                    isTrue(alg + ": card reports a different fingerprint",
                            Arrays.areEqual(publicKey.getFingerprint(), hwKey.getFingerprint()));
                    isTrue(alg + ": reconstructed key has a different fingerprint",
                            Arrays.areEqual(publicKey.getFingerprint(),
                                    card.reconstructPGPPublicKey(keyRef).getFingerprint()));
                    isTrue(alg + ": generated key not found by fingerprint",
                            card.hasKeyWithFingerprint(publicKey.getFingerprint()));
                }

                // a request whose algorithm ID does not fit the algorithm is refused before the slot is touched
                byte[] fingerprint = card.getKeyByKeyRef(keyRef).getFingerprint();
                SupportedAlgorithms.Algorithm alg = keyAlgorithms.getAlgorithms().get(0);
                int wrongTag = (alg instanceof SupportedAlgorithms.RSA)
                        ? PublicKeyAlgorithmTags.ECDSA : PublicKeyAlgorithmTags.RSA_GENERAL;
                try
                {
                    card.generateKey(alg, 4, wrongTag, true, c -> properties.getAdminPin());
                    fail(alg + ": algorithm ID " + wrongTag + " accepted");
                }
                catch (IllegalArgumentException e)
                {
                    // expected
                }
                try
                {
                    card.generateKey(alg, 3, alg.algorithmId, true, c -> properties.getAdminPin());
                    fail(alg + ": key version 3 accepted");
                }
                catch (IllegalArgumentException e)
                {
                    // expected
                }
                isTrue(alg + ": rejected request changed the key in slot " + keyRef,
                        Arrays.areEqual(fingerprint, card.getKeyByKeyRef(keyRef).getFingerprint()));
            }
        }
    }

    public static void main(String[] args)
            throws CardException
    {
        OpenPGPSmartCardManager m;
        TestProperties p;

        try
        {
            p = YubikeyTestInstanceProvider.defaultProperties();

            // BCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, new BcOpenPGPSmartCardImplementation()));
            runTest(new SmartCardKeyGenerationTest(m, p));

            // JCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, new JcaOpenPGPSmartCardImplementation()));
            runTest(new SmartCardKeyGenerationTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SmartCardKeyGenerationTest on Yubikey: " + e.getMessage());
        }

        p = new TestProperties(1312);
        SimulatorOpenPGPSmartCardBackend sim = new SimulatorOpenPGPSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, p.getSerialNumber()));
        m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        runTest(new SmartCardKeyGenerationTest(m, p));
    }
}
