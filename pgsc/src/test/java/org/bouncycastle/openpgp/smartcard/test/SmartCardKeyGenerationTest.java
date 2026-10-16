package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
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

import java.io.ByteArrayOutputStream;
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
    public void performTest() throws Exception
    {
        for (OpenPGPSmartCardBackend backend : manager.getBackends())
        {
            try
            {
                performTestOn(backend);
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
    }

    private void performTestOn(OpenPGPSmartCardBackend backend)
            throws CardException, IOException
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
                for (SupportedAlgorithms.Algorithm alg : keyAlgorithms.getAlgorithms())
                {
                    long currentTime = System.currentTimeMillis();
                    // -DM System.out.println
                    System.out.println("Generate key " + alg.toString());
                    PGPPublicKey publicKey = card.generateKey(
                            alg,
                            4,
                            alg.algorithmId,
                            true,
                            k -> "12345678".toCharArray());
                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                    ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
                    BCPGOutputStream pOut = new BCPGOutputStream(aOut);
                    publicKey.encode(pOut);
                    pOut.close();
                    aOut.close();
                    // -DM System.out.println
                    System.out.println(bOut);
                    // -DM System.out.println
                    System.out.println("Took " + ((System.currentTimeMillis() - currentTime) / 1000) +  " seconds");
                }
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
