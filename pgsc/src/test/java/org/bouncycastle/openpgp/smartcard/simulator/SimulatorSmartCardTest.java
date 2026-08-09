package org.bouncycastle.openpgp.smartcard.simulator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardTestProperties;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestProperties;

import java.io.IOException;

public class SimulatorSmartCardTest
    extends AbstractOpenPGPSmartCardTest
{

    public SimulatorSmartCardTest(OpenPGPSmartCardManager manager, SmartCardTestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "SimulatorSmartCardTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testSignOnlyKey();
        testEncryptOnlyKey();
        testSignEncryptKey();
        testEmptyKey();
    }

    private void testSignOnlyKey()
            throws PGPException, CardException, IOException
    {
        OpenPGPKey key = api.generateKey(4)
                .signOnlyKey()
                .build();

        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        keyToCard(key, card);

        isEquals("SerialNumber mismatch", properties.getSerialNumber(), card.getSerialNumber());

        isTrue("sign-only key MUST NOT have decryption key",
                !card.hasDecryptionKey());
        isTrue("sign-only key MUST NOT have auth key",
                !card.hasAuthenticationKey());
        isTrue("sign-only key MUST have sign key",
                card.hasSignatureKey());
        // -DM System.out.println
        System.out.println(card);
    }

    private void testEncryptOnlyKey()
            throws PGPException, CardException, IOException
    {
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey()
                .addEncryptionSubkey()
                .build();

        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        keyToCard(key, card);

        isEquals("SerialNumber mismatch", properties.getSerialNumber(), card.getSerialNumber());

        isTrue("encrypt-only key MUST have decryption key",
                card.hasDecryptionKey());
        isTrue("encrypt-only key MUST NOT have auth key",
                !card.hasAuthenticationKey());
        isTrue("encrypt-only key MUST NOT have sign key",
                !card.hasSignatureKey());
        // -DM System.out.println
        System.out.println(card);
    }

    private void testSignEncryptKey()
            throws PGPException, CardException, IOException
    {
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey()
                .addSigningSubkey()
                .addEncryptionSubkey()
                .build();

        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        keyToCard(key, card);

        isEquals("SerialNumber mismatch", properties.getSerialNumber(), card.getSerialNumber());

        isTrue("key MUST have decryption key",
                card.hasDecryptionKey());
        isTrue("key MUST NOT have auth key",
                !card.hasAuthenticationKey());
        isTrue("key MUST have sign key",
                card.hasSignatureKey());
        // -DM System.out.println
        System.out.println(card);
    }

    public void testEmptyKey()
            throws PGPException, CardException, IOException
    {
        OpenPGPKey key = api.generateKey(4)
                .withPrimaryKey()
                .build();

        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        keyToCard(key, card);

        isEquals("SerialNumber mismatch", properties.getSerialNumber(), card.getSerialNumber());

        isTrue("key MUST NOT have decryption key",
                !card.hasDecryptionKey());
        isTrue("key MUST NOT have auth key",
                !card.hasAuthenticationKey());
        isTrue("key MUST NOT have sign key",
                !card.hasSignatureKey());
        // -DM System.out.println
        System.out.println(card);
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
            runTest(new SimulatorSmartCardTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SimulatorSmartCardTest on Yubikey.");
        }

        SimulatorSmartCardBackend sim = new SimulatorSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, 1312));
        m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        p = new SmartCardTestProperties(1312);
        runTest(new SimulatorSmartCardTest(m, p));
    }
}
