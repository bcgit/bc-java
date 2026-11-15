package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.smartcard.BcOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.JcaOpenPGPSmartCardImplementation;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;

import java.io.IOException;
import java.util.List;

public class SmartCardChangePINTest
        extends AbstractOpenPGPSmartCardTest
{

    public SmartCardChangePINTest(OpenPGPSmartCardManager manager, TestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "SmartCardChangePINTest";
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
            throws CardException, IOException
    {
        // -DM System.out.println
        System.out.println("Run SmartCardChangePINTest on backend " + backend.getName());
        List<OpenPGPSmartCard> cards = backend.listSmartCards();
        for (OpenPGPSmartCard card : cards)
        {
            // -DM System.out.println
            System.out.println("Change PINs on " + card.getCardType() + " " + card.getSerialNumber());
            testChangeAdminPIN(card);
            testChangeUserPIN(card);
        }
    }

    private void testChangeAdminPIN(OpenPGPSmartCard card)
            throws CardException
    {
        char[] oldAdminPin = properties.getAdminPin();
        isTrue("Cannot verify old admin PIN", card.checkAdminPIN(c -> oldAdminPin));

        char[] newAdminPin = "12131415".toCharArray();
        card.changeAdminPIN(c -> oldAdminPin, c -> newAdminPin);
        try
        {
            isTrue("Cannot verify new admin PIN after changing it", card.checkAdminPIN(c -> newAdminPin));
            isTrue("Old admin PIN erroneously still verifies", !card.checkAdminPIN(c -> oldAdminPin));
        }
        finally
        {
            // change back, so a failure does not leave the card with an unknown PIN
            card.changeAdminPIN(c -> newAdminPin, c -> oldAdminPin);
        }
        isTrue("Cannot verify admin PIN after changing it back", card.checkAdminPIN(c -> oldAdminPin));
    }

    private void testChangeUserPIN(OpenPGPSmartCard card)
            throws CardException
    {
        char[] oldUserPIN = properties.getUserPin();
        isTrue("Cannot verify old user PIN", card.checkUserPIN(c -> oldUserPIN));

        // a wrong old PIN is refused and leaves the PIN as it was
        char[] newUserPIN = "121314".toCharArray();
        try
        {
            card.changeUserPIN(c -> "999999".toCharArray(), c -> newUserPIN);
            fail("User PIN changed with a wrong old PIN");
        }
        catch (CardException e)
        {
            // expected
        }
        isTrue("Rejected change altered the user PIN", card.checkUserPIN(c -> oldUserPIN));

        card.changeUserPIN(c -> oldUserPIN, c -> newUserPIN);
        try
        {
            isTrue("Cannot verify new user PIN after changing it", card.checkUserPIN(c -> newUserPIN));
            isTrue("Old user PIN erroneously still verifies", !card.checkUserPIN(c -> oldUserPIN));
        }
        finally
        {
            // change back, so a failure does not leave the card with an unknown PIN
            card.changeUserPIN(c -> newUserPIN, c -> oldUserPIN);
        }
        isTrue("Cannot verify user PIN after changing it back", card.checkUserPIN(c -> oldUserPIN));
    }

    public static void main(String[] args)
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
            runTest(new SmartCardChangePINTest(m, p));

            // JCYK
            m = new OpenPGPSmartCardManager();
            m.addBackend(
                    YubikeyTestInstanceProvider.prepareBackend(p, new JcaOpenPGPSmartCardImplementation()));
            runTest(new SmartCardChangePINTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SmartCardChangePINTest on Yubikey: " + e.getMessage());
        }

        p = new TestProperties(161);
        SimulatorOpenPGPSmartCardBackend sim = new SimulatorOpenPGPSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, p.getSerialNumber()));
        m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        runTest(new SmartCardChangePINTest(m, p));
    }
}
