package org.bouncycastle.openpgp.smartcard.yubikey;

import com.yubico.yubikit.core.smartcard.ApduException;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardTestProperties;

import java.io.IOException;

public class CloseYubikeySessionTest
        extends AbstractOpenPGPSmartCardTest
{

    public CloseYubikeySessionTest(OpenPGPSmartCardManager manager, SmartCardTestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public void performTest()
            throws Exception
    {
        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        if (!(card instanceof YubikeyOpenPGPSmartCard))
        {
            fail("Cannot run test with non-Yubikey");
        }

        YubikeyOpenPGPSmartCard yubikey = (YubikeyOpenPGPSmartCard) card;
        try
        {
            yubikey.openSession();
        }
        catch (ApduException e)
        {
            throw new CardException(e);
        }

        try
        {
            yubikey.openSession();
        }
        catch (IOException e)
        {
            isTrue(e.getMessage().contains("Exclusive access"));
        }
        catch (ApduException e)
        {
            throw new RuntimeException(e);
        }

    }

    @Override
    public String getName()
    {
        return "CloseYubikeySessionTest";
    }

    public static void main(String[] args)
    {
        SmartCardTestProperties p = new YubikeyTestProperties();
        OpenPGPSmartCardManager m;
        try
        {
            m = YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager(p);
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException | CardException e)
        {
            throw new RuntimeException(e);
        }
        runTest(new CloseYubikeySessionTest(m, p));
    }
}
