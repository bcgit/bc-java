package org.bouncycastle.smartcard.yubikey;

import junit.framework.TestCase;
import org.bouncycastle.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.smartcard.card.CardException;
import org.bouncycastle.smartcard.test.*;
import org.bouncycastle.util.test.SimpleTestResult;

public class YubikeyTests
        extends TestCase
{

    public void testYubikeySmartCard()
            throws CardException
    {
        SmartCardTestProperties p;
        OpenPGPSmartCardManager m;
        try
        {
            p = new YubikeyTestProperties();
            m = YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager(p);
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.err.println
            System.err.println("Skipping run of OpenPGP Smart Card tests on Yubikey.");
            return;
        }

        AbstractOpenPGPSmartCardTest[] tests = new AbstractOpenPGPSmartCardTest[]
                {
                        new SmartCardMessageDecryptionTest(m, p),
                        new UnrelatedSmartCardMessageDecryptionTest(m, p),
                        new CloseYubikeySessionTest(m, p),
                };

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                result.getException().printStackTrace();
                fail(result.toString());
            }
        }
    }
}
