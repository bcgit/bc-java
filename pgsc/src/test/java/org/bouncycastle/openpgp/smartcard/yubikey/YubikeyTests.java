package org.bouncycastle.openpgp.smartcard.yubikey;

import junit.framework.TestCase;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;
import org.bouncycastle.openpgp.smartcard.test.AnonymousRecipientSmartCardDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardMessageDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardTestProperties;
import org.bouncycastle.openpgp.smartcard.test.UnrelatedSmartCardMessageDecryptionTest;
import org.bouncycastle.util.test.SimpleTestResult;

public class YubikeyTests
        extends TestCase
{

    public void testBCYK()
            throws CardException
    {
        SmartCardTestProperties p;
        OpenPGPSmartCardManager m;

        try
        {
            p = new YubikeyTestProperties();
            m = YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager(p, YubikeySmartCardBackend.bcImpl());
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.err.println
            System.err.println("Skipping run of OpenPGP Smart Card tests on BC Yubikey.");
            return;
        }

        AbstractOpenPGPSmartCardTest[] tests = new AbstractOpenPGPSmartCardTest[]
                {
                        new SmartCardMessageDecryptionTest(m, p),
                        new AnonymousRecipientSmartCardDecryptionTest(m, p),
                        new UnrelatedSmartCardMessageDecryptionTest(m, p),
                        new CloseYubikeySessionTest(m, p),
                };

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }

    public void testJCEYK()
            throws CardException
    {
        SmartCardTestProperties p;
        OpenPGPSmartCardManager m;

        try
        {
            p = new YubikeyTestProperties();
            m = YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager(p, YubikeySmartCardBackend.jceImpl());
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.err.println
            System.err.println("Skipping run of OpenPGP Smart Card tests on JCE Yubikey.");
            return;
        }

        AbstractOpenPGPSmartCardTest[] tests = new AbstractOpenPGPSmartCardTest[]
                {
                        new SmartCardMessageDecryptionTest(m, p),
                        new AnonymousRecipientSmartCardDecryptionTest(m, p),
                        new UnrelatedSmartCardMessageDecryptionTest(m, p),
                        new CloseYubikeySessionTest(m, p),
                };

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }
}
