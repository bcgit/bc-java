package org.bouncycastle.openpgp.smartcard.simulator;

import junit.framework.TestCase;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;
import org.bouncycastle.openpgp.smartcard.test.AnonymousRecipientSmartCardDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardMessageDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardTestProperties;
import org.bouncycastle.openpgp.smartcard.test.UnrelatedSmartCardMessageDecryptionTest;
import org.bouncycastle.util.test.SimpleTestResult;

public class SimulatorTests
        extends TestCase
{
    public void testSimulatorSmartCard()
    {
        SimulatorSmartCardBackend sim = new SimulatorSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, 1312));
        OpenPGPSmartCardManager m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        SmartCardTestProperties p = new SmartCardTestProperties(1312);

        AbstractOpenPGPSmartCardTest[] tests = new AbstractOpenPGPSmartCardTest[]
                {
                        new SmartCardMessageDecryptionTest(m, p),
                        new AnonymousRecipientSmartCardDecryptionTest(m, p),
                        new UnrelatedSmartCardMessageDecryptionTest(m, p),
                        new SimulatorSmartCardTest(m, p)
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
