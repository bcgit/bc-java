package org.bouncycastle.openpgp.smartcard.simulator;

import junit.framework.TestCase;
import org.bouncycastle.openpgp.smartcard.operator.PublicKeyConverterTest;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.test.AbstractOpenPGPSmartCardTest;
import org.bouncycastle.openpgp.smartcard.test.AnonymousRecipientSmartCardDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.MultiBackendTest;
import org.bouncycastle.openpgp.smartcard.test.OpenPGPSmartCardBackendTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardKeyGenerationTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardMessageDecryptionTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardMessageSigningTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardUserPinOwnershipTest;
import org.bouncycastle.openpgp.smartcard.test.SmartCardWithV6KeysTest;
import org.bouncycastle.openpgp.smartcard.test.UnrelatedSmartCardMessageDecryptionTest;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;

public class SimulatorTests
        extends TestCase
{
    public void testOnSimulatorSmartCard()
    {
        SimulatorOpenPGPSmartCardBackend sim = new SimulatorOpenPGPSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, 1312));
        OpenPGPSmartCardManager m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        AbstractOpenPGPSmartCardTest.TestProperties p = new AbstractOpenPGPSmartCardTest.TestProperties(1312);

        Test[] tests = new Test[]
                {
                        new SimulatorSmartCardTest(m, p),
                        new SmartCardMessageDecryptionTest(m, p),
                        new SmartCardMessageSigningTest(m, p),
                        new SmartCardKeyGenerationTest(m, p),
                        new AnonymousRecipientSmartCardDecryptionTest(m, p),
                        new UnrelatedSmartCardMessageDecryptionTest(m, p),
                        new SmartCardWithV6KeysTest(m, p),
                        new OpenPGPSmartCardBackendTest(m, p),
                        new SmartCardUserPinOwnershipTest(m, p),
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

    public static void main(String[] args)
    {
        new SimulatorTests().testOnSimulatorSmartCard();
    }
}
