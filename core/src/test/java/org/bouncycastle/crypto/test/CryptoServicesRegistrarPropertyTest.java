package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for the thread and global properties of CryptoServicesRegistrar. Setting a
 * global property used to copy the value onto the calling thread as well, so the thread that ran
 * the class's static initializer kept the default DSA and DH parameters, and with them the class
 * loader that loaded Bouncy Castle, for as long as it lived (github #2536). A global value is now
 * only copied onto a thread that already has a value of its own for the property.
 */
public class CryptoServicesRegistrarPropertyTest
    extends SimpleTest
{
    private static final CryptoServicesRegistrar.Property DSA = CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS;

    public String getName()
    {
        return "CryptoServicesRegistrarProperty";
    }

    public void performTest()
        throws Exception
    {
        DSAParameters[] original = toDSA(CryptoServicesRegistrar.getSizedProperty(DSA));
        DSAParameters[] reversed = new DSAParameters[original.length];
        for (int i = 0; i != original.length; i++)
        {
            reversed[i] = original[original.length - 1 - i];
        }

        try
        {
            noThreadCopyOnGlobalSet(reversed);
            threadValueUpdatedOnGlobalSet(original, reversed);
            globalSetFromOtherThreadVisible(original, reversed);
            clearOnFreshThread();
        }
        finally
        {
            CryptoServicesRegistrar.setGlobalProperty(DSA, original);
        }

        isTrue("global value not restored", CryptoServicesRegistrar.getSizedProperty(DSA)[0] == original[0]);
    }

    /*
     * A thread with no values of its own that sets a global property - as the static initializer
     * does - must be left with no thread value afterwards.
     */
    private void noThreadCopyOnGlobalSet(final DSAParameters[] value)
        throws Exception
    {
        runOnNewThread(new Check()
        {
            void check()
            {
                CryptoServicesRegistrar.setGlobalProperty(DSA, value);

                isTrue("global value not visible", CryptoServicesRegistrar.getSizedProperty(DSA)[0] == value[0]);
                isTrue("global set left a thread value", CryptoServicesRegistrar.clearThreadProperty(DSA) == null);
            }
        });
    }

    /*
     * A thread that has its own value sees a global set it makes itself.
     */
    private void threadValueUpdatedOnGlobalSet(final DSAParameters[] threadValue, final DSAParameters[] globalValue)
        throws Exception
    {
        runOnNewThread(new Check()
        {
            void check()
            {
                CryptoServicesRegistrar.setThreadProperty(DSA, threadValue);
                CryptoServicesRegistrar.setGlobalProperty(DSA, globalValue);

                isTrue("thread value not updated", CryptoServicesRegistrar.getSizedProperty(DSA)[0] == globalValue[0]);
                isTrue("thread value missing", CryptoServicesRegistrar.clearThreadProperty(DSA) != null);
                isTrue("cleared thread value still present", CryptoServicesRegistrar.clearThreadProperty(DSA) == null);
            }
        });
    }

    /*
     * A thread that set a global value without a value of its own sees a later global set made
     * by another thread, rather than a stale copy of its own.
     */
    private void globalSetFromOtherThreadVisible(final DSAParameters[] first, final DSAParameters[] second)
        throws Exception
    {
        runOnNewThread(new Check()
        {
            void check()
                throws Exception
            {
                CryptoServicesRegistrar.setGlobalProperty(DSA, first);

                runOnNewThread(new Check()
                {
                    void check()
                    {
                        CryptoServicesRegistrar.setGlobalProperty(DSA, second);
                    }
                });

                isTrue("stale global value", CryptoServicesRegistrar.getSizedProperty(DSA)[0] == second[0]);
            }
        });
    }

    /*
     * Clearing a property on a thread with no values returns null without leaving anything behind.
     */
    private void clearOnFreshThread()
        throws Exception
    {
        runOnNewThread(new Check()
        {
            void check()
            {
                isTrue("unexpected thread value", CryptoServicesRegistrar.clearThreadProperty(DSA) == null);
                isTrue("global value lost", CryptoServicesRegistrar.getSizedProperty(DSA) != null);
            }
        });
    }

    private static DSAParameters[] toDSA(Object[] values)
    {
        DSAParameters[] params = new DSAParameters[values.length];
        System.arraycopy(values, 0, params, 0, values.length);
        return params;
    }

    private static void runOnNewThread(final Check check)
        throws Exception
    {
        Thread t = new Thread(check);

        t.start();
        t.join();

        if (check.failure != null)
        {
            throw check.failure;
        }
    }

    private static abstract class Check
        implements Runnable
    {
        Exception failure;

        abstract void check()
            throws Exception;

        public void run()
        {
            try
            {
                check();
            }
            catch (Exception e)
            {
                failure = e;
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new CryptoServicesRegistrarPropertyTest());
    }
}
