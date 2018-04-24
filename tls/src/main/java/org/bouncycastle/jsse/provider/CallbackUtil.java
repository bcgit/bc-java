package org.bouncycastle.jsse.provider;

abstract class CallbackUtil
{
    static void safeCallback(Runnable r)
    {
        try
        {
            r.run();
        }
        catch (Error e)
        {
            /*
             * "An Error is a subclass of Throwable that indicates serious problems that a
             * reasonable application should not try to catch. Most such errors are abnormal
             * conditions. The ThreadDeath error, though a "normal" condition, is also a subclass of
             * Error because most applications should not try to catch it."
             */
            throw e;
        }
        catch (Throwable t)
        {
            // TODO[jsse] Logging
        }
    }
}
