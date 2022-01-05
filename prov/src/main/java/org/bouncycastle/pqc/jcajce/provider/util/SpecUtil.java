package org.bouncycastle.pqc.jcajce.provider.util;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;

public class SpecUtil
{
    public static String getNameFrom(final AlgorithmParameterSpec paramSpec)
    {
        return (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    Method m = paramSpec.getClass().getMethod("getName");

                    return m.invoke(paramSpec);
                }
                catch (Exception e)
                {
                    // ignore - maybe log?
                }

                return null;
            }
        });
    }
}
