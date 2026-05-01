package org.bouncycastle.jcajce.util;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

public class SpecUtil
{
    private static Class[] NO_PARAMS = new Class[0];
    private static Object[] NO_ARGS = new Object[0];

    public static String getNameFrom(final AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof NamedParameterSpec)
        {
            return ((NamedParameterSpec)paramSpec).getName();
        }

        return (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    Method m = paramSpec.getClass().getMethod("getName", NO_PARAMS);

                    return m.invoke(paramSpec, NO_ARGS);
                }
                catch (Exception e)
                {
                    // ignore - maybe log?
                }

                return null;
            }
        });
    }

    public static byte[] getContextFrom(final AlgorithmParameterSpec paramSpec)
    {
        return (byte[])AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    Method m = paramSpec.getClass().getMethod("getContext", NO_PARAMS);

                    return m.invoke(paramSpec, NO_ARGS);
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
