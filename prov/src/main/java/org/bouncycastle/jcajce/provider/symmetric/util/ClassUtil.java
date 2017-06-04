package org.bouncycastle.jcajce.provider.symmetric.util;

import java.security.AccessController;
import java.security.PrivilegedAction;

public class ClassUtil
{
    public static Class loadClass(Class sourceClass, final String className)
    {
        try
        {
            ClassLoader loader = sourceClass.getClassLoader();
            Class clazz = null;

            if (loader != null)
            {
                return loader.loadClass(className);
            }
            else
            {
                return AccessController.doPrivileged(new PrivilegedAction<Class>()
                {
                    public Class run()
                    {
                        try
                        {
                            return Class.forName(className);
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
        catch (ClassNotFoundException e)
        {
            // ignore - maybe log?
        }

        return null;
    }
}
