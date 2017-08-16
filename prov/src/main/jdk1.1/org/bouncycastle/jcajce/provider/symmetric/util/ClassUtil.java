package org.bouncycastle.jcajce.provider.symmetric.util;

public class ClassUtil
{
    public static Class loadClass(Class sourceClass, final String className)
    {
        try
        {
            ClassLoader loader = sourceClass.getClassLoader();

            if (loader != null)
            {
                return loader.loadClass(className);
            }
            else
            {
                return (Class)Class.forName(className);
            }
        }
        catch (ClassNotFoundException e)
        {
            // ignore - maybe log?
        }

        return null;
    }
}
