package org.bouncycastle.tls.crypto.impl.jcajce;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Integers;

class GCMUtil
{
    static final Constructor<AlgorithmParameterSpec> gcmParameterSpec = getConstructor();

    static AlgorithmParameterSpec createGCMParameterSpec(final int tLen, final byte[] src)
        throws Exception
    {
        if (gcmParameterSpec == null)
        {
            throw new IllegalStateException();
        }

        return AccessController.doPrivileged(new PrivilegedExceptionAction<AlgorithmParameterSpec>()
        {
            public AlgorithmParameterSpec run()
                throws Exception
            {
                return gcmParameterSpec.newInstance(new Object[]{ Integers.valueOf(tLen), src });
            }
        });
    }

    static boolean isGCMParameterSpecAvailable()
    {
        return gcmParameterSpec != null;
    }

    private static Constructor<AlgorithmParameterSpec> getConstructor()
    {
        return AccessController.doPrivileged(new PrivilegedAction<Constructor<AlgorithmParameterSpec>>()
        {
            public Constructor<AlgorithmParameterSpec> run()
            {
                try
                {
                    String className = "javax.crypto.spec.GCMParameterSpec";

                    ClassLoader classLoader = GCMUtil.class.getClassLoader();
                    Class<?> clazz = (null == classLoader)
                        ?   Class.forName(className)
                        :   classLoader.loadClass(className);
                    if (clazz != null && AlgorithmParameterSpec.class.isAssignableFrom(clazz))
                    {
                        @SuppressWarnings("unchecked")
                        Class<AlgorithmParameterSpec> typedClazz = (Class<AlgorithmParameterSpec>)clazz;
                        return typedClazz.getConstructor(new Class[]{ Integer.TYPE, byte[].class });
                    }
                }
                catch (Exception e)
                {
                }

                return null;
            }
        });
    }
}
