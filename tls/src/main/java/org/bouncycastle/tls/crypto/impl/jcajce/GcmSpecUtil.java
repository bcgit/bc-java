package org.bouncycastle.tls.crypto.impl.jcajce;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.util.Integers;

class GcmSpecUtil
{
    static final Class gcmSpecClass = lookup("javax.crypto.spec.GCMParameterSpec");

    static boolean gcmSpecExists()
    {
        return gcmSpecClass != null;
    }

    static AlgorithmParameterSpec createGcmSpec(final byte[] nonce, final int macLen)
        throws InvalidParameterSpecException
    {
        Object rv = AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                try
                {
                    Constructor constructor = gcmSpecClass.getConstructor(new Class[]{Integer.TYPE, byte[].class});

                    return constructor.newInstance(new Object[]{Integers.valueOf(macLen * 8), nonce});
                }
                catch (NoSuchMethodException e)
                {
                    return new InvalidParameterSpecException("no constructor found!");   // should never happen
                }
                catch (Exception e)
                {
                    return new InvalidParameterSpecException("construction failed: " + e.getMessage());   // should never happen
                }
            }
        });
        if (rv instanceof AlgorithmParameterSpec)
        {
            return (AlgorithmParameterSpec)rv;
        }
        else
        {
            throw (InvalidParameterSpecException)rv;
        }
    }

    static Class lookup(final String className)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Class>()
        {
            public Class run()
            {
                try
                {
                    ClassLoader loader = GcmSpecUtil.class.getClassLoader();
                    if (loader == null)
                    {
                        loader = ClassLoader.getSystemClassLoader();
                    }

                    return loader.loadClass(className);
                }
                catch (Exception e)
                {
                    return null;
                }
            }
        });
    }
}
