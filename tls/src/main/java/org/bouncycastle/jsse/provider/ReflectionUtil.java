package org.bouncycastle.jsse.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

class ReflectionUtil
{
    static Method findMethod(Method[] methods, String name)
    {
        if (methods != null)
        {
            for (Method m : methods)
            {
                if (m.getName().equals(name))
                {
                    return m;
                }
            }
        }
        return null;
    }

    static boolean hasMethod(Method[] methods, String name)
    {
        return null != findMethod(methods, name);
    }

    static Constructor getDeclaredConstructor(final String className, final Class<?>... parameterTypes)
    {
        if (null == className)
        {
            return null;
        }

        return AccessController.doPrivileged(new PrivilegedAction<Constructor>()
        {
            public Constructor run()
            {
                try
                {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    Class<?> clazz = (null == classLoader)
                        ?   Class.forName(className)
                        :   classLoader.loadClass(className);

                    if (null != clazz)
                    {
                        return clazz.getDeclaredConstructor(parameterTypes);
                    }
                }
                catch (Exception e)
                {
                }

                return null;
            }
        });
    }

    static Method[] getMethods(final String className)
    {
        if (null == className)
        {
            return null;
        }

        return AccessController.doPrivileged(new PrivilegedAction<Method[]>()
        {
            public Method[] run()
            {
                try
                {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    Class<?> clazz = (null == classLoader)
                        ?   Class.forName(className)
                        :   classLoader.loadClass(className);

                    if (null != clazz)
                    {
                        return clazz.getMethods();
                    }
                }
                catch (Exception e)
                {
                }

                return null;
            }
        });
    }

    static Object invokeGetter(final Object obj, final Method method)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                try
                {
                    return method.invoke(obj);
                }
                catch (Exception e)
                {
                    // TODO: log?
                }
                return null;
            }
        });
    }

    static void invokeSetter(final Object obj, final Method method, final Object arg)
    {
        AccessController.doPrivileged(new PrivilegedAction<Void>()
        {
            public Void run()
            {
                try
                {
                    method.invoke(obj, arg);
                }
                catch (Exception e)
                {
                    // TODO: log?
                }
                return null;
            }
        });
    }
}
