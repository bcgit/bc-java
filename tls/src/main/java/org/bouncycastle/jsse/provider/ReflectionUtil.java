package org.bouncycastle.jsse.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
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

    static Class<?> getClass(final String className)
    {
        if (null == className)
        {
            return null;
        }

        return AccessController.doPrivileged(new PrivilegedAction<Class<?>>()
        {
            public Class<?> run()
            {
                try
                {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    Class<?> clazz = (null == classLoader)
                        ?   Class.forName(className)
                        :   classLoader.loadClass(className);
                    return clazz;
                }
                catch (Exception e)
                {
                }

                return null;
            }
        });
    }

    static <T> Constructor<T> getDeclaredConstructor(final String className, final Class<?>... parameterTypes)
    {
        if (null == className)
        {
            return null;
        }

        return AccessController.doPrivileged(new PrivilegedAction<Constructor<T>>()
        {
            public Constructor<T> run()
            {
                try
                {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    @SuppressWarnings("unchecked")
                    Class<T> clazz = (Class<T>)((null == classLoader)
                        ?   Class.forName(className)
                        :   classLoader.loadClass(className));
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

    static Method getMethod(final String className, final String methodName, final Class<?>... parameterTypes)
    {
        if (null == className || null == methodName)
        {
            return null;
        }

        return AccessController.doPrivileged(new PrivilegedAction<Method>()
        {
            public Method run()
            {
                try
                {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    Class<?> clazz = (null == classLoader)
                        ?   Class.forName(className)
                        :   classLoader.loadClass(className);

                    if (null != clazz)
                    {
                        return clazz.getMethod(methodName, parameterTypes);
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

    static Integer getStaticInt(final String className, final String fieldName)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Integer>()
        {
            public Integer run()
            {
                try
                {
                    ClassLoader classLoader = ReflectionUtil.class.getClassLoader();
                    Class<?> clazz = (null == classLoader)
                        ?   Class.forName(className)
                        :   classLoader.loadClass(className);

                    if (null != clazz)
                    {
                        Field field = clazz.getField(fieldName);
                        if (null != field)
                        {
                            Class<?> fieldType = field.getType();
                            if (int.class == fieldType)
                            {
                                return field.getInt(null);
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                }

                return null;
            }
        });
    }

    static Integer getStaticIntOrDefault(final String className, final String fieldName, int defaultValue)
    {
        Integer value = getStaticInt(className, fieldName);
        return null == value ? defaultValue : value.intValue();
    }

    static Object invokeGetter(final Object obj, final Method method)
    {
        return invokeMethod(obj, method);
    }

    static Object invokeMethod(final Object obj, final Method method, final Object... args)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                try
                {
                    return method.invoke(obj, args);
                }
                catch (IllegalAccessException e)
                {
                    throw new RuntimeException(e);
                }
                catch (InvocationTargetException e)
                {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    static void invokeSetter(final Object obj, final Method method, final Object arg)
    {
        invokeMethod(obj, method, arg);
    }
}
