package org.bouncycastle.tls.crypto.impl.jcajce;

import java.lang.reflect.Method;
import java.security.PrivateKey;

import org.bouncycastle.tls.ReflectionUtil;

abstract class PrivateKeyUtil
{
    private static final Method destroy;

    static
    {
        Method[] methods = ReflectionUtil.getMethods("java.security.PrivateKey");

        destroy = ReflectionUtil.findMethod(methods, "destroy");
    }

    static void destroy(PrivateKey privateKey)
    {
        if (destroy != null)
        {
            try
            {
                ReflectionUtil.invokeMethod(privateKey, destroy);
            }
            catch (Exception e)
            {
            }
        }
    }
}
