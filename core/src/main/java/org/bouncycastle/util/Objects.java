package org.bouncycastle.util;

import java.util.function.Supplier;

public class Objects
{
    public static boolean areEqual(Object a, Object b)
    {
        return a == b || (null != a && null != b && a.equals(b));
    }

    public static int hashCode(Object obj)
    {
        return null == obj ? 0 : obj.hashCode();
    }

    public static <T> T or(T nullable, Supplier<T> supplier)
    {
        if (nullable == null)
        {
            return supplier.get();
        }
        return nullable;
    }
}
