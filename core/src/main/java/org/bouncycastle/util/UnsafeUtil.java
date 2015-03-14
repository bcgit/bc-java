package org.bouncycastle.util;

import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.nio.ByteOrder;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;

/**
 * Created by Borislav Ivanov
 * Date: 7/7/14
 * Time: 12:32 PM
 */
public class UnsafeUtil {


    public static Unsafe UNSAFE;

    static
    {
        try
        {
            final PrivilegedExceptionAction<Unsafe> action = new PrivilegedExceptionAction<Unsafe>()
            {
                public Unsafe run() throws Exception
                {
                    final Field field = Unsafe.class.getDeclaredField("theUnsafe");
                    field.setAccessible(true);
                    return (Unsafe)field.get(null);
                }
            };

            UNSAFE = AccessController.doPrivileged(action);
        }
        catch (final Exception ex)
        {
            throw new RuntimeException(ex);
        }
    }


    public static final ByteOrder NATIVE_BYTE_ORDER = ByteOrder.nativeOrder();

    public static final long BYTE_ARRAY_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);



}
