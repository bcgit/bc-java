package org.bouncycastle.crypto.util;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class EraseUtil {

    private static Logger LOG = java.util.logging.Logger.getLogger(EraseUtil.class.getName());

    public static void clearByteArray(final byte[] array) 
    {
        if (array != null) {
            Arrays.fill(array, (byte) 0);
        }
    }

    public static void clearIntArray(final int[] array) 
    {
        if (array != null) 
        {
            Arrays.fill(array, 0);
        }
    }

    public static void clearLongArray(final long[] array) 
    {
        if (array != null) 
        {
            Arrays.fill(array, 0);
        }
    }

    public static void clearBigInteger(final BigInteger bigInteger) 
    {
        if (bigInteger != null) 
        {
            Field declaredField = null;
            try {

                declaredField = BigInteger.class.getDeclaredField("mag");
                final boolean accessible = declaredField.isAccessible();

                declaredField.setAccessible(true);

                final int[] array = (int[]) declaredField.get(bigInteger);
                clearIntArray(array);
                declaredField.setAccessible(accessible);

            } 
            catch (Exception e) 
            {
                LOG.log(Level.WARNING, "Could not erase BigInteger", e);
            }
        }
    }

    public static void clearECFieldElement(final ECFieldElement ecField) {
        if (ecField != null) 
        {

            ecField.toBigInteger(); // x = int[]; long[]
            Field declaredField = null;
            try 
            {
                declaredField = ECFieldElement.class.getDeclaredField("x");
                final boolean accessible = declaredField.isAccessible();

                declaredField.setAccessible(true);

                if (declaredField.getType().isAssignableFrom(BigInteger.class)) 
                {
                    final BigInteger bigInteger = (BigInteger) declaredField.get(ecField);
                    clearBigInteger(bigInteger);
                } 
                else if (declaredField.getType().getSimpleName().equals("LongArray")) 
                {
                    clearBCLongArray(declaredField.get(ecField));
                } 
                else if (declaredField.getType().isArray()) 
                {
                    if (declaredField.getType().getComponentType().getName().equals("int")) 
                    {
                        final int[] array = (int[]) declaredField.get(ecField);
                        clearIntArray(array);
                    } 
                    else if (declaredField.getType().getComponentType().getName().equals("long")) 
                    {
                        final long[] array = (long[]) declaredField.get(ecField);
                        clearLongArray(array);
                    }
                }

                declaredField.setAccessible(accessible);

            } 
            catch (Exception e) 
            {
                LOG.log(Level.WARNING, "Could not erase ECFieldElement", e);
            }
        }
    }

    private static void clearBCLongArray(final Object longArray) 
    {

        if (longArray != null) 
        {
            try 
            {
                final Class<?> c = Class.forName("org.bouncycastle.math.ec.LongArray");
                final Field declaredField = ECPoint.class.getDeclaredField("m_ints");
                final boolean accessible = declaredField.isAccessible();

                declaredField.setAccessible(true);

                final long[] array = (long[]) declaredField.get(longArray);
                clearLongArray(array);

                final ECFieldElement ecField = (ECFieldElement) declaredField.get(longArray);
                clearECFieldElement(ecField);
                declaredField.setAccessible(accessible);

            } 
            catch (Exception e) {
                LOG.log(Level.WARNING, "Could not erase LongArray", e);
            }
        }
    }
}
