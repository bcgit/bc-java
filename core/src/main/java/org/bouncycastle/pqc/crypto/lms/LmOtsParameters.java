package org.bouncycastle.pqc.crypto.lms;

import java.util.HashMap;
import java.util.Map;

public class LmOtsParameters
{
    public static final int reserved = 0;
    public static final int sha256_n32_w1 = 1;
    public static final int sha256_n32_w2 = 2;
    public static final int sha256_n32_w4 = 3;
    public static final int sha256_n32_w8 = 4;

    private static final Map<Object, ForClass> suppliers = new HashMap<Object, ForClass>()
    {
        {
            put(sha256_n32_w1, new ForClass(LmOtsParameter.LMOTS_SHA256_N32_W1.class));
            put(sha256_n32_w2, new ForClass(LmOtsParameter.LMOTS_SHA256_N32_W2.class));
            put(sha256_n32_w4, new ForClass(LmOtsParameter.LMOTS_SHA256_N32_W4.class));
            put(sha256_n32_w8, new ForClass(LmOtsParameter.LMOTS_SHA256_N32_W8.class));
        }
    };


    /**
     * Return Leighton-Micali One Time Signature Parameters for a given key.
     * The key is usually an integer.
     *
     * @param key The key.
     * @return A LmOtsParameter instance or throws IllegalArgumentException
     */
    public static LmOtsParameter getOtsParameter(Object key) throws LMSException
    {
        if (key instanceof LmOtsParameter) {
            return (LmOtsParameter)key;
        }

        ForClass fc = suppliers.get(key);
        if (fc != null)
        {
            return fc.create();
        }
        throw new LMSException("no parameters for key " + key);
    }

    private interface OtsParamSuppler
    {
        public LmOtsParameter create();
    }


    private static class ForClass
        implements OtsParamSuppler
    {

        Class<? extends LmOtsParameter> aClass;

        public ForClass(Class<? extends LmOtsParameter> aClass)
        {
            this.aClass = aClass;
        }

        @Override
        public LmOtsParameter create()
        {
            try
            {
                return (LmOtsParameter)aClass.getConstructor(new Class[0]).newInstance();
            }
            catch (Exception ex)
            {
                throw new RuntimeException(ex.getMessage(), ex);
            }
        }
    }
}
