package org.bouncycastle.pqc.crypto.lms;

import java.util.HashMap;
import java.util.Map;

public class LmsParameters
{
    public static final int lms_sha256_n32_h5 = 5;
    public static final int lms_sha256_n32_h10 = 6;
    public static final int lms_sha256_n32_h15 = 7;
    public static final int lms_sha256_n32_h20 = 8;
    public static final int lms_sha256_n32_h25 = 9;

    private static Map<Object, ForClass> paramBuilders = new HashMap<Object, ForClass>()
    {
        {
            put(lms_sha256_n32_h5, new ForClass(LmsParameter.LMS_SHA256_M32_H5.class));
            put(lms_sha256_n32_h10, new ForClass(LmsParameter.LMS_SHA256_M32_H10.class));
            put(lms_sha256_n32_h15, new ForClass(LmsParameter.LMS_SHA256_M32_H15.class));
            put(lms_sha256_n32_h20, new ForClass(LmsParameter.LMS_SHA256_M32_H20.class));
            put(lms_sha256_n32_h25, new ForClass(LmsParameter.LMS_SHA256_M32_H25.class));

        }
    };

    public static LmsParameter getParametersForType(Object lmsType)
    {
        ForClass fc = paramBuilders.get(lmsType);
        if (fc != null)
        {
            return fc.create();
        }
        throw new IllegalArgumentException("could not find parameters for type " + lmsType);
    }

    private static class ForClass
    {
        private final Class<? extends LmsParameter> aClass;


        private ForClass(Class<? extends LmsParameter> aClass)
        {
            this.aClass = aClass;
        }

        public LmsParameter create()
        {
            try
            {
                return this.aClass.getConstructor(new Class[0]).newInstance();
            }
            catch (Exception ex)
            {
                throw new IllegalArgumentException(ex.getMessage(), ex);
            }
        }
    }
}
