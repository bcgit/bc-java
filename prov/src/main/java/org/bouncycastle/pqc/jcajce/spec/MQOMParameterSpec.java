package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Strings;

/**
 * AlgorithmParameterSpec for MQOM v2.1. One constant per official parameter set
 * (36 in total).
 */
public class MQOMParameterSpec
    implements AlgorithmParameterSpec
{
    public static final MQOMParameterSpec mqom2_cat1_gf2_fast_r3      = new MQOMParameterSpec("MQOM2-CAT1-GF2-FAST-R3");
    public static final MQOMParameterSpec mqom2_cat1_gf2_fast_r5      = new MQOMParameterSpec("MQOM2-CAT1-GF2-FAST-R5");
    public static final MQOMParameterSpec mqom2_cat1_gf2_short_r3     = new MQOMParameterSpec("MQOM2-CAT1-GF2-SHORT-R3");
    public static final MQOMParameterSpec mqom2_cat1_gf2_short_r5     = new MQOMParameterSpec("MQOM2-CAT1-GF2-SHORT-R5");
    public static final MQOMParameterSpec mqom2_cat1_gf16_fast_r3     = new MQOMParameterSpec("MQOM2-CAT1-GF16-FAST-R3");
    public static final MQOMParameterSpec mqom2_cat1_gf16_fast_r5     = new MQOMParameterSpec("MQOM2-CAT1-GF16-FAST-R5");
    public static final MQOMParameterSpec mqom2_cat1_gf16_short_r3    = new MQOMParameterSpec("MQOM2-CAT1-GF16-SHORT-R3");
    public static final MQOMParameterSpec mqom2_cat1_gf16_short_r5    = new MQOMParameterSpec("MQOM2-CAT1-GF16-SHORT-R5");
    public static final MQOMParameterSpec mqom2_cat1_gf256_fast_r3    = new MQOMParameterSpec("MQOM2-CAT1-GF256-FAST-R3");
    public static final MQOMParameterSpec mqom2_cat1_gf256_fast_r5    = new MQOMParameterSpec("MQOM2-CAT1-GF256-FAST-R5");
    public static final MQOMParameterSpec mqom2_cat1_gf256_short_r3   = new MQOMParameterSpec("MQOM2-CAT1-GF256-SHORT-R3");
    public static final MQOMParameterSpec mqom2_cat1_gf256_short_r5   = new MQOMParameterSpec("MQOM2-CAT1-GF256-SHORT-R5");

    public static final MQOMParameterSpec mqom2_cat3_gf2_fast_r3      = new MQOMParameterSpec("MQOM2-CAT3-GF2-FAST-R3");
    public static final MQOMParameterSpec mqom2_cat3_gf2_fast_r5      = new MQOMParameterSpec("MQOM2-CAT3-GF2-FAST-R5");
    public static final MQOMParameterSpec mqom2_cat3_gf2_short_r3     = new MQOMParameterSpec("MQOM2-CAT3-GF2-SHORT-R3");
    public static final MQOMParameterSpec mqom2_cat3_gf2_short_r5     = new MQOMParameterSpec("MQOM2-CAT3-GF2-SHORT-R5");
    public static final MQOMParameterSpec mqom2_cat3_gf16_fast_r3     = new MQOMParameterSpec("MQOM2-CAT3-GF16-FAST-R3");
    public static final MQOMParameterSpec mqom2_cat3_gf16_fast_r5     = new MQOMParameterSpec("MQOM2-CAT3-GF16-FAST-R5");
    public static final MQOMParameterSpec mqom2_cat3_gf16_short_r3    = new MQOMParameterSpec("MQOM2-CAT3-GF16-SHORT-R3");
    public static final MQOMParameterSpec mqom2_cat3_gf16_short_r5    = new MQOMParameterSpec("MQOM2-CAT3-GF16-SHORT-R5");
    public static final MQOMParameterSpec mqom2_cat3_gf256_fast_r3    = new MQOMParameterSpec("MQOM2-CAT3-GF256-FAST-R3");
    public static final MQOMParameterSpec mqom2_cat3_gf256_fast_r5    = new MQOMParameterSpec("MQOM2-CAT3-GF256-FAST-R5");
    public static final MQOMParameterSpec mqom2_cat3_gf256_short_r3   = new MQOMParameterSpec("MQOM2-CAT3-GF256-SHORT-R3");
    public static final MQOMParameterSpec mqom2_cat3_gf256_short_r5   = new MQOMParameterSpec("MQOM2-CAT3-GF256-SHORT-R5");

    public static final MQOMParameterSpec mqom2_cat5_gf2_fast_r3      = new MQOMParameterSpec("MQOM2-CAT5-GF2-FAST-R3");
    public static final MQOMParameterSpec mqom2_cat5_gf2_fast_r5      = new MQOMParameterSpec("MQOM2-CAT5-GF2-FAST-R5");
    public static final MQOMParameterSpec mqom2_cat5_gf2_short_r3     = new MQOMParameterSpec("MQOM2-CAT5-GF2-SHORT-R3");
    public static final MQOMParameterSpec mqom2_cat5_gf2_short_r5     = new MQOMParameterSpec("MQOM2-CAT5-GF2-SHORT-R5");
    public static final MQOMParameterSpec mqom2_cat5_gf16_fast_r3     = new MQOMParameterSpec("MQOM2-CAT5-GF16-FAST-R3");
    public static final MQOMParameterSpec mqom2_cat5_gf16_fast_r5     = new MQOMParameterSpec("MQOM2-CAT5-GF16-FAST-R5");
    public static final MQOMParameterSpec mqom2_cat5_gf16_short_r3    = new MQOMParameterSpec("MQOM2-CAT5-GF16-SHORT-R3");
    public static final MQOMParameterSpec mqom2_cat5_gf16_short_r5    = new MQOMParameterSpec("MQOM2-CAT5-GF16-SHORT-R5");
    public static final MQOMParameterSpec mqom2_cat5_gf256_fast_r3    = new MQOMParameterSpec("MQOM2-CAT5-GF256-FAST-R3");
    public static final MQOMParameterSpec mqom2_cat5_gf256_fast_r5    = new MQOMParameterSpec("MQOM2-CAT5-GF256-FAST-R5");
    public static final MQOMParameterSpec mqom2_cat5_gf256_short_r3   = new MQOMParameterSpec("MQOM2-CAT5-GF256-SHORT-R3");
    public static final MQOMParameterSpec mqom2_cat5_gf256_short_r5   = new MQOMParameterSpec("MQOM2-CAT5-GF256-SHORT-R5");

    private static final Map parameters = new HashMap();

    static
    {
        MQOMParameterSpec[] all = new MQOMParameterSpec[]{
            mqom2_cat1_gf2_fast_r3, mqom2_cat1_gf2_fast_r5,
            mqom2_cat1_gf2_short_r3, mqom2_cat1_gf2_short_r5,
            mqom2_cat1_gf16_fast_r3, mqom2_cat1_gf16_fast_r5,
            mqom2_cat1_gf16_short_r3, mqom2_cat1_gf16_short_r5,
            mqom2_cat1_gf256_fast_r3, mqom2_cat1_gf256_fast_r5,
            mqom2_cat1_gf256_short_r3, mqom2_cat1_gf256_short_r5,
            mqom2_cat3_gf2_fast_r3, mqom2_cat3_gf2_fast_r5,
            mqom2_cat3_gf2_short_r3, mqom2_cat3_gf2_short_r5,
            mqom2_cat3_gf16_fast_r3, mqom2_cat3_gf16_fast_r5,
            mqom2_cat3_gf16_short_r3, mqom2_cat3_gf16_short_r5,
            mqom2_cat3_gf256_fast_r3, mqom2_cat3_gf256_fast_r5,
            mqom2_cat3_gf256_short_r3, mqom2_cat3_gf256_short_r5,
            mqom2_cat5_gf2_fast_r3, mqom2_cat5_gf2_fast_r5,
            mqom2_cat5_gf2_short_r3, mqom2_cat5_gf2_short_r5,
            mqom2_cat5_gf16_fast_r3, mqom2_cat5_gf16_fast_r5,
            mqom2_cat5_gf16_short_r3, mqom2_cat5_gf16_short_r5,
            mqom2_cat5_gf256_fast_r3, mqom2_cat5_gf256_fast_r5,
            mqom2_cat5_gf256_short_r3, mqom2_cat5_gf256_short_r5,
        };
        for (int i = 0; i < all.length; i++)
        {
            parameters.put(Strings.toLowerCase(all[i].name), all[i]);
        }
    }

    private final String name;

    private MQOMParameterSpec(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public static MQOMParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }
        MQOMParameterSpec spec = (MQOMParameterSpec)parameters.get(Strings.toLowerCase(name));
        if (spec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }
        return spec;
    }
}
