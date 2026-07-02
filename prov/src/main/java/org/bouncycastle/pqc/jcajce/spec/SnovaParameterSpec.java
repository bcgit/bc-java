package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.snova.SnovaParameters;
import org.bouncycastle.util.Strings;

public class SnovaParameterSpec
    implements AlgorithmParameterSpec
{
    public static final SnovaParameterSpec SNOVA_24_5_4_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_24_5_4_SSK);
    public static final SnovaParameterSpec SNOVA_24_5_4_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_24_5_4_ESK);
    public static final SnovaParameterSpec SNOVA_24_5_4_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_24_5_4_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_24_5_4_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_24_5_4_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_24_5_5_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_24_5_5_SSK);
    public static final SnovaParameterSpec SNOVA_24_5_5_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_24_5_5_ESK);
    public static final SnovaParameterSpec SNOVA_24_5_5_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_24_5_5_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_24_5_5_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_24_5_5_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_25_8_3_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_25_8_3_SSK);
    public static final SnovaParameterSpec SNOVA_25_8_3_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_25_8_3_ESK);
    public static final SnovaParameterSpec SNOVA_25_8_3_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_25_8_3_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_25_8_3_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_25_8_3_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_29_6_5_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_29_6_5_SSK);
    public static final SnovaParameterSpec SNOVA_29_6_5_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_29_6_5_ESK);
    public static final SnovaParameterSpec SNOVA_29_6_5_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_29_6_5_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_29_6_5_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_29_6_5_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_37_8_4_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_37_8_4_SSK);
    public static final SnovaParameterSpec SNOVA_37_8_4_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_37_8_4_ESK);
    public static final SnovaParameterSpec SNOVA_37_8_4_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_37_8_4_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_37_8_4_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_37_8_4_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_37_17_2_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_37_17_2_SSK);
    public static final SnovaParameterSpec SNOVA_37_17_2_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_37_17_2_ESK);
    public static final SnovaParameterSpec SNOVA_37_17_2_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_37_17_2_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_37_17_2_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_37_17_2_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_49_11_3_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_49_11_3_SSK);
    public static final SnovaParameterSpec SNOVA_49_11_3_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_49_11_3_ESK);
    public static final SnovaParameterSpec SNOVA_49_11_3_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_49_11_3_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_49_11_3_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_49_11_3_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_56_25_2_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_56_25_2_SSK);
    public static final SnovaParameterSpec SNOVA_56_25_2_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_56_25_2_ESK);
    public static final SnovaParameterSpec SNOVA_56_25_2_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_56_25_2_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_56_25_2_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_56_25_2_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_60_10_4_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_60_10_4_SSK);
    public static final SnovaParameterSpec SNOVA_60_10_4_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_60_10_4_ESK);
    public static final SnovaParameterSpec SNOVA_60_10_4_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_60_10_4_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_60_10_4_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_60_10_4_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_66_15_3_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_66_15_3_SSK);
    public static final SnovaParameterSpec SNOVA_66_15_3_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_66_15_3_ESK);
    public static final SnovaParameterSpec SNOVA_66_15_3_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_66_15_3_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_66_15_3_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_66_15_3_SHAKE_ESK);

    public static final SnovaParameterSpec SNOVA_75_33_2_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_75_33_2_SSK);
    public static final SnovaParameterSpec SNOVA_75_33_2_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_75_33_2_ESK);
    public static final SnovaParameterSpec SNOVA_75_33_2_SHAKE_SSK = new SnovaParameterSpec(SnovaParameters.SNOVA_75_33_2_SHAKE_SSK);
    public static final SnovaParameterSpec SNOVA_75_33_2_SHAKE_ESK = new SnovaParameterSpec(SnovaParameters.SNOVA_75_33_2_SHAKE_ESK);


    private static Map parameters = new HashMap();

    static
    {
        // fromName(name) looks up Strings.toLowerCase(name), but the SnovaParameters
        // names are upper-case (e.g. "SNOVA_24_5_4_SSK"); key by the lower-cased name so
        // fromName(getName()) round-trips. Same shape as MQOMParameterSpec.
        SnovaParameterSpec[] all = new SnovaParameterSpec[]{
            SNOVA_24_5_4_SSK, SNOVA_24_5_4_ESK, SNOVA_24_5_4_SHAKE_SSK, SNOVA_24_5_4_SHAKE_ESK,
            SNOVA_24_5_5_SSK, SNOVA_24_5_5_ESK, SNOVA_24_5_5_SHAKE_SSK, SNOVA_24_5_5_SHAKE_ESK,
            SNOVA_25_8_3_SSK, SNOVA_25_8_3_ESK, SNOVA_25_8_3_SHAKE_SSK, SNOVA_25_8_3_SHAKE_ESK,
            SNOVA_29_6_5_SSK, SNOVA_29_6_5_ESK, SNOVA_29_6_5_SHAKE_SSK, SNOVA_29_6_5_SHAKE_ESK,
            SNOVA_37_8_4_SSK, SNOVA_37_8_4_ESK, SNOVA_37_8_4_SHAKE_SSK, SNOVA_37_8_4_SHAKE_ESK,
            SNOVA_37_17_2_SSK, SNOVA_37_17_2_ESK, SNOVA_37_17_2_SHAKE_SSK, SNOVA_37_17_2_SHAKE_ESK,
            SNOVA_49_11_3_SSK, SNOVA_49_11_3_ESK, SNOVA_49_11_3_SHAKE_SSK, SNOVA_49_11_3_SHAKE_ESK,
            SNOVA_56_25_2_SSK, SNOVA_56_25_2_ESK, SNOVA_56_25_2_SHAKE_SSK, SNOVA_56_25_2_SHAKE_ESK,
            SNOVA_60_10_4_SSK, SNOVA_60_10_4_ESK, SNOVA_60_10_4_SHAKE_SSK, SNOVA_60_10_4_SHAKE_ESK,
            SNOVA_66_15_3_SSK, SNOVA_66_15_3_ESK, SNOVA_66_15_3_SHAKE_SSK, SNOVA_66_15_3_SHAKE_ESK,
            SNOVA_75_33_2_SSK, SNOVA_75_33_2_ESK, SNOVA_75_33_2_SHAKE_SSK, SNOVA_75_33_2_SHAKE_ESK,
        };
        for (int i = 0; i < all.length; i++)
        {
            parameters.put(Strings.toLowerCase(all[i].name), all[i]);
        }
    }

    private final String name;

    private SnovaParameterSpec(SnovaParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static SnovaParameterSpec fromName(String name)
    {
        return (SnovaParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
