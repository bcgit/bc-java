package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Strings;

/**
 * AlgorithmSpec for SDitH (Syndrome-Decoding-in-the-Head), exposed via the
 * BCPQC provider.
 * <p>
 * Currently only the {@code SDITH-HYPERCUBE-CAT1-GF256} parameter set is
 * wired in; the other 23 NIST-submitted variants (hypercube/threshold &times;
 * cat1/3/5 &times; gf256/p251) will be added as their implementations come in.
 */
public class SDitHParameterSpec
    implements AlgorithmParameterSpec
{
    public static final SDitHParameterSpec sdith_hypercube_cat1_gf256 = new SDitHParameterSpec("SDITH-HYPERCUBE-CAT1-GF256");
    public static final SDitHParameterSpec sdith_hypercube_cat3_gf256 = new SDitHParameterSpec("SDITH-HYPERCUBE-CAT3-GF256");
    public static final SDitHParameterSpec sdith_hypercube_cat5_gf256 = new SDitHParameterSpec("SDITH-HYPERCUBE-CAT5-GF256");
    public static final SDitHParameterSpec sdith_hypercube_cat1_p251  = new SDitHParameterSpec("SDITH-HYPERCUBE-CAT1-P251");
    public static final SDitHParameterSpec sdith_hypercube_cat3_p251  = new SDitHParameterSpec("SDITH-HYPERCUBE-CAT3-P251");
    public static final SDitHParameterSpec sdith_hypercube_cat5_p251  = new SDitHParameterSpec("SDITH-HYPERCUBE-CAT5-P251");
    public static final SDitHParameterSpec sdith_threshold_cat1_gf256 = new SDitHParameterSpec("SDITH-THRESHOLD-CAT1-GF256");
    public static final SDitHParameterSpec sdith_threshold_cat3_gf256 = new SDitHParameterSpec("SDITH-THRESHOLD-CAT3-GF256");
    public static final SDitHParameterSpec sdith_threshold_cat5_gf256 = new SDitHParameterSpec("SDITH-THRESHOLD-CAT5-GF256");
    public static final SDitHParameterSpec sdith_threshold_cat1_p251  = new SDitHParameterSpec("SDITH-THRESHOLD-CAT1-P251");
    public static final SDitHParameterSpec sdith_threshold_cat3_p251  = new SDitHParameterSpec("SDITH-THRESHOLD-CAT3-P251");
    public static final SDitHParameterSpec sdith_threshold_cat5_p251  = new SDitHParameterSpec("SDITH-THRESHOLD-CAT5-P251");

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("sdith-hypercube-cat1-gf256", sdith_hypercube_cat1_gf256);
        parameters.put("sdith-hypercube-cat3-gf256", sdith_hypercube_cat3_gf256);
        parameters.put("sdith-hypercube-cat5-gf256", sdith_hypercube_cat5_gf256);
        parameters.put("sdith-hypercube-cat1-p251",  sdith_hypercube_cat1_p251);
        parameters.put("sdith-hypercube-cat3-p251",  sdith_hypercube_cat3_p251);
        parameters.put("sdith-hypercube-cat5-p251",  sdith_hypercube_cat5_p251);
        parameters.put("sdith-threshold-cat1-gf256", sdith_threshold_cat1_gf256);
        parameters.put("sdith-threshold-cat3-gf256", sdith_threshold_cat3_gf256);
        parameters.put("sdith-threshold-cat5-gf256", sdith_threshold_cat5_gf256);
        parameters.put("sdith-threshold-cat1-p251",  sdith_threshold_cat1_p251);
        parameters.put("sdith-threshold-cat3-p251",  sdith_threshold_cat3_p251);
        parameters.put("sdith-threshold-cat5-p251",  sdith_threshold_cat5_p251);
    }

    private final String name;

    private SDitHParameterSpec(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public static SDitHParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }
        SDitHParameterSpec spec = (SDitHParameterSpec)parameters.get(Strings.toLowerCase(name));
        if (spec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }
        return spec;
    }
}
