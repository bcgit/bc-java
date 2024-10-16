package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Strings;

/**
 * AlgorithmSpec for SLH-DSA
 */
public class SLHDSAParameterSpec
    implements AlgorithmParameterSpec
{
    public static final SLHDSAParameterSpec slh_dsa_sha2_128f = new SLHDSAParameterSpec("slh-dsa-sha2-128f");
    public static final SLHDSAParameterSpec slh_dsa_sha2_128s = new SLHDSAParameterSpec("slh-dsa-sha2-128s");

    public static final SLHDSAParameterSpec slh_dsa_sha2_192f = new SLHDSAParameterSpec("slh-dsa-sha2-192f");
    public static final SLHDSAParameterSpec slh_dsa_sha2_192s = new SLHDSAParameterSpec("slh-dsa-sha2-192s");

    public static final SLHDSAParameterSpec slh_dsa_sha2_256f = new SLHDSAParameterSpec("slh-dsa-sha2-256f");
    public static final SLHDSAParameterSpec slh_dsa_sha2_256s = new SLHDSAParameterSpec("slh-dsa-sha2-256s");

    // SHAKE-256.

    public static final SLHDSAParameterSpec slh_dsa_shake_128f = new SLHDSAParameterSpec("slh-dsa-shake-128f");
    public static final SLHDSAParameterSpec slh_dsa_shake_128s = new SLHDSAParameterSpec("slh-dsa-shake-128s");

    public static final SLHDSAParameterSpec slh_dsa_shake_192f = new SLHDSAParameterSpec("slh-dsa-shake-192f");
    public static final SLHDSAParameterSpec slh_dsa_shake_192s = new SLHDSAParameterSpec("slh-dsa-shake-192s");

    public static final SLHDSAParameterSpec slh_dsa_shake_256f = new SLHDSAParameterSpec("slh-dsa-shake-256f");
    public static final SLHDSAParameterSpec slh_dsa_shake_256s = new SLHDSAParameterSpec("slh-dsa-shake-256s");

    // PREHASH
    public static final SLHDSAParameterSpec slh_dsa_sha2_128f_with_sha256 = new SLHDSAParameterSpec("slh-dsa-sha2-128f-with-sha256");
    public static final SLHDSAParameterSpec slh_dsa_sha2_128s_with_sha256 = new SLHDSAParameterSpec("slh-dsa-sha2-128s-with-sha256");

    public static final SLHDSAParameterSpec slh_dsa_sha2_192f_with_sha512 = new SLHDSAParameterSpec("slh-dsa-sha2-192f-with-sha512");
    public static final SLHDSAParameterSpec slh_dsa_sha2_192s_with_sha512 = new SLHDSAParameterSpec("slh-dsa-sha2-192s-with-sha512");

    public static final SLHDSAParameterSpec slh_dsa_sha2_256f_with_sha512 = new SLHDSAParameterSpec("slh-dsa-sha2-256f-with-sha512");
    public static final SLHDSAParameterSpec slh_dsa_sha2_256s_with_sha512 = new SLHDSAParameterSpec("slh-dsa-sha2-256s-with-sha512");

    // SHAKE-256.

    public static final SLHDSAParameterSpec slh_dsa_shake_128f_with_shake128 = new SLHDSAParameterSpec("slh-dsa-shake-128f-with-shake128");
    public static final SLHDSAParameterSpec slh_dsa_shake_128s_with_shake128 = new SLHDSAParameterSpec("slh-dsa-shake-128s-with-shake128");

    public static final SLHDSAParameterSpec slh_dsa_shake_192f_with_shake256 = new SLHDSAParameterSpec("slh-dsa-shake-192f-with-shake256");
    public static final SLHDSAParameterSpec slh_dsa_shake_192s_with_shake256 = new SLHDSAParameterSpec("slh-dsa-shake-192s-with-shake256");

    public static final SLHDSAParameterSpec slh_dsa_shake_256f_with_shake256 = new SLHDSAParameterSpec("slh-dsa-shake-256f-with-shake256");
    public static final SLHDSAParameterSpec slh_dsa_shake_256s_with_shake256 = new SLHDSAParameterSpec("slh-dsa-shake-256s-with-shake256");

    private static Map parameters = new HashMap();

    static
    {
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128f.getName(), SLHDSAParameterSpec.slh_dsa_sha2_128f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128s.getName(), SLHDSAParameterSpec.slh_dsa_sha2_128s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192f.getName(), SLHDSAParameterSpec.slh_dsa_sha2_192f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192s.getName(), SLHDSAParameterSpec.slh_dsa_sha2_192s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256f.getName(), SLHDSAParameterSpec.slh_dsa_sha2_256f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256s.getName(), SLHDSAParameterSpec.slh_dsa_sha2_256s);

        parameters.put("sha2-128f", SLHDSAParameterSpec.slh_dsa_sha2_128f);
        parameters.put("sha2-128s", SLHDSAParameterSpec.slh_dsa_sha2_128s);
        parameters.put("sha2-192f", SLHDSAParameterSpec.slh_dsa_sha2_192f);
        parameters.put("sha2-192s", SLHDSAParameterSpec.slh_dsa_sha2_192s);
        parameters.put("sha2-256f", SLHDSAParameterSpec.slh_dsa_sha2_256f);
        parameters.put("sha2-256s", SLHDSAParameterSpec.slh_dsa_sha2_256s);

        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128f.getName(), SLHDSAParameterSpec.slh_dsa_shake_128f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128s.getName(), SLHDSAParameterSpec.slh_dsa_shake_128s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192f.getName(), SLHDSAParameterSpec.slh_dsa_shake_192f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192s.getName(), SLHDSAParameterSpec.slh_dsa_shake_192s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256f.getName(), SLHDSAParameterSpec.slh_dsa_shake_256f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256s.getName(), SLHDSAParameterSpec.slh_dsa_shake_256s);

        parameters.put("shake-128f", SLHDSAParameterSpec.slh_dsa_shake_128f);
        parameters.put("shake-128s", SLHDSAParameterSpec.slh_dsa_shake_128s);
        parameters.put("shake-192f", SLHDSAParameterSpec.slh_dsa_shake_192f);
        parameters.put("shake-192s", SLHDSAParameterSpec.slh_dsa_shake_192s);
        parameters.put("shake-256f", SLHDSAParameterSpec.slh_dsa_shake_256f);
        parameters.put("shake-256s", SLHDSAParameterSpec.slh_dsa_shake_256s);

        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256.getName(), SLHDSAParameterSpec.slh_dsa_sha2_128f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256.getName(), SLHDSAParameterSpec.slh_dsa_sha2_128s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512.getName(), SLHDSAParameterSpec.slh_dsa_sha2_192f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512.getName(), SLHDSAParameterSpec.slh_dsa_sha2_192s);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512.getName(), SLHDSAParameterSpec.slh_dsa_sha2_256f);
        parameters.put(SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512.getName(), SLHDSAParameterSpec.slh_dsa_sha2_256s);

        parameters.put("sha2-128f-with-sha256", SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256);
        parameters.put("sha2-128s-with-sha256", SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256);
        parameters.put("sha2-192f-with-sha512", SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512);
        parameters.put("sha2-192s-with-sha512", SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512);
        parameters.put("sha2-256f-with-sha512", SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512);
        parameters.put("sha2-256s-with-sha512", SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512);

        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128.getName(), SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128.getName(), SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256.getName(), SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256.getName(), SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256.getName(), SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256);
        parameters.put(SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256.getName(), SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256);

        parameters.put("shake-128f-with-shake128", SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128);
        parameters.put("shake-128s-with-shake128", SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128);
        parameters.put("shake-192f-with-shake256", SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256);
        parameters.put("shake-192s-with-shake256", SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256);
        parameters.put("shake-256f-with-shake256", SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256);
        parameters.put("shake-256s-with-shake256", SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256);

    }

    private final String name;

    private SLHDSAParameterSpec(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public static SLHDSAParameterSpec fromName(String name)
    {
        return (SLHDSAParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
