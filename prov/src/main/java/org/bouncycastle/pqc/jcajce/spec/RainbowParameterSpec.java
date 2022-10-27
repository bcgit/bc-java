package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.util.Strings;

public class RainbowParameterSpec
    implements AlgorithmParameterSpec
{
    public static final RainbowParameterSpec rainbowIIIclassic = new RainbowParameterSpec(RainbowParameters.rainbowIIIclassic);
    public static final RainbowParameterSpec rainbowIIIcircumzenithal = new RainbowParameterSpec(RainbowParameters.rainbowIIIcircumzenithal);
    public static final RainbowParameterSpec rainbowIIIcompressed = new RainbowParameterSpec(RainbowParameters.rainbowIIIcompressed);

    public static final RainbowParameterSpec rainbowVclassic = new RainbowParameterSpec(RainbowParameters.rainbowVclassic);
    public static final RainbowParameterSpec rainbowVcircumzenithal = new RainbowParameterSpec(RainbowParameters.rainbowVcircumzenithal);
    public static final RainbowParameterSpec rainbowVcompressed = new RainbowParameterSpec(RainbowParameters.rainbowVcompressed);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("rainbow-iii-classic", rainbowIIIclassic);
        parameters.put("rainbow-iii-circumzenithal", rainbowIIIcircumzenithal);
        parameters.put("rainbow-iii-compressed", rainbowIIIcompressed);
        parameters.put("rainbow-v-classic", rainbowVclassic);
        parameters.put("rainbow-v-circumzenithal", rainbowVcircumzenithal);
        parameters.put("rainbow-v-compressed", rainbowVcompressed);
    }

    private final String name;

    private RainbowParameterSpec(RainbowParameters parameters)
    {
        this.name = Strings.toUpperCase(parameters.getName());
    }

    public String getName()
    {
        return name;
    }

    public static RainbowParameterSpec fromName(String name)
    {
        return (RainbowParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
