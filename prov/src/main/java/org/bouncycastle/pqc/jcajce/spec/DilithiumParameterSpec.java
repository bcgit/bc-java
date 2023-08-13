package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.util.Strings;

public class DilithiumParameterSpec
    implements AlgorithmParameterSpec
{
    public static final DilithiumParameterSpec dilithium2 = new DilithiumParameterSpec(DilithiumParameters.dilithium2);
    public static final DilithiumParameterSpec dilithium3 = new DilithiumParameterSpec(DilithiumParameters.dilithium3);
    public static final DilithiumParameterSpec dilithium5 = new DilithiumParameterSpec(DilithiumParameters.dilithium5);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("dilithium2", dilithium2);
        parameters.put("dilithium3", dilithium3);
        parameters.put("dilithium5", dilithium5);
    }

    private final String name;

    private DilithiumParameterSpec(DilithiumParameters parameters)
    {
        this.name = Strings.toUpperCase(parameters.getName());
    }

    public String getName()
    {
        return name;
    }

    public static DilithiumParameterSpec fromName(String name)
    {
        return (DilithiumParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
