package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.util.Strings;

public class NTRUParameterSpec
    implements AlgorithmParameterSpec
{
    public static final NTRUParameterSpec ntruhps2048509 = new NTRUParameterSpec(NTRUParameters.ntruhps2048509);
    public static final NTRUParameterSpec ntruhps2048677 = new NTRUParameterSpec(NTRUParameters.ntruhps2048677);
    public static final NTRUParameterSpec ntruhps4096821 = new NTRUParameterSpec(NTRUParameters.ntruhps4096821);
    public static final NTRUParameterSpec ntruhrss701 = new NTRUParameterSpec(NTRUParameters.ntruhrss701);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("ntruhps2048509", ntruhps2048509);
        parameters.put("ntruhps2048677", ntruhps2048677);
        parameters.put("ntruhps4096821", ntruhps4096821);
        parameters.put("ntruhrss701", ntruhrss701);
    }

    private final String name;

    private NTRUParameterSpec(NTRUParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }
    public static NTRUParameterSpec fromName(String name)
    {
        return (NTRUParameterSpec) parameters.get(Strings.toLowerCase(name));
    }
}
