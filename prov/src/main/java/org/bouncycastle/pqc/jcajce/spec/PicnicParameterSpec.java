package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.util.Strings;

public class PicnicParameterSpec
        implements AlgorithmParameterSpec
{
    public static final PicnicParameterSpec picnicl1fs = new PicnicParameterSpec(PicnicParameters.picnicl1fs);
    public static final PicnicParameterSpec picnicl1ur = new PicnicParameterSpec(PicnicParameters.picnicl1ur);
    public static final PicnicParameterSpec picnicl3fs = new PicnicParameterSpec(PicnicParameters.picnicl3fs);
    public static final PicnicParameterSpec picnicl3ur = new PicnicParameterSpec(PicnicParameters.picnicl3ur);
    public static final PicnicParameterSpec picnicl5fs = new PicnicParameterSpec(PicnicParameters.picnicl5fs);
    public static final PicnicParameterSpec picnicl5ur = new PicnicParameterSpec(PicnicParameters.picnicl5ur);
    public static final PicnicParameterSpec picnic3l1 = new PicnicParameterSpec(PicnicParameters.picnic3l1);
    public static final PicnicParameterSpec picnic3l3 = new PicnicParameterSpec(PicnicParameters.picnic3l3);
    public static final PicnicParameterSpec picnic3l5 = new PicnicParameterSpec(PicnicParameters.picnic3l5);
    public static final PicnicParameterSpec picnicl1full = new PicnicParameterSpec(PicnicParameters.picnicl1full);
    public static final PicnicParameterSpec picnicl3full = new PicnicParameterSpec(PicnicParameters.picnicl3full);
    public static final PicnicParameterSpec picnicl5full = new PicnicParameterSpec(PicnicParameters.picnicl5full);

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("picnicl1fs", picnicl1fs);
        parameters.put("picnicl1ur", picnicl1ur);
        parameters.put("picnicl3fs", picnicl3fs);
        parameters.put("picnicl3ur", picnicl3ur);
        parameters.put("picnicl5fs", picnicl5fs);
        parameters.put("picnicl5ur", picnicl5ur);
        parameters.put("picnic3l1", picnic3l1);
        parameters.put("picnic3l3", picnic3l3);
        parameters.put("picnic3l5", picnic3l5);
        parameters.put("picnicl1full", picnicl1full);
        parameters.put("picnicl3full", picnicl3full);
        parameters.put("picnicl5full", picnicl5full);
    }

    private final String name;

    private PicnicParameterSpec(PicnicParameters parameters)
    {
        this.name = parameters.getName();
    }

    public String getName()
    {
        return name;
    }

    public static PicnicParameterSpec fromName(String name)
    {
        return (PicnicParameterSpec) parameters.get(Strings.toLowerCase(name));
    }
}
