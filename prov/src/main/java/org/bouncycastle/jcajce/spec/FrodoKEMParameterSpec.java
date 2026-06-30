package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Strings;

/**
 * AlgorithmSpec for the standardised FrodoKEM (ISO/IEC 18033-2). The salted "FrodoKEM" variant is
 * named frodokem*, the ephemeral "eFrodoKEM" variant efrodokem*; the SHAKE and AES matrix-generation
 * parameter sets at security levels 976 and 1344 are assigned object identifiers by the standard.
 */
public class FrodoKEMParameterSpec
    implements AlgorithmParameterSpec
{
    public static final FrodoKEMParameterSpec frodokem976shake = new FrodoKEMParameterSpec("frodokem976shake");
    public static final FrodoKEMParameterSpec frodokem1344shake = new FrodoKEMParameterSpec("frodokem1344shake");
    public static final FrodoKEMParameterSpec efrodokem976shake = new FrodoKEMParameterSpec("efrodokem976shake");
    public static final FrodoKEMParameterSpec efrodokem1344shake = new FrodoKEMParameterSpec("efrodokem1344shake");
    public static final FrodoKEMParameterSpec frodokem976aes = new FrodoKEMParameterSpec("frodokem976aes");
    public static final FrodoKEMParameterSpec frodokem1344aes = new FrodoKEMParameterSpec("frodokem1344aes");
    public static final FrodoKEMParameterSpec efrodokem976aes = new FrodoKEMParameterSpec("efrodokem976aes");
    public static final FrodoKEMParameterSpec efrodokem1344aes = new FrodoKEMParameterSpec("efrodokem1344aes");

    private static Map parameters = new HashMap();

    static
    {
        parameters.put("frodokem976shake", frodokem976shake);
        parameters.put("frodokem1344shake", frodokem1344shake);
        parameters.put("efrodokem976shake", efrodokem976shake);
        parameters.put("efrodokem1344shake", efrodokem1344shake);
        parameters.put("frodokem976aes", frodokem976aes);
        parameters.put("frodokem1344aes", frodokem1344aes);
        parameters.put("efrodokem976aes", efrodokem976aes);
        parameters.put("efrodokem1344aes", efrodokem1344aes);
    }

    private final String name;

    private FrodoKEMParameterSpec(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }

    public static FrodoKEMParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }

        FrodoKEMParameterSpec parameterSpec = (FrodoKEMParameterSpec)parameters.get(Strings.toLowerCase(name));

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }

        return parameterSpec;
    }
}
