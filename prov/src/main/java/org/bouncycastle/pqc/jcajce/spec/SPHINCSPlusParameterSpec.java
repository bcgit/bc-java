package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Strings;

/**
 * AlgorithmSpec for SPHINCS+.
 */
public class SPHINCSPlusParameterSpec
    implements AlgorithmParameterSpec
{
    public static final SPHINCSPlusParameterSpec sha256_128f = new SPHINCSPlusParameterSpec("sha256-128f-robust");
    public static final SPHINCSPlusParameterSpec sha256_128s = new SPHINCSPlusParameterSpec("sha256-128s-robust");

    public static final SPHINCSPlusParameterSpec sha256_192f = new SPHINCSPlusParameterSpec("sha256-192f-robust");
    public static final SPHINCSPlusParameterSpec sha256_192s = new SPHINCSPlusParameterSpec("sha256-192s-robust");

    public static final SPHINCSPlusParameterSpec sha256_256f = new SPHINCSPlusParameterSpec("sha256-256f-robust");
    public static final SPHINCSPlusParameterSpec sha256_256s = new SPHINCSPlusParameterSpec("sha256-256s-robust");

    public static final SPHINCSPlusParameterSpec sha256_128f_simple = new SPHINCSPlusParameterSpec("sha256-128s-simple");
    public static final SPHINCSPlusParameterSpec sha256_128s_simple = new SPHINCSPlusParameterSpec("sha256-128f-simple");

    public static final SPHINCSPlusParameterSpec sha256_192f_simple = new SPHINCSPlusParameterSpec("sha256-192f-simple");
    public static final SPHINCSPlusParameterSpec sha256_192s_simple = new SPHINCSPlusParameterSpec("sha256-192s-simple");

    public static final SPHINCSPlusParameterSpec sha256_256f_simple = new SPHINCSPlusParameterSpec("sha256-256f-simple");
    public static final SPHINCSPlusParameterSpec sha256_256s_simple = new SPHINCSPlusParameterSpec("sha256-256s-simple");

    // SHAKE-256.

    public static final SPHINCSPlusParameterSpec shake256_128f = new SPHINCSPlusParameterSpec("shake256-128f-robust");
    public static final SPHINCSPlusParameterSpec shake256_128s = new SPHINCSPlusParameterSpec("shake256-128s-robust");

    public static final SPHINCSPlusParameterSpec shake256_192f = new SPHINCSPlusParameterSpec("shake256-192f-robust");
    public static final SPHINCSPlusParameterSpec shake256_192s = new SPHINCSPlusParameterSpec("shake256-192s-robust");

    public static final SPHINCSPlusParameterSpec shake256_256f = new SPHINCSPlusParameterSpec("shake256-256f-robust");
    public static final SPHINCSPlusParameterSpec shake256_256s = new SPHINCSPlusParameterSpec("shake256-256s-robust");

    public static final SPHINCSPlusParameterSpec shake256_128f_simple = new SPHINCSPlusParameterSpec("shake256-128f-simple");
    public static final SPHINCSPlusParameterSpec shake256_128s_simple = new SPHINCSPlusParameterSpec("shake256-128s-simple");

    public static final SPHINCSPlusParameterSpec shake256_192f_simple = new SPHINCSPlusParameterSpec("shake256-192f-simple");
    public static final SPHINCSPlusParameterSpec shake256_192s_simple = new SPHINCSPlusParameterSpec("shake256-192s-simple");

    public static final SPHINCSPlusParameterSpec shake256_256f_simple = new SPHINCSPlusParameterSpec("shake256-256f-simple");
    public static final SPHINCSPlusParameterSpec shake256_256s_simple = new SPHINCSPlusParameterSpec("shake256-256s-simple");

    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(SPHINCSPlusParameterSpec.sha256_128f.getName(), SPHINCSPlusParameterSpec.sha256_128f);
        parameters.put(SPHINCSPlusParameterSpec.sha256_128s.getName(), SPHINCSPlusParameterSpec.sha256_128s);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192f.getName(), SPHINCSPlusParameterSpec.sha256_192f);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192s.getName(), SPHINCSPlusParameterSpec.sha256_192s);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256f.getName(), SPHINCSPlusParameterSpec.sha256_256f);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256s.getName(), SPHINCSPlusParameterSpec.sha256_256s);
        
        parameters.put(SPHINCSPlusParameterSpec.sha256_128f_simple.getName(), SPHINCSPlusParameterSpec.sha256_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_128s_simple.getName(), SPHINCSPlusParameterSpec.sha256_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192f_simple.getName(), SPHINCSPlusParameterSpec.sha256_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_192s_simple.getName(), SPHINCSPlusParameterSpec.sha256_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256f_simple.getName(), SPHINCSPlusParameterSpec.sha256_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha256_256s_simple.getName(), SPHINCSPlusParameterSpec.sha256_256s_simple);
        
        parameters.put(SPHINCSPlusParameterSpec.shake256_128f.getName(), SPHINCSPlusParameterSpec.shake256_128f);
        parameters.put(SPHINCSPlusParameterSpec.shake256_128s.getName(), SPHINCSPlusParameterSpec.shake256_128s);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192f.getName(), SPHINCSPlusParameterSpec.shake256_192f);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192s.getName(), SPHINCSPlusParameterSpec.shake256_192s);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256f.getName(), SPHINCSPlusParameterSpec.shake256_256f);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256s.getName(), SPHINCSPlusParameterSpec.shake256_256s);
        
        parameters.put(SPHINCSPlusParameterSpec.shake256_128f_simple.getName(), SPHINCSPlusParameterSpec.shake256_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_128s_simple.getName(), SPHINCSPlusParameterSpec.shake256_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192f_simple.getName(), SPHINCSPlusParameterSpec.shake256_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_192s_simple.getName(), SPHINCSPlusParameterSpec.shake256_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256f_simple.getName(), SPHINCSPlusParameterSpec.shake256_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake256_256s_simple.getName(), SPHINCSPlusParameterSpec.shake256_256s_simple);
    }
    
    private final String name;

    private SPHINCSPlusParameterSpec(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }
    
    public static SPHINCSPlusParameterSpec fromName(String name)
    {
        return (SPHINCSPlusParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
