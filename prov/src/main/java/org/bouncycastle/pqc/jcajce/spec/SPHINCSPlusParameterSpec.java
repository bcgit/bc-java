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
    public static final SPHINCSPlusParameterSpec sha2_128f = new SPHINCSPlusParameterSpec("sha2-128f-robust");
    public static final SPHINCSPlusParameterSpec sha2_128s = new SPHINCSPlusParameterSpec("sha2-128s-robust");

    public static final SPHINCSPlusParameterSpec sha2_192f = new SPHINCSPlusParameterSpec("sha2-192f-robust");
    public static final SPHINCSPlusParameterSpec sha2_192s = new SPHINCSPlusParameterSpec("sha2-192s-robust");

    public static final SPHINCSPlusParameterSpec sha2_256f = new SPHINCSPlusParameterSpec("sha2-256f-robust");
    public static final SPHINCSPlusParameterSpec sha2_256s = new SPHINCSPlusParameterSpec("sha2-256s-robust");

    public static final SPHINCSPlusParameterSpec sha2_128f_simple = new SPHINCSPlusParameterSpec("sha2-128s-simple");
    public static final SPHINCSPlusParameterSpec sha2_128s_simple = new SPHINCSPlusParameterSpec("sha2-128f-simple");

    public static final SPHINCSPlusParameterSpec sha2_192f_simple = new SPHINCSPlusParameterSpec("sha2-192f-simple");
    public static final SPHINCSPlusParameterSpec sha2_192s_simple = new SPHINCSPlusParameterSpec("sha2-192s-simple");

    public static final SPHINCSPlusParameterSpec sha2_256f_simple = new SPHINCSPlusParameterSpec("sha2-256f-simple");
    public static final SPHINCSPlusParameterSpec sha2_256s_simple = new SPHINCSPlusParameterSpec("sha2-256s-simple");

    // SHAKE-256.

    public static final SPHINCSPlusParameterSpec shake_128f = new SPHINCSPlusParameterSpec("shake-128f-robust");
    public static final SPHINCSPlusParameterSpec shake_128s = new SPHINCSPlusParameterSpec("shake-128s-robust");

    public static final SPHINCSPlusParameterSpec shake_192f = new SPHINCSPlusParameterSpec("shake-192f-robust");
    public static final SPHINCSPlusParameterSpec shake_192s = new SPHINCSPlusParameterSpec("shake-192s-robust");

    public static final SPHINCSPlusParameterSpec shake_256f = new SPHINCSPlusParameterSpec("shake-256f-robust");
    public static final SPHINCSPlusParameterSpec shake_256s = new SPHINCSPlusParameterSpec("shake-256s-robust");

    public static final SPHINCSPlusParameterSpec shake_128f_simple = new SPHINCSPlusParameterSpec("shake-128f-simple");
    public static final SPHINCSPlusParameterSpec shake_128s_simple = new SPHINCSPlusParameterSpec("shake-128s-simple");

    public static final SPHINCSPlusParameterSpec shake_192f_simple = new SPHINCSPlusParameterSpec("shake-192f-simple");
    public static final SPHINCSPlusParameterSpec shake_192s_simple = new SPHINCSPlusParameterSpec("shake-192s-simple");

    public static final SPHINCSPlusParameterSpec shake_256f_simple = new SPHINCSPlusParameterSpec("shake-256f-simple");
    public static final SPHINCSPlusParameterSpec shake_256s_simple = new SPHINCSPlusParameterSpec("shake-256s-simple");

    private static Map parameters = new HashMap();
    
    static
    {
        parameters.put(SPHINCSPlusParameterSpec.sha2_128f.getName(), SPHINCSPlusParameterSpec.sha2_128f);
        parameters.put(SPHINCSPlusParameterSpec.sha2_128s.getName(), SPHINCSPlusParameterSpec.sha2_128s);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192f.getName(), SPHINCSPlusParameterSpec.sha2_192f);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192s.getName(), SPHINCSPlusParameterSpec.sha2_192s);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256f.getName(), SPHINCSPlusParameterSpec.sha2_256f);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256s.getName(), SPHINCSPlusParameterSpec.sha2_256s);
        
        parameters.put(SPHINCSPlusParameterSpec.sha2_128f_simple.getName(), SPHINCSPlusParameterSpec.sha2_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha2_128s_simple.getName(), SPHINCSPlusParameterSpec.sha2_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192f_simple.getName(), SPHINCSPlusParameterSpec.sha2_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192s_simple.getName(), SPHINCSPlusParameterSpec.sha2_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256f_simple.getName(), SPHINCSPlusParameterSpec.sha2_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256s_simple.getName(), SPHINCSPlusParameterSpec.sha2_256s_simple);
        
        parameters.put(SPHINCSPlusParameterSpec.shake_128f.getName(), SPHINCSPlusParameterSpec.shake_128f);
        parameters.put(SPHINCSPlusParameterSpec.shake_128s.getName(), SPHINCSPlusParameterSpec.shake_128s);
        parameters.put(SPHINCSPlusParameterSpec.shake_192f.getName(), SPHINCSPlusParameterSpec.shake_192f);
        parameters.put(SPHINCSPlusParameterSpec.shake_192s.getName(), SPHINCSPlusParameterSpec.shake_192s);
        parameters.put(SPHINCSPlusParameterSpec.shake_256f.getName(), SPHINCSPlusParameterSpec.shake_256f);
        parameters.put(SPHINCSPlusParameterSpec.shake_256s.getName(), SPHINCSPlusParameterSpec.shake_256s);
        
        parameters.put(SPHINCSPlusParameterSpec.shake_128f_simple.getName(), SPHINCSPlusParameterSpec.shake_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake_128s_simple.getName(), SPHINCSPlusParameterSpec.shake_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake_192f_simple.getName(), SPHINCSPlusParameterSpec.shake_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake_192s_simple.getName(), SPHINCSPlusParameterSpec.shake_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake_256f_simple.getName(), SPHINCSPlusParameterSpec.shake_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.shake_256s_simple.getName(), SPHINCSPlusParameterSpec.shake_256s_simple);
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
