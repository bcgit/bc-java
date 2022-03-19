package org.bouncycastle.pqc.crypto.sphincsplus;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

public class SPHINCSPlusParameters
{
    public static final SPHINCSPlusParameters sha256_128f = new SPHINCSPlusParameters("sha256-128f-robust", new SPHINCSPlusEngine.Sha256Engine(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha256_128s = new SPHINCSPlusParameters("sha256-128s-robust", new SPHINCSPlusEngine.Sha256Engine(true, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters sha256_192f = new SPHINCSPlusParameters("sha256-192f-robust", new SPHINCSPlusEngine.Sha256Engine(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha256_192s = new SPHINCSPlusParameters("sha256-192s-robust", new SPHINCSPlusEngine.Sha256Engine(true, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters sha256_256f = new SPHINCSPlusParameters("sha256-256f-robust", new SPHINCSPlusEngine.Sha256Engine(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha256_256s = new SPHINCSPlusParameters("sha256-256s-robust", new SPHINCSPlusEngine.Sha256Engine(true, 32, 16, 8, 14, 22, 64));

    public static final SPHINCSPlusParameters sha256_128f_simple = new SPHINCSPlusParameters("sha256-128f-simple", new SPHINCSPlusEngine.Sha256Engine(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha256_128s_simple = new SPHINCSPlusParameters("sha256-128s-simple", new SPHINCSPlusEngine.Sha256Engine(false, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters sha256_192f_simple = new SPHINCSPlusParameters("sha256-192f-simple", new SPHINCSPlusEngine.Sha256Engine(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha256_192s_simple = new SPHINCSPlusParameters("sha256-192s-simple", new SPHINCSPlusEngine.Sha256Engine(false, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters sha256_256f_simple = new SPHINCSPlusParameters("sha256-256f-simple", new SPHINCSPlusEngine.Sha256Engine(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha256_256s_simple = new SPHINCSPlusParameters("sha256-256s-simple", new SPHINCSPlusEngine.Sha256Engine(false, 32, 16, 8, 14, 22, 64));

    // SHAKE-256.

    public static final SPHINCSPlusParameters shake256_128f = new SPHINCSPlusParameters("shake256-128f-robust", new SPHINCSPlusEngine.Shake256Engine(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake256_128s = new SPHINCSPlusParameters("shake256-128s-robust", new SPHINCSPlusEngine.Shake256Engine(true, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters shake256_192f = new SPHINCSPlusParameters("shake256-192f-robust", new SPHINCSPlusEngine.Shake256Engine(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake256_192s = new SPHINCSPlusParameters("shake256-192s-robust", new SPHINCSPlusEngine.Shake256Engine(true, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters shake256_256f = new SPHINCSPlusParameters("shake256-256f-robust", new SPHINCSPlusEngine.Shake256Engine(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake256_256s = new SPHINCSPlusParameters("shake256-256s-robust", new SPHINCSPlusEngine.Shake256Engine(true, 32, 16, 8, 14, 22, 64));

    public static final SPHINCSPlusParameters shake256_128f_simple = new SPHINCSPlusParameters("shake256-128f-simple", new SPHINCSPlusEngine.Shake256Engine(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake256_128s_simple = new SPHINCSPlusParameters("shake256-128s-simple", new SPHINCSPlusEngine.Shake256Engine(false, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters shake256_192f_simple = new SPHINCSPlusParameters("shake256-192f-simple", new SPHINCSPlusEngine.Shake256Engine(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake256_192s_simple = new SPHINCSPlusParameters("shake256-192s-simple", new SPHINCSPlusEngine.Shake256Engine(false, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters shake256_256f_simple = new SPHINCSPlusParameters("shake256-256f-simple", new SPHINCSPlusEngine.Shake256Engine(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake256_256s_simple = new SPHINCSPlusParameters("shake256-256s-simple", new SPHINCSPlusEngine.Shake256Engine(false, 32, 16, 8, 14, 22, 64));

    private static final Integer sphincsPlus_sha256_128f_robust = Integers.valueOf(0x010101);
    private static final Integer sphincsPlus_sha256_128s_robust = Integers.valueOf(0x010102);
    private static final Integer sphincsPlus_sha256_192f_robust = Integers.valueOf(0x010103);
    private static final Integer sphincsPlus_sha256_192s_robust = Integers.valueOf(0x010104);
    private static final Integer sphincsPlus_sha256_256f_robust = Integers.valueOf(0x010105);
    private static final Integer sphincsPlus_sha256_256s_robust = Integers.valueOf(0x010106);

    private static final Integer sphincsPlus_sha256_128f_simple = Integers.valueOf(0x010201);
    private static final Integer sphincsPlus_sha256_128s_simple = Integers.valueOf(0x010202);
    private static final Integer sphincsPlus_sha256_192f_simple = Integers.valueOf(0x010203);
    private static final Integer sphincsPlus_sha256_192s_simple = Integers.valueOf(0x010204);
    private static final Integer sphincsPlus_sha256_256f_simple = Integers.valueOf(0x010205);
    private static final Integer sphincsPlus_sha256_256s_simple = Integers.valueOf(0x010206);

    private static final Integer sphincsPlus_shake256_128f_robust = Integers.valueOf(0x020101);
    private static final Integer sphincsPlus_shake256_128s_robust = Integers.valueOf(0x020102);
    private static final Integer sphincsPlus_shake256_192f_robust = Integers.valueOf(0x020103);
    private static final Integer sphincsPlus_shake256_192s_robust = Integers.valueOf(0x020104);
    private static final Integer sphincsPlus_shake256_256f_robust = Integers.valueOf(0x020105);
    private static final Integer sphincsPlus_shake256_256s_robust = Integers.valueOf(0x020106);

    private static final Integer sphincsPlus_shake256_128f_simple = Integers.valueOf(0x020201);
    private static final Integer sphincsPlus_shake256_128s_simple = Integers.valueOf(0x020202);
    private static final Integer sphincsPlus_shake256_192f_simple = Integers.valueOf(0x020203);
    private static final Integer sphincsPlus_shake256_192s_simple = Integers.valueOf(0x020204);
    private static final Integer sphincsPlus_shake256_256f_simple = Integers.valueOf(0x020205);
    private static final Integer sphincsPlus_shake256_256s_simple = Integers.valueOf(0x020206);

    private static final Map oidToParams = new HashMap();
    private static final Map paramsToOid = new HashMap();

    static
    {
        oidToParams.put(sphincsPlus_sha256_128f_robust, SPHINCSPlusParameters.sha256_128f);
        oidToParams.put(sphincsPlus_sha256_128s_robust, SPHINCSPlusParameters.sha256_128s);
        oidToParams.put(sphincsPlus_sha256_192f_robust, SPHINCSPlusParameters.sha256_192f);
        oidToParams.put(sphincsPlus_sha256_192s_robust, SPHINCSPlusParameters.sha256_192s);
        oidToParams.put(sphincsPlus_sha256_256f_robust, SPHINCSPlusParameters.sha256_256f);
        oidToParams.put(sphincsPlus_sha256_256s_robust, SPHINCSPlusParameters.sha256_256s);

        oidToParams.put(sphincsPlus_sha256_128f_simple, SPHINCSPlusParameters.sha256_128f_simple);
        oidToParams.put(sphincsPlus_sha256_128s_simple, SPHINCSPlusParameters.sha256_128s_simple);
        oidToParams.put(sphincsPlus_sha256_192f_simple, SPHINCSPlusParameters.sha256_192f_simple);
        oidToParams.put(sphincsPlus_sha256_192s_simple, SPHINCSPlusParameters.sha256_192s_simple);
        oidToParams.put(sphincsPlus_sha256_256f_simple, SPHINCSPlusParameters.sha256_256f_simple);
        oidToParams.put(sphincsPlus_sha256_256s_simple, SPHINCSPlusParameters.sha256_256s_simple);

        oidToParams.put(sphincsPlus_shake256_128f_robust, SPHINCSPlusParameters.shake256_128f);
        oidToParams.put(sphincsPlus_shake256_128s_robust, SPHINCSPlusParameters.shake256_128s);
        oidToParams.put(sphincsPlus_shake256_192f_robust, SPHINCSPlusParameters.shake256_192f);
        oidToParams.put(sphincsPlus_shake256_192s_robust, SPHINCSPlusParameters.shake256_192s);
        oidToParams.put(sphincsPlus_shake256_256f_robust, SPHINCSPlusParameters.shake256_256f);
        oidToParams.put(sphincsPlus_shake256_256s_robust, SPHINCSPlusParameters.shake256_256s);

        oidToParams.put(sphincsPlus_shake256_128f_simple, SPHINCSPlusParameters.shake256_128f_simple);
        oidToParams.put(sphincsPlus_shake256_128s_simple, SPHINCSPlusParameters.shake256_128s_simple);
        oidToParams.put(sphincsPlus_shake256_192f_simple, SPHINCSPlusParameters.shake256_192f_simple);
        oidToParams.put(sphincsPlus_shake256_192s_simple, SPHINCSPlusParameters.shake256_192s_simple);
        oidToParams.put(sphincsPlus_shake256_256f_simple, SPHINCSPlusParameters.shake256_256f_simple);
        oidToParams.put(sphincsPlus_shake256_256s_simple, SPHINCSPlusParameters.shake256_256s_simple);

        paramsToOid.put(SPHINCSPlusParameters.sha256_128f, sphincsPlus_sha256_128f_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha256_128s, sphincsPlus_sha256_128s_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha256_192f, sphincsPlus_sha256_192f_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha256_192s, sphincsPlus_sha256_192s_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha256_256f, sphincsPlus_sha256_256f_robust);
        paramsToOid.put(SPHINCSPlusParameters.sha256_256s, sphincsPlus_sha256_256s_robust);

        paramsToOid.put(SPHINCSPlusParameters.sha256_128f_simple, sphincsPlus_sha256_128f_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha256_128s_simple, sphincsPlus_sha256_128s_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha256_192f_simple, sphincsPlus_sha256_192f_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha256_192s_simple, sphincsPlus_sha256_192s_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha256_256f_simple, sphincsPlus_sha256_256f_simple);
        paramsToOid.put(SPHINCSPlusParameters.sha256_256s_simple, sphincsPlus_sha256_256s_simple);
        
        paramsToOid.put(SPHINCSPlusParameters.shake256_128f, sphincsPlus_shake256_128f_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake256_128s, sphincsPlus_shake256_128s_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake256_192f, sphincsPlus_shake256_192f_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake256_192s, sphincsPlus_shake256_192s_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake256_256f, sphincsPlus_shake256_256f_robust);
        paramsToOid.put(SPHINCSPlusParameters.shake256_256s, sphincsPlus_shake256_256s_robust);
    
        paramsToOid.put(SPHINCSPlusParameters.shake256_128f_simple, sphincsPlus_shake256_128f_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake256_128s_simple, sphincsPlus_shake256_128s_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake256_192f_simple, sphincsPlus_shake256_192f_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake256_192s_simple, sphincsPlus_shake256_192s_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake256_256f_simple, sphincsPlus_shake256_256f_simple);
        paramsToOid.put(SPHINCSPlusParameters.shake256_256s_simple, sphincsPlus_shake256_256s_simple);
    }

    private final String name;
    private final SPHINCSPlusEngine engine;

    private SPHINCSPlusParameters(String name, SPHINCSPlusEngine engine)
    {
        this.name = name;
        this.engine = engine;
    }

    public String getName()
    {
        return name;
    }

    SPHINCSPlusEngine getEngine()
    {
        return engine;
    }

    /**
     * Return the SPHINCS+ parameters that map to the passed in parameter ID.
     * 
     * @param id the oid of interest.
     * @return the parameter set.
     */
    public static SPHINCSPlusParameters getParams(Integer id)
    {
          return (SPHINCSPlusParameters)oidToParams.get(id);
    }

    /**
     * Return the OID that maps to the passed in SPHINCS+ parameters.
     *
     * @param params the parameters of interest.
     * @return the OID for the parameter set.
     */
    public static Integer getID(SPHINCSPlusParameters params)
    {
          return (Integer)paramsToOid.get(params);
    }

    public byte[] getEncoded()
    {
        return Pack.intToBigEndian(getID(this).intValue());
    }
}
