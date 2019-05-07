package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * XMSSOid^MT class.
 */
public final class DefaultXMSSMTOid
    implements XMSSOid
{

    /**
     * XMSS^MT OID lookup table.
     */
    private static final Map<String, DefaultXMSSMTOid> oidLookupTable;

    static
    {
        Map<String, DefaultXMSSMTOid> map = new HashMap<String, DefaultXMSSMTOid>();
        map.put(createKey("SHA-256", 32, 16, 67, 20, 2),
            new DefaultXMSSMTOid(0x00000001, "XMSSMT_SHA2_20/2_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 20, 4),
            new DefaultXMSSMTOid(0x00000002, "XMSSMT_SHA2_20/4_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 40, 2),
            new DefaultXMSSMTOid(0x00000003, "XMSSMT_SHA2_40/2_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 40, 2),
            new DefaultXMSSMTOid(0x00000004, "XMSSMT_SHA2_40/4_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 40, 4),
            new DefaultXMSSMTOid(0x00000005, "XMSSMT_SHA2_40/8_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 60, 8),
            new DefaultXMSSMTOid(0x00000006, "XMSSMT_SHA2_60/3_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 60, 6),
            new DefaultXMSSMTOid(0x00000007, "XMSSMT_SHA2_60/6_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 60, 12),
            new DefaultXMSSMTOid(0x00000008, "XMSSMT_SHA2_60/12_256"));
        map.put(createKey("SHA-512", 64, 16, 131, 20, 2),
            new DefaultXMSSMTOid(0x00000009, "XMSSMT_SHA2_20/2_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 20, 4),
            new DefaultXMSSMTOid(0x0000000a, "XMSSMT_SHA2_20/4_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 40, 2),
            new DefaultXMSSMTOid(0x0000000b, "XMSSMT_SHA2_40/2_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 40, 4),
            new DefaultXMSSMTOid(0x0000000c, "XMSSMT_SHA2_40/4_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 40, 8),
            new DefaultXMSSMTOid(0x0000000d, "XMSSMT_SHA2_40/8_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 60, 3),
            new DefaultXMSSMTOid(0x0000000e, "XMSSMT_SHA2_60/3_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 60, 6),
            new DefaultXMSSMTOid(0x0000000f, "XMSSMT_SHA2_60/6_512"));
        map.put(createKey("SHA-512", 64, 16, 131, 60, 12),
            new DefaultXMSSMTOid(0x00000010, "XMSSMT_SHA2_60/12_512"));
        map.put(createKey("SHAKE128", 32, 16, 67, 20, 2),
            new DefaultXMSSMTOid(0x00000011, "XMSSMT_SHAKE_20/2_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 20, 4),
            new DefaultXMSSMTOid(0x00000012, "XMSSMT_SHAKE_20/4_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 40, 2),
            new DefaultXMSSMTOid(0x00000013, "XMSSMT_SHAKE_40/2_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 40, 4),
            new DefaultXMSSMTOid(0x00000014, "XMSSMT_SHAKE_40/4_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 40, 8),
            new DefaultXMSSMTOid(0x00000015, "XMSSMT_SHAKE_40/8_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 60, 3),
            new DefaultXMSSMTOid(0x00000016, "XMSSMT_SHAKE_60/3_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 60, 6),
            new DefaultXMSSMTOid(0x00000017, "XMSSMT_SHAKE_60/6_256"));
        map.put(createKey("SHAKE128", 32, 16, 67, 60, 12),
            new DefaultXMSSMTOid(0x00000018, "XMSSMT_SHAKE_60/12_256"));
        map.put(createKey("SHAKE256", 64, 16, 131, 20, 2),
            new DefaultXMSSMTOid(0x00000019, "XMSSMT_SHAKE_20/2_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 20, 4),
            new DefaultXMSSMTOid(0x0000001a, "XMSSMT_SHAKE_20/4_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 40, 2),
            new DefaultXMSSMTOid(0x0000001b, "XMSSMT_SHAKE_40/2_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 40, 4),
            new DefaultXMSSMTOid(0x0000001c, "XMSSMT_SHAKE_40/4_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 40, 8),
            new DefaultXMSSMTOid(0x0000001d, "XMSSMT_SHAKE_40/8_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 60, 3),
            new DefaultXMSSMTOid(0x0000001e, "XMSSMT_SHAKE_60/3_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 60, 6),
            new DefaultXMSSMTOid(0x0000001f, "XMSSMT_SHAKE_60/6_512"));
        map.put(createKey("SHAKE256", 64, 16, 131, 60, 12),
            new DefaultXMSSMTOid(0x00000020, "XMSSMT_SHAKE_60/12_512"));
        oidLookupTable = Collections.unmodifiableMap(map);
    }

    /**
     * OID.
     */
    private final int oid;
    /**
     * String representation of OID.
     */
    private final String stringRepresentation;

    /**
     * Constructor...
     *
     * @param oid                  OID.
     * @param stringRepresentation String representation of OID.
     */
    private DefaultXMSSMTOid(int oid, String stringRepresentation)
    {
        super();
        this.oid = oid;
        this.stringRepresentation = stringRepresentation;
    }

    /**
     * Lookup OID.
     *
     * @param algorithmName       Algorithm name.
     * @param winternitzParameter Winternitz parameter.
     * @param height              Binary tree height.
     * @return XMSS OID if parameters were found, null else.
     */
    public static DefaultXMSSMTOid lookup(String algorithmName, int digestSize, int winternitzParameter, int len,
                                          int height, int layers)
    {
        if (algorithmName == null)
        {
            throw new NullPointerException("algorithmName == null");
        }
        return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len, height, layers));
    }

    /**
     * Create a key based on parameters.
     *
     * @param algorithmName       Algorithm name.
     * @param winternitzParameter Winternitz Parameter.
     * @param height              Binary tree height.
     * @return String representation of parameters for lookup table.
     */
    private static String createKey(String algorithmName, int digestSize, int winternitzParameter, int len, int height,
                                    int layers)
    {
        if (algorithmName == null)
        {
            throw new NullPointerException("algorithmName == null");
        }
        
        return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len + "-" + height + "-" + layers;
    }

    /**
     * Getter OID.
     *
     * @return OID.
     */
    public int getOid()
    {
        return oid;
    }

    public String toString()
    {
        return stringRepresentation;
    }
}
