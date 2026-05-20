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
        map.put(createKey("SHA-256", 32, 16, 67, 40, 4),
            new DefaultXMSSMTOid(0x00000004, "XMSSMT_SHA2_40/4_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 40, 8),
            new DefaultXMSSMTOid(0x00000005, "XMSSMT_SHA2_40/8_256"));
        map.put(createKey("SHA-256", 32, 16, 67, 60, 3),
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

        // SP 800-208: SHA-256/192 (n=24)
        map.put(createKey("SHA-256", 24, 16, 51, 20, 2),
            new DefaultXMSSMTOid(0x00000021, "XMSSMT_SHA2_20/2_192"));
        map.put(createKey("SHA-256", 24, 16, 51, 20, 4),
            new DefaultXMSSMTOid(0x00000022, "XMSSMT_SHA2_20/4_192"));
        map.put(createKey("SHA-256", 24, 16, 51, 40, 2),
            new DefaultXMSSMTOid(0x00000023, "XMSSMT_SHA2_40/2_192"));
        map.put(createKey("SHA-256", 24, 16, 51, 40, 4),
            new DefaultXMSSMTOid(0x00000024, "XMSSMT_SHA2_40/4_192"));
        map.put(createKey("SHA-256", 24, 16, 51, 40, 8),
            new DefaultXMSSMTOid(0x00000025, "XMSSMT_SHA2_40/8_192"));
        map.put(createKey("SHA-256", 24, 16, 51, 60, 3),
            new DefaultXMSSMTOid(0x00000026, "XMSSMT_SHA2_60/3_192"));
        map.put(createKey("SHA-256", 24, 16, 51, 60, 6),
            new DefaultXMSSMTOid(0x00000027, "XMSSMT_SHA2_60/6_192"));
        map.put(createKey("SHA-256", 24, 16, 51, 60, 12),
            new DefaultXMSSMTOid(0x00000028, "XMSSMT_SHA2_60/12_192"));

        // SP 800-208: SHAKE256/256 (n=32)
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 20, 2),
            new DefaultXMSSMTOid(0x00000029, "XMSSMT_SHAKE256_20/2_256"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 20, 4),
            new DefaultXMSSMTOid(0x0000002a, "XMSSMT_SHAKE256_20/4_256"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 40, 2),
            new DefaultXMSSMTOid(0x0000002b, "XMSSMT_SHAKE256_40/2_256"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 40, 4),
            new DefaultXMSSMTOid(0x0000002c, "XMSSMT_SHAKE256_40/4_256"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 40, 8),
            new DefaultXMSSMTOid(0x0000002d, "XMSSMT_SHAKE256_40/8_256"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 60, 3),
            new DefaultXMSSMTOid(0x0000002e, "XMSSMT_SHAKE256_60/3_256"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 60, 6),
            new DefaultXMSSMTOid(0x0000002f, "XMSSMT_SHAKE256_60/6_256"));
        map.put(createKey("SHAKE256-LEN", 32, 16, 67, 60, 12),
            new DefaultXMSSMTOid(0x00000030, "XMSSMT_SHAKE256_60/12_256"));

        // SP 800-208: SHAKE256/192 (n=24)
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 20, 2),
            new DefaultXMSSMTOid(0x00000031, "XMSSMT_SHAKE256_20/2_192"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 20, 4),
            new DefaultXMSSMTOid(0x00000032, "XMSSMT_SHAKE256_20/4_192"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 40, 2),
            new DefaultXMSSMTOid(0x00000033, "XMSSMT_SHAKE256_40/2_192"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 40, 4),
            new DefaultXMSSMTOid(0x00000034, "XMSSMT_SHAKE256_40/4_192"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 40, 8),
            new DefaultXMSSMTOid(0x00000035, "XMSSMT_SHAKE256_40/8_192"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 60, 3),
            new DefaultXMSSMTOid(0x00000036, "XMSSMT_SHAKE256_60/3_192"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 60, 6),
            new DefaultXMSSMTOid(0x00000037, "XMSSMT_SHAKE256_60/6_192"));
        map.put(createKey("SHAKE256-LEN", 24, 16, 51, 60, 12),
            new DefaultXMSSMTOid(0x00000038, "XMSSMT_SHAKE256_60/12_192"));

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
