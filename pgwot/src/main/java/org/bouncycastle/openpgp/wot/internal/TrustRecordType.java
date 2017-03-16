package org.bouncycastle.openpgp.wot.internal;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

enum TrustRecordType
{
    UNUSED((short) 0, TrustRecord.Unused.class),
    VERSION((short) 1, TrustRecord.Version.class),
    HTBL((short) 10, TrustRecord.HashTbl.class),
    HLST((short) 11, TrustRecord.HashLst.class),
    TRUST((short) 12, TrustRecord.Trust.class),
    VALID((short) 13, TrustRecord.Valid.class),
    FREE((short) 254, TrustRecord.Free.class);

    private static volatile Map<Short, TrustRecordType> id2Type;
    private static volatile Map<Class<? extends TrustRecord>, TrustRecordType> class2Type;

    private final short id;
    private Class<? extends TrustRecord> trustRecordClass;

    private TrustRecordType(short id, Class<? extends TrustRecord> trustRecordClass)
    {
        this.id = id;
        this.trustRecordClass = assertNotNull("trustRecordClass", trustRecordClass);
    }

    public short getId()
    {
        return id;
    }

    public Class<? extends TrustRecord> getTrustRecordClass()
    {
        return trustRecordClass;
    }

    public static TrustRecordType fromId(short id)
    {
        TrustRecordType type = getId2Type().get(id);
        if (type == null)
            throw new IllegalArgumentException("id unknown: " + id);

        return type;
    }

    public static TrustRecordType fromClass(Class<? extends TrustRecord> trustRecordClass)
    {
        assertNotNull("trustRecordClass", trustRecordClass);
        TrustRecordType type = getClass2Type().get(trustRecordClass);
        if (type == null)
            throw new IllegalArgumentException("trustRecordClass unknown: " + trustRecordClass.getName());

        return type;
    }

    private static Map<Short, TrustRecordType> getId2Type()
    {
        if (id2Type == null)
        {
            Map<Short, TrustRecordType> m = new HashMap<>(values().length);
            for (TrustRecordType type : values())
                m.put(type.getId(), type);

            id2Type = Collections.unmodifiableMap(m);
        }
        return id2Type;
    }

    private static Map<Class<? extends TrustRecord>, TrustRecordType> getClass2Type()
    {
        if (class2Type == null)
        {
            Map<Class<? extends TrustRecord>, TrustRecordType> m = new HashMap<>(values().length);
            for (TrustRecordType type : values())
                m.put(type.getTrustRecordClass(), type);

            class2Type = Collections.unmodifiableMap(m);
        }
        return class2Type;
    }
}
