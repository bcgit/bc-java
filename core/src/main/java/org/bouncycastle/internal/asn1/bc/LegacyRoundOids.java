package org.bouncycastle.internal.asn1.bc;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;

/**
 * The OIDs Bouncy Castle 1.81 to 1.87 gave the NIST additional-signature parameter sets, before each
 * had the round of the version it identifies appended. A key or signature under one of these is read
 * as the parameter set it names; nothing is written under them.
 */
public class LegacyRoundOids
{
    private static final Map legacyToCurrent = new HashMap();

    static
    {
        add(BCObjectIdentifiers.snova, 44, "2");
        add(BCObjectIdentifiers.faest, 12, "2");
        add(BCObjectIdentifiers.mqom, 36, "2");
        add(BCObjectIdentifiers.uov, 12, "2");
        add(BCObjectIdentifiers.qruov, 12, "2");
        add(BCObjectIdentifiers.sqisign, 3, "2");
        add(BCObjectIdentifiers.sdith, 12, "1");
    }

    private LegacyRoundOids()
    {
    }

    private static void add(ASN1ObjectIdentifier arc, int leafCount, String round)
    {
        for (int leaf = 1; leaf <= leafCount; leaf++)
        {
            ASN1ObjectIdentifier legacy = arc.branch(Integer.toString(leaf));

            legacyToCurrent.put(legacy, legacy.branch(round));
        }
    }

    /**
     * Return the current OID for a legacy one.
     *
     * @param oid the OID to look up.
     * @return the current OID if oid is a legacy one, null otherwise.
     */
    public static ASN1ObjectIdentifier getCurrent(ASN1ObjectIdentifier oid)
    {
        return (ASN1ObjectIdentifier)legacyToCurrent.get(oid);
    }

    /**
     * Return the current OID for oid if oid is a legacy one, otherwise oid itself.
     *
     * @param oid the OID to normalise.
     * @return the OID to use for oid.
     */
    public static ASN1ObjectIdentifier normalise(ASN1ObjectIdentifier oid)
    {
        ASN1ObjectIdentifier current = getCurrent(oid);

        return current != null ? current : oid;
    }

    /**
     * Return an iterator over the legacy OIDs.
     *
     * @return an iterator of ASN1ObjectIdentifier.
     */
    public static Iterator legacyOids()
    {
        return legacyToCurrent.keySet().iterator();
    }
}
