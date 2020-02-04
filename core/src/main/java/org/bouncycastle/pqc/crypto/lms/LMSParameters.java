package org.bouncycastle.pqc.crypto.lms;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

public class LMSParameters
{
    public static final LMSParameters lms_sha256_n32_h5 = new LMSParameters(5, 32, 5, NISTObjectIdentifiers.id_sha256);
    public static final LMSParameters lms_sha256_n32_h10 = new LMSParameters(6, 32, 10, NISTObjectIdentifiers.id_sha256);
    public static final LMSParameters lms_sha256_n32_h15 = new LMSParameters(7, 32, 15, NISTObjectIdentifiers.id_sha256);
    public static final LMSParameters lms_sha256_n32_h20 = new LMSParameters(8, 32, 20, NISTObjectIdentifiers.id_sha256);
    public static final LMSParameters lms_sha256_n32_h25 = new LMSParameters(9, 32, 25, NISTObjectIdentifiers.id_sha256);

    private static Map<Object, LMSParameters> paramBuilders = new HashMap<Object, LMSParameters>()
    {
        {
            put(lms_sha256_n32_h5.type, lms_sha256_n32_h5);
            put(lms_sha256_n32_h10.type, lms_sha256_n32_h10);
            put(lms_sha256_n32_h15.type, lms_sha256_n32_h15);
            put(lms_sha256_n32_h20.type, lms_sha256_n32_h20);
            put(lms_sha256_n32_h25.type, lms_sha256_n32_h25);
        }
    };

    private final int type;
    private final int m;
    private final int h;
    private final ASN1ObjectIdentifier digestOid;

    protected LMSParameters(int type, int m, int h, ASN1ObjectIdentifier digestOid)
    {
        this.type = type;
        this.m = m;
        this.h = h;
        this.digestOid = digestOid;
    }

    public int getType()
    {
        return type;
    }

    public int getH()
    {
        return h;
    }

    public int getM()
    {
        return m;
    }

    public ASN1ObjectIdentifier getDigestOID()
    {
        return digestOid;
    }

    static LMSParameters getParametersForType(int type)
    {
        return paramBuilders.get(type);
    }
}
