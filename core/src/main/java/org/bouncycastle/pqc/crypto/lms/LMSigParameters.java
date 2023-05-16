package org.bouncycastle.pqc.crypto.lms;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

public class LMSigParameters
{
    public static final LMSigParameters lms_sha256_n32_h5 = new LMSigParameters(0x05, 32, 5, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h10 = new LMSigParameters(0x06, 32, 10, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h15 = new LMSigParameters(0x07, 32, 15, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h20 = new LMSigParameters(0x08, 32, 20, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h25 = new LMSigParameters(0x09, 32, 25, NISTObjectIdentifiers.id_sha256);

    public static final LMSigParameters lms_sha256_n24_h5 = new LMSigParameters(0x0a, 24, 5, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h10 = new LMSigParameters(0x0b, 24, 10, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h15 = new LMSigParameters(0x0c, 24, 15, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h20 = new LMSigParameters(0x0d, 24, 20, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h25 = new LMSigParameters(0x0e, 24, 25, NISTObjectIdentifiers.id_sha256);

    public static final LMSigParameters lms_shake256_n32_h5 = new LMSigParameters(0x0f, 32, 5, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h10 = new LMSigParameters(0x10, 32, 10, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h15 = new LMSigParameters(0x11, 32, 15, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h20 = new LMSigParameters(0x12, 32, 20, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h25 = new LMSigParameters(0x13, 32, 25, NISTObjectIdentifiers.id_shake256_len);

    public static final LMSigParameters lms_shake256_n24_h5 = new LMSigParameters(0x14, 24, 5, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h10 = new LMSigParameters(0x15, 24, 10, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h15 = new LMSigParameters(0x16, 24, 15, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h20 = new LMSigParameters(0x17, 24, 20, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h25 = new LMSigParameters(0x18, 24, 25, NISTObjectIdentifiers.id_shake256_len);

    private static Map<Object, LMSigParameters> paramBuilders = new HashMap<Object, LMSigParameters>()
    {
        {
            put(lms_sha256_n32_h5.type, lms_sha256_n32_h5);
            put(lms_sha256_n32_h10.type, lms_sha256_n32_h10);
            put(lms_sha256_n32_h15.type, lms_sha256_n32_h15);
            put(lms_sha256_n32_h20.type, lms_sha256_n32_h20);
            put(lms_sha256_n32_h25.type, lms_sha256_n32_h25);

            put(lms_sha256_n24_h5.type, lms_sha256_n24_h5);
            put(lms_sha256_n24_h10.type, lms_sha256_n24_h10);
            put(lms_sha256_n24_h15.type, lms_sha256_n24_h15);
            put(lms_sha256_n24_h20.type, lms_sha256_n24_h20);
            put(lms_sha256_n24_h25.type, lms_sha256_n24_h25);

            put(lms_shake256_n32_h5.type, lms_shake256_n32_h5);
            put(lms_shake256_n32_h10.type, lms_shake256_n32_h10);
            put(lms_shake256_n32_h15.type, lms_shake256_n32_h15);
            put(lms_shake256_n32_h20.type, lms_shake256_n32_h20);
            put(lms_shake256_n32_h25.type, lms_shake256_n32_h25);

            put(lms_shake256_n24_h5.type, lms_shake256_n24_h5);
            put(lms_shake256_n24_h10.type, lms_shake256_n24_h10);
            put(lms_shake256_n24_h15.type, lms_shake256_n24_h15);
            put(lms_shake256_n24_h20.type, lms_shake256_n24_h20);
            put(lms_shake256_n24_h25.type, lms_shake256_n24_h25);
        }
    };

    private final int type;
    private final int m;
    private final int h;
    private final ASN1ObjectIdentifier digestOid;

    protected LMSigParameters(int type, int m, int h, ASN1ObjectIdentifier digestOid)
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

    static LMSigParameters getParametersForType(int type)
    {
        return paramBuilders.get(type);
    }
}
