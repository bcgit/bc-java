package org.bouncycastle.pqc.crypto.lms;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

public class LMOtsParameters
{
    public static final int reserved = 0;
    public static final LMOtsParameters sha256_n32_w1 = new LMOtsParameters(0x01, 32, 1, 265, 7, 8516, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w2 = new LMOtsParameters(0x02, 32, 2, 133, 6, 4292, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w4 = new LMOtsParameters(0x03, 32, 4, 67, 4, 2180, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w8 = new LMOtsParameters(0x04, 32, 8, 34, 0, 1124, NISTObjectIdentifiers.id_sha256);

    public static final LMOtsParameters sha256_n24_w1 = new LMOtsParameters(0x05, 24, 1, 200, 8, 5436, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w2 = new LMOtsParameters(0x06, 24, 2, 101, 6, 2940, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w4 = new LMOtsParameters(0x07, 24, 4, 51, 4, 1500, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w8 = new LMOtsParameters(0x08, 24, 8, 26, 0, 1020, NISTObjectIdentifiers.id_sha256);

    public static final LMOtsParameters shake256_n32_w1 = new LMOtsParameters(0x09, 32, 1, 265, 7, 8516, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n32_w2 = new LMOtsParameters(0x0a, 32, 2, 133, 6, 4292, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n32_w4 = new LMOtsParameters(0x0b, 32, 4, 67, 4, 2180, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n32_w8 = new LMOtsParameters(0x0c, 32, 8, 34, 0, 1124, NISTObjectIdentifiers.id_shake256_len);

    public static final LMOtsParameters shake256_n24_w1 = new LMOtsParameters(0x0d, 24, 1, 200, 8, 5436, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w2 = new LMOtsParameters(0x0e, 24, 2, 101, 6, 2940, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w4 = new LMOtsParameters(0x0f, 24, 4, 51, 4, 1500, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w8 = new LMOtsParameters(0x10, 24, 8, 26, 0, 1020, NISTObjectIdentifiers.id_shake256_len);

    private static final Map<Object, LMOtsParameters> suppliers = new HashMap<Object, LMOtsParameters>()
    {
        {
            put(sha256_n32_w1.type, sha256_n32_w1);
            put(sha256_n32_w2.type, sha256_n32_w2);
            put(sha256_n32_w4.type, sha256_n32_w4);
            put(sha256_n32_w8.type, sha256_n32_w8);
            put(sha256_n24_w1.type, sha256_n24_w1);
            put(sha256_n24_w2.type, sha256_n24_w2);
            put(sha256_n24_w4.type, sha256_n24_w4);
            put(sha256_n24_w8.type, sha256_n24_w8);
            put(shake256_n32_w1.type, shake256_n32_w1);
            put(shake256_n32_w2.type, shake256_n32_w2);
            put(shake256_n32_w4.type, shake256_n32_w4);
            put(shake256_n32_w8.type, shake256_n32_w8);
            put(shake256_n24_w1.type, shake256_n24_w1);
            put(shake256_n24_w2.type, shake256_n24_w2);
            put(shake256_n24_w4.type, shake256_n24_w4);
            put(shake256_n24_w8.type, shake256_n24_w8);
        }
    };

    private final int type;
    private final int n;
    private final int w;
    private final int p;
    private final int ls;
    private final int sigLen;
    private final ASN1ObjectIdentifier digestOID;

    protected LMOtsParameters(int type, int n, int w, int p, int ls, int sigLen, ASN1ObjectIdentifier digestOID)
    {
        this.type = type;
        this.n = n;
        this.w = w;
        this.p = p;
        this.ls = ls;
        this.sigLen = sigLen;
        this.digestOID = digestOID;
    }

    public int getType()
    {
        return type;
    }

    public int getN()
    {
        return n;
    }

    public int getW()
    {
        return w;
    }

    public int getP()
    {
        return p;
    }

    public int getLs()
    {
        return ls;
    }

    public int getSigLen()
    {
        return sigLen;
    }

    public ASN1ObjectIdentifier getDigestOID()
    {
        return digestOID;
    }

    public static LMOtsParameters getParametersForType(int type)
    {
        return suppliers.get(type);
    }
}
