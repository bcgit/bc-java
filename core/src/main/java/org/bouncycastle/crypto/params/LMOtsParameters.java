package org.bouncycastle.crypto.params;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.util.Integers;

public class LMOtsParameters
    implements PQCParameters
{
    public static final int reserved = 0;
    public static final LMOtsParameters sha256_n32_w1 = create(0x01, 32, 1, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w2 = create(0x02, 32, 2, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w4 = create(0x03, 32, 4, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n32_w8 = create(0x04, 32, 8, NISTObjectIdentifiers.id_sha256);

    public static final LMOtsParameters sha256_n24_w1 = create(0x05, 24, 1, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w2 = create(0x06, 24, 2, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w4 = create(0x07, 24, 4, NISTObjectIdentifiers.id_sha256);
    public static final LMOtsParameters sha256_n24_w8 = create(0x08, 24, 8, NISTObjectIdentifiers.id_sha256);

    public static final LMOtsParameters shake256_n32_w1 = create(0x09, 32, 1, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n32_w2 = create(0x0a, 32, 2, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n32_w4 = create(0x0b, 32, 4, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n32_w8 = create(0x0c, 32, 8, NISTObjectIdentifiers.id_shake256_len);

    public static final LMOtsParameters shake256_n24_w1 = create(0x0d, 24, 1, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w2 = create(0x0e, 24, 2, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w4 = create(0x0f, 24, 4, NISTObjectIdentifiers.id_shake256_len);
    public static final LMOtsParameters shake256_n24_w8 = create(0x10, 24, 8, NISTObjectIdentifiers.id_shake256_len);

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

    /**
     * Build a parameter set from its defining values: the typecode, the hash length n and the Winternitz
     * parameter w. The rest follows from n and w (RFC 8554 Appendix B): u = ceil(8n / w) chains carry the
     * message digest, v = ceil((floor(log2(u * (2^w - 1))) + 1) / w) chains carry its checksum, p = u + v, the
     * checksum is left-shifted by ls = 16 - v * w, and a signature is u32str(type) || C || y[0..p-1], i.e.
     * 4 + n + p * n bytes.
     */
    private static LMOtsParameters create(int type, int n, int w, ASN1ObjectIdentifier digestOID)
    {
        int u = (8 * n + w - 1) / w;
        int v = (Integers.bitLength(u * ((1 << w) - 1)) + w - 1) / w; // bitLength(x) == floor(log2(x)) + 1
        int p = u + v;
        int ls = 16 - v * w;
        int sigLen = 4 + n + p * n;

        return new LMOtsParameters(type, n, w, p, ls, sigLen, digestOID);
    }

    private final int type;
    private final int n;
    private final int w;
    private final int p;
    private final int ls;
    private final int sigLen;
    private final ASN1ObjectIdentifier digestOID;

    /**
     * @deprecated The parameter sets are the static fields of this class, looked up by
     * {@link #getParametersForType(int)}; this class is not intended to be subclassed and this constructor will be
     * made private.
     */
    @Deprecated
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

    /**
     * The typecode identifies the parameter set: the rest of the values are derived from it.
     * <p>
     * The instances are interned - every lookup hands back one of the static fields - so this agrees with the
     * reference equality it replaces. It states the intent instead of leaving callers to rely on the interning.
     */
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof LMOtsParameters))
        {
            return false;
        }

        LMOtsParameters that = (LMOtsParameters)obj;
        return type == that.type;
    }

    public int hashCode()
    {
        return type;
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

    /**
     * Return the NIST security category of this parameter set: 3 for the SHA-256/192 and
     * SHAKE256/192 sets (n = 24) and 5 for the SHA-256 and SHAKE256/256 sets (n = 32)
     * (NIST IR 8547, Table 3).
     */
    public int getSecurityCategory()
    {
        return (n <= 24) ? 3 : 5;
    }

    /**
     * Return the classical security strength of this parameter set: 8 times the hash output
     * length n, so 192 or 256 bits (NIST IR 8547, Table 3).
     */
    public int getClassicalSecurityStrength()
    {
        return 8 * n;
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
