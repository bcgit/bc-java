package org.bouncycastle.crypto.params;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

public class LMSigParameters
    implements PQCParameters
{
    public static final LMSigParameters lms_sha256_n32_h5 = create(0x05, 32, 5, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h10 = create(0x06, 32, 10, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h15 = create(0x07, 32, 15, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h20 = create(0x08, 32, 20, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n32_h25 = create(0x09, 32, 25, NISTObjectIdentifiers.id_sha256);

    public static final LMSigParameters lms_sha256_n24_h5 = create(0x0a, 24, 5, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h10 = create(0x0b, 24, 10, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h15 = create(0x0c, 24, 15, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h20 = create(0x0d, 24, 20, NISTObjectIdentifiers.id_sha256);
    public static final LMSigParameters lms_sha256_n24_h25 = create(0x0e, 24, 25, NISTObjectIdentifiers.id_sha256);

    public static final LMSigParameters lms_shake256_n32_h5 = create(0x0f, 32, 5, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h10 = create(0x10, 32, 10, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h15 = create(0x11, 32, 15, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h20 = create(0x12, 32, 20, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n32_h25 = create(0x13, 32, 25, NISTObjectIdentifiers.id_shake256_len);

    public static final LMSigParameters lms_shake256_n24_h5 = create(0x14, 24, 5, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h10 = create(0x15, 24, 10, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h15 = create(0x16, 24, 15, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h20 = create(0x17, 24, 20, NISTObjectIdentifiers.id_shake256_len);
    public static final LMSigParameters lms_shake256_n24_h25 = create(0x18, 24, 25, NISTObjectIdentifiers.id_shake256_len);

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

    private static LMSigParameters create(int type, int m, int h, ASN1ObjectIdentifier digestOid)
    {
        return new LMSigParameters(type, m, h, digestOid);
    }

    private final int type;
    private final int m;
    private final int h;
    private final ASN1ObjectIdentifier digestOid;

    /**
     * @deprecated The parameter sets are the static fields of this class, looked up by
     * {@link #getParametersForType(int)}; this class is not intended to be subclassed and this constructor will be
     * made private.
     */
    @Deprecated
    protected LMSigParameters(int type, int m, int h, ASN1ObjectIdentifier digestOid)
    {
        this.type = type;
        this.m = m;
        this.h = h;
        this.digestOid = digestOid;
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
        if (!(obj instanceof LMSigParameters))
        {
            return false;
        }

        LMSigParameters that = (LMSigParameters)obj;
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

    public int getH()
    {
        return h;
    }

    /**
     * Return the NIST security category of this parameter set: 3 for the SHA-256/192 and
     * SHAKE256/192 sets (m = 24) and 5 for the SHA-256 and SHAKE256/256 sets (m = 32)
     * (NIST IR 8547, Table 3).
     */
    public int getSecurityCategory()
    {
        return (m <= 24) ? 3 : 5;
    }

    /**
     * Return the classical security strength of this parameter set: 8 times the hash output
     * length m, so 192 or 256 bits (NIST IR 8547, Table 3).
     */
    public int getClassicalSecurityStrength()
    {
        return 8 * m;
    }

    public int getM()
    {
        return m;
    }

    public ASN1ObjectIdentifier getDigestOID()
    {
        return digestOid;
    }

    public static LMSigParameters getParametersForType(int type)
    {
        return paramBuilders.get(type);
    }
}
