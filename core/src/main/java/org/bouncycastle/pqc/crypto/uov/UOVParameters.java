package org.bouncycastle.pqc.crypto.uov;

/**
 * Parameter set for the Unbalanced Oil and Vinegar (UOV) signature scheme.
 * <p>
 * Tracks the OV / pqov NIST submission's four mathematical variants (uov-Is,
 * uov-Ip, uov-III, uov-V) × three key-encoding variants (classic, pkc,
 * pkc-skc), giving twelve named parameter sets. The math is shared within
 * a parameter-family; only the public/private-key serialization differs
 * between encoding variants:
 * <ul>
 * <li><b>classic</b>: uncompressed pk = P1 || P2 || P3; uncompressed sk =
 *     sk_seed || O || P1 || S (where S = F2).</li>
 * <li><b>pkc</b>: compressed pk = pk_seed (16 bytes) || P3; uncompressed sk.</li>
 * <li><b>pkc-skc</b>: compressed pk; sk = sk_seed (32 bytes) only.</li>
 * </ul>
 */
public class UOVParameters
{
    public static final int GF_16 = 16;
    public static final int GF_256 = 256;

    public static final int VARIANT_CLASSIC = 0;
    public static final int VARIANT_PKC = 1;
    public static final int VARIANT_PKC_SKC = 2;

    public static final int SK_SEED_BYTES = 32;
    public static final int PK_SEED_BYTES = 16;
    public static final int SALT_BYTES = 16;

    public static final UOVParameters uov_Is = new UOVParameters("uov-is", GF_16, 160, 64, 32, VARIANT_CLASSIC);
    public static final UOVParameters uov_Is_pkc = new UOVParameters("uov-is-pkc", GF_16, 160, 64, 32, VARIANT_PKC);
    public static final UOVParameters uov_Is_pkc_skc = new UOVParameters("uov-is-pkc-skc", GF_16, 160, 64, 32, VARIANT_PKC_SKC);

    public static final UOVParameters uov_Ip = new UOVParameters("uov-ip", GF_256, 112, 44, 32, VARIANT_CLASSIC);
    public static final UOVParameters uov_Ip_pkc = new UOVParameters("uov-ip-pkc", GF_256, 112, 44, 32, VARIANT_PKC);
    public static final UOVParameters uov_Ip_pkc_skc = new UOVParameters("uov-ip-pkc-skc", GF_256, 112, 44, 32, VARIANT_PKC_SKC);

    public static final UOVParameters uov_III = new UOVParameters("uov-iii", GF_256, 184, 72, 48, VARIANT_CLASSIC);
    public static final UOVParameters uov_III_pkc = new UOVParameters("uov-iii-pkc", GF_256, 184, 72, 48, VARIANT_PKC);
    public static final UOVParameters uov_III_pkc_skc = new UOVParameters("uov-iii-pkc-skc", GF_256, 184, 72, 48, VARIANT_PKC_SKC);

    public static final UOVParameters uov_V = new UOVParameters("uov-v", GF_256, 244, 96, 64, VARIANT_CLASSIC);
    public static final UOVParameters uov_V_pkc = new UOVParameters("uov-v-pkc", GF_256, 244, 96, 64, VARIANT_PKC);
    public static final UOVParameters uov_V_pkc_skc = new UOVParameters("uov-v-pkc-skc", GF_256, 244, 96, 64, VARIANT_PKC_SKC);

    private final String name;
    private final int gfSize;
    private final int n;
    private final int m;
    private final int hashLen;
    private final int v;
    private final int variant;

    private UOVParameters(String name, int gfSize, int n, int m, int hashLen, int variant)
    {
        this.name = name;
        this.gfSize = gfSize;
        this.n = n;
        this.m = m;
        this.hashLen = hashLen;
        this.v = n - m;
        this.variant = variant;
    }

    public String getName()
    {
        return name;
    }

    public int getGfSize()
    {
        return gfSize;
    }

    public boolean isGF16()
    {
        return gfSize == GF_16;
    }

    public int getN()
    {
        return n;
    }

    public int getM()
    {
        return m;
    }

    public int getO()
    {
        return m;
    }

    public int getV()
    {
        return v;
    }

    public int getHashLen()
    {
        return hashLen;
    }

    public int getVariant()
    {
        return variant;
    }

    public boolean isCompressedPublicKey()
    {
        return variant != VARIANT_CLASSIC;
    }

    public boolean isCompressedSecretKey()
    {
        return variant == VARIANT_PKC_SKC;
    }

    public int packedBytes(int numElements)
    {
        return isGF16() ? ((numElements + 1) >>> 1) : numElements;
    }

    public int getVByte()
    {
        return packedBytes(v);
    }

    public int getOByte()
    {
        return packedBytes(m);
    }

    public int getNByte()
    {
        return packedBytes(n);
    }

    public int getMByte()
    {
        return getOByte();
    }

    public int getSignatureBytes()
    {
        return getNByte() + SALT_BYTES;
    }

    public int getPkP1Bytes()
    {
        return getOByte() * (v * (v + 1) / 2);
    }

    public int getPkP2Bytes()
    {
        return getOByte() * v * m;
    }

    public int getPkP3Bytes()
    {
        return getOByte() * (m * (m + 1) / 2);
    }

    public int getClassicPublicKeyBytes()
    {
        return getPkP1Bytes() + getPkP2Bytes() + getPkP3Bytes();
    }

    public int getCompressedPublicKeyBytes()
    {
        return PK_SEED_BYTES + getPkP3Bytes();
    }

    public int getPublicKeyBytes()
    {
        return isCompressedPublicKey() ? getCompressedPublicKeyBytes() : getClassicPublicKeyBytes();
    }

    public int getOMapBytes()
    {
        return getVByte() * m;
    }

    public int getClassicSecretKeyBytes()
    {
        return SK_SEED_BYTES + getOMapBytes() + getPkP1Bytes() + getPkP2Bytes();
    }

    public int getCompressedSecretKeyBytes()
    {
        return SK_SEED_BYTES;
    }

    public int getSecretKeyBytes()
    {
        return isCompressedSecretKey() ? getCompressedSecretKeyBytes() : getClassicSecretKeyBytes();
    }
}
