package org.bouncycastle.tls;

/**
 * RFC 7919
 */
public class NamedGroup
{
    /*
     * RFC 4492 5.1.1
     * <p>
     * The named curves defined here are those specified in SEC 2 [13]. Note that many of these curves
     * are also recommended in ANSI X9.62 [7] and FIPS 186-2 [11]. Values 0xFE00 through 0xFEFF are
     * reserved for private use. Values 0xFF01 and 0xFF02 indicate that the client supports arbitrary
     * prime and characteristic-2 curves, respectively (the curve parameters must be encoded explicitly
     * in ECParameters).
     */
    public static final int sect163k1 = 1;
    public static final int sect163r1 = 2;
    public static final int sect163r2 = 3;
    public static final int sect193r1 = 4;
    public static final int sect193r2 = 5;
    public static final int sect233k1 = 6;
    public static final int sect233r1 = 7;
    public static final int sect239k1 = 8;
    public static final int sect283k1 = 9;
    public static final int sect283r1 = 10;
    public static final int sect409k1 = 11;
    public static final int sect409r1 = 12;
    public static final int sect571k1 = 13;
    public static final int sect571r1 = 14;
    public static final int secp160k1 = 15;
    public static final int secp160r1 = 16;
    public static final int secp160r2 = 17;
    public static final int secp192k1 = 18;
    public static final int secp192r1 = 19;
    public static final int secp224k1 = 20;
    public static final int secp224r1 = 21;
    public static final int secp256k1 = 22;
    public static final int secp256r1 = 23;
    public static final int secp384r1 = 24;
    public static final int secp521r1 = 25;
    
    /*
     * RFC 7027
     */
    public static final int brainpoolP256r1 = 26;
    public static final int brainpoolP384r1 = 27;
    public static final int brainpoolP512r1 = 28;

    /*
     * RFC 8422
     */
    public static final int x25519 = 29;
    public static final int x448 = 30;

    /*
     * RFC 7919 2. Codepoints in the "Supported Groups Registry" with a high byte of 0x01 (that is,
     * between 256 and 511, inclusive) are set aside for FFDHE groups, though only a small number of
     * them are initially defined and we do not expect many other FFDHE groups to be added to this
     * range. No codepoints outside of this range will be allocated to FFDHE groups.
     */
    public static final int ffdhe2048 = 256;
    public static final int ffdhe3072 = 257;
    public static final int ffdhe4096 = 258;
    public static final int ffdhe6144 = 259;
    public static final int ffdhe8192 = 260;

    /*
     * RFC 8446 reserved ffdhe_private_use (0x01FC..0x01FF)
     */

    /*
     * RFC 4492 reserved ecdhe_private_use (0xFE00..0xFEFF)
     */

    /*
     * RFC 4492
     */
    public static final int arbitrary_explicit_prime_curves = 0xFF01;
    public static final int arbitrary_explicit_char2_curves = 0xFF02;

    private static final String[] CURVE_NAMES = new String[] { "sect163k1", "sect163r1", "sect163r2", "sect193r1",
        "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1",
        "sect571k1", "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1",
        "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1",
        "brainpoolp256r1", "brainpoolp384r1", "brainpoolp512r1", "x25519", "x448" };

    private static final String[] FINITE_FIELD_NAMES = new String[] { "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192" };

    public static boolean canBeNegotiated(int namedGroup, ProtocolVersion version)
    {
        if (TlsUtils.isTLSv13(version))
        {
            if ((namedGroup >= sect163k1 && namedGroup <= secp256k1)
                || (namedGroup >= brainpoolP256r1 && namedGroup <= brainpoolP512r1)
                || (namedGroup >= arbitrary_explicit_prime_curves && namedGroup <= arbitrary_explicit_char2_curves))
            {
                return false;
            }
        }

        return isValid(namedGroup);
    }

    public static int getByName(String name)
    {
        if (name != null)
        {
            for (int i = 0; i < CURVE_NAMES.length; ++i)
            {
                if (name.equals(CURVE_NAMES[i]))
                {
                    return sect163k1 + i;
                }
            }
            for (int i = 0; i < FINITE_FIELD_NAMES.length; ++i)
            {
                if (name.equals(FINITE_FIELD_NAMES[i]))
                {
                    return ffdhe2048 + i;
                }
            }
        }
        return -1;
    }

    public static int getCurveBits(int namedGroup)
    {
        switch (namedGroup)
        {
        case secp160k1:
        case secp160r1:
        case secp160r2:
            return 160;

        case sect163k1:
        case sect163r1:
        case sect163r2:
            return 163;

        case secp192k1:
        case secp192r1:
            return 192;

        case sect193r1:
        case sect193r2:
            return 193;

        case secp224k1:
        case secp224r1:
            return 224;

        case sect233k1:
        case sect233r1:
            return 233;

        case sect239k1:
            return 239;

        case x25519:
            return 252;

        case brainpoolP256r1:
        case secp256k1:
        case secp256r1:
            return 256;

        case sect283k1:
        case sect283r1:
            return 283;

        case brainpoolP384r1:
        case secp384r1:
            return 384;

        case sect409k1:
        case sect409r1:
            return 409;

        case x448:
            return 446;

        case brainpoolP512r1:
            return 512;

        case secp521r1:
            return 521;

        case sect571k1:
        case sect571r1:
            return 571;

        default:
            return 0;
        }
    }

    public static int getFiniteFieldBits(int namedGroup)
    {
        switch (namedGroup)
        {
        case ffdhe2048:
            return 2048;
        case ffdhe3072:
            return 3072;
        case ffdhe4096:
            return 4096;
        case ffdhe6144:
            return 6144;
        case ffdhe8192:
            return 8192;
        default:
            return 0;
        }
    }

    public static int getMaximumChar2CurveBits()
    {
        return 571;
    }

    public static int getMaximumCurveBits()
    {
        return 571;
    }

    public static int getMaximumFiniteFieldBits()
    {
        return 8192;
    }

    public static int getMaximumPrimeCurveBits()
    {
        return 521;
    }

    public static String getName(int namedGroup)
    {
        if (isPrivate(namedGroup))
        {
            return "PRIVATE";
        }

        if (namedGroup >= sect163k1 && namedGroup <= x448)
        {
            return CURVE_NAMES[namedGroup - sect163k1];
        }

        if (namedGroup >= ffdhe2048 && namedGroup <= ffdhe8192)
        {
            return FINITE_FIELD_NAMES[namedGroup - ffdhe2048];
        }

        switch (namedGroup)
        {
        case arbitrary_explicit_prime_curves:
            return "arbitrary_explicit_prime_curves";
        case arbitrary_explicit_char2_curves:
            return "arbitrary_explicit_char2_curves";
        default:
            return "UNKNOWN";
        }
    }

    public static String getText(int namedGroup)
    {
        return getName(namedGroup) + "(" + namedGroup + ")";
    }

    public static boolean isChar2Curve(int namedGroup)
    {
        return (namedGroup >= sect163k1 && namedGroup <= sect571r1)
            || (namedGroup == arbitrary_explicit_char2_curves);
    }

    public static boolean isPrimeCurve(int namedGroup)
    {
        return (namedGroup >= secp160k1 && namedGroup <= x448)
            || (namedGroup == arbitrary_explicit_prime_curves);
    }

    public static boolean isPrivate(int namedGroup)
    {
        return (namedGroup >>> 2) == 0x7F || (namedGroup >>> 8) == 0xFE;
    }

    public static boolean isValid(int namedGroup)
    {
        return refersToASpecificGroup(namedGroup)
            || isPrivate(namedGroup)
            || (namedGroup >= arbitrary_explicit_prime_curves && namedGroup <= arbitrary_explicit_char2_curves);
    }

    public static boolean refersToAnECDHCurve(int namedGroup)
    {
        return namedGroup >= sect163k1 && namedGroup <= x448;
    }

    public static boolean refersToAnECDSACurve(int namedGroup)
    {
        return namedGroup >= sect163k1 && namedGroup <= brainpoolP512r1;
    }

    public static boolean refersToAnXDHCurve(int namedGroup)
    {
        return namedGroup >= x25519 && namedGroup <= x448;
    }

    public static boolean refersToASpecificCurve(int namedGroup)
    {
        return namedGroup >= sect163k1 && namedGroup <= x448;
    }

    public static boolean refersToASpecificFiniteField(int namedGroup)
    {
        return namedGroup >= ffdhe2048 && namedGroup <= ffdhe8192;
    }

    public static boolean refersToASpecificGroup(int namedGroup)
    {
        return refersToASpecificCurve(namedGroup)
            || refersToASpecificFiniteField(namedGroup);
    }
}
