package org.bouncycastle.tls;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * RFC 4492 5.1.1
 * <p>
 * The named curves defined here are those specified in SEC 2 [13]. Note that many of these curves
 * are also recommended in ANSI X9.62 [7] and FIPS 186-2 [11]. Values 0xFE00 through 0xFEFF are
 * reserved for private use. Values 0xFF01 and 0xFF02 indicate that the client supports arbitrary
 * prime and characteristic-2 curves, respectively (the curve parameters must be encoded explicitly
 * in ECParameters).
 */
public class NamedCurve
{
    private static final String[] CURVE_NAMES = new String[] { "sect163k1", "sect163r1", "sect163r2", "sect193r1",
        "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1",
        "sect571k1", "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1",
        "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1",
        "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"};

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
     * reserved (0xFE00..0xFEFF)
     */

    public static final int arbitrary_explicit_prime_curves = 0xFF01;
    public static final int arbitrary_explicit_char2_curves = 0xFF02;

    public static final Set<Integer> ALL;
    public static final Set<Integer> FIPS_APPROVED;

    static
    {
        Set<Integer> curves = new HashSet<Integer>();

        for (int i = 0; i <= 28; i++)
        {
            curves.add(i);
        }

        curves.add(arbitrary_explicit_prime_curves);
        curves.add(arbitrary_explicit_char2_curves);

        ALL = Collections.unmodifiableSet(curves);

        curves = new HashSet<Integer>();

        curves.add(secp224k1);
        curves.add(secp224r1);
        curves.add(secp256k1);
        curves.add(secp256r1);
        curves.add(secp384r1);
        curves.add(secp521r1);

        curves.add(brainpoolP256r1);
        curves.add(brainpoolP384r1);
        curves.add(brainpoolP512r1);

        FIPS_APPROVED = Collections.unmodifiableSet(curves);
    }

    public static int getCurveBits(int namedCurve)
    {
        switch (namedCurve)
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

    public static int getMaximumCurveBits()
    {
        return 571;
    }

    public static String getName(int namedCurve)
    {
        if (!isValid(namedCurve))
        {
            return null;
        }

        switch (namedCurve)
        {
        case arbitrary_explicit_prime_curves:
            return "arbitrary_explicit_prime_curves";
        case arbitrary_explicit_char2_curves:
            return "arbitrary_explicit_char2_curves";
        default:
            return CURVE_NAMES[namedCurve - 1];
        }
    }

    public static String getNameOfSpecificCurve(int namedCurve)
    {
        if (!refersToASpecificNamedCurve(namedCurve))
        {
            return null;
        }

        return CURVE_NAMES[namedCurve - 1];
    }

    public static boolean isChar2(int namedCurve)
    {
        return (namedCurve >= sect163k1 && namedCurve <= sect571r1);
    }

    public static boolean isPrime(int namedCurve)
    {
        return (namedCurve >= secp160k1 && namedCurve <= brainpoolP512r1);
    }

    public static boolean isValid(int namedCurve)
    {
        return (namedCurve >= sect163k1 && namedCurve <= brainpoolP512r1)
            || (namedCurve >= arbitrary_explicit_prime_curves && namedCurve <= arbitrary_explicit_char2_curves);
    }

    public static boolean refersToASpecificNamedCurve(int namedCurve)
    {
        switch (namedCurve)
        {
        case arbitrary_explicit_prime_curves:
        case arbitrary_explicit_char2_curves:
            return false;
        default:
            return true;
        }
    }
}
