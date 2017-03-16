package org.bouncycastle.openpgp.wot;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.wot.internal.TrustDbImpl;

/**
 * Validity of a key or user-identity/-attribute.
 * <p>
 * The validity is calculated by {@link TrustDbImpl#updateTrustDb()} and can be queried by its
 * {@link TrustDbImpl#getValidity(org.bouncycastle.openpgp.wot.key.PgpKey) getValidity(PgpKey)} or another overloaded
 * {@code getValidity(...)} method.
 */
public enum Validity
{

    /**
     * The key/user-identity/user-attribute is not valid or the validity is not known.
     * <p>
     * A user should be warned when using or encountering such a key (e.g. a red indication colour is a good idea).
     */
    NONE(TrustConst.TRUST_UNKNOWN), // 0

//    EXPIRED(TrustConst.TRUST_EXPIRED), // 1

    /**
     * The key/user-identity/user-attribute is not valid. The 'undefined' state results from trust originating
     * transitively from keys being expired, revoked or otherwise not trustworthy, anymore.
     * <p>
     * A user should be warned when using or encountering such a key (e.g. a red indication colour is a good idea).
     */
    UNDEFINED(TrustConst.TRUST_UNDEFINED), // 2

    /**
     * The key/user-identity/user-attribute is probably valid. There is some indication for its authenticity.
     * <p>
     * A user might get a mild warning when using or encountering such a key (e.g. a yellow/orange indication colour),
     * though it is probably fine.
     */
    MARGINAL(TrustConst.TRUST_MARGINAL), // 4

    /**
     * The key/user-identity/user-attribute is valid. There is strong indication for its authenticity.
     * <p>
     * A user should see some positive confirmation (e.g. a green indication colour) when using or encountering such a
     * key.
     */
    FULL(TrustConst.TRUST_FULL), // 5

    /**
     * The key/user-identity/user-attribute is definitely valid - probably it's belonging to the user himself. There is
     * no doubt about its authenticity.
     * <p>
     * A user should see some positive confirmation (e.g. a green indication colour) when using or encountering such a
     * key.
     */
    ULTIMATE(TrustConst.TRUST_ULTIMATE) // 6
    ;

    private final int numericValue;

    private static volatile Map<Integer, Validity> numericValue2Validity;

    private Validity(final int numericValue)
    {
        this.numericValue = numericValue;
    }

    public int getNumericValue()
    {
        return numericValue;
    }

    public static Validity fromNumericValue(final int numericValue)
    {
        final Validity validity = getNumericValue2Validity().get(numericValue);
        if (validity == null)
            throw new IllegalArgumentException("numericValue unknown: " + numericValue);

        return validity;
    }

    private static Map<Integer, Validity> getNumericValue2Validity()
    {
        if (numericValue2Validity == null)
        {
            Map<Integer, Validity> m = new HashMap<>(values().length);
            for (Validity ownerTrust : values())
                m.put(ownerTrust.getNumericValue(), ownerTrust);

            numericValue2Validity = m;
        }
        return numericValue2Validity;
    }
}
