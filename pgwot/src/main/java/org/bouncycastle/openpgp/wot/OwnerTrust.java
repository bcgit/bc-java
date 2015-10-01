package org.bouncycastle.openpgp.wot;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.wot.internal.TrustDbImpl;

/**
 * The owner-trust is assigned to a key, but does <i>not</i> describe the key itself. It specifies how reliable the
 * <i>owner</i> of this key is in his function as notary certifying other keys.
 * <p>
 * When judging the owner-trust of a person, you should answer the following questions:
 * <ul>
 * <li>How well does this person understand OpenPGP?
 * <li>How well does this person protect his computer's integrity and most importantly his private key?
 * <li>How well does this person check the authenticity of another key before signing (= certifying) it?
 * <li>Would this person certify a key in bad faith?
 * </ul>
 * <p>
 * Whether you trust this person on a personal level, should have only a minor influence on the owner-trust. For
 * example, you certainly trust your mother, but unless she's really computer-savvy, you likely assign a low owner-trust
 * to her key.

 * @see TrustDbImpl#getOwnerTrust(org.bouncycastle.openpgp.wot.key.PgpKey)
 */
public enum OwnerTrust
{
    /**
     * It is unknown, how reliable the key's owner is as notary for other keys.
     * <p>
     * This causes no transitive trust.
     */
    UNKNOWN(TrustConst.TRUST_UNKNOWN), // 0

    /**
     * The key's owner should not be trusted.
     * <p>
     * This causes no transitive trust.
     */
    NEVER(TrustConst.TRUST_NEVER), // 3

    /**
     * The key's owner is a marginally trustable notary. Certifications of keys made by this key's owner can thus be
     * trusted a little.
     * <p>
     * This causes some transitive trust. Together with other "marginally" trusted owner's certifications, it might
     * cause a key to be trusted fully.
     */
    MARGINAL(TrustConst.TRUST_MARGINAL), // 4

    /**
     * The key's owner is a fully trusted notary. Certificaton of keys made by this key's owner are thus considered very
     * reliable.
     * <p>
     * This causes significant transitive trust. Depending on the settings, this is already enough for a certified key
     * to be trusted fully, or it might require further signatures.
     */
    FULL(TrustConst.TRUST_FULL), // 5

    /**
     * The key's owner can be ultimately trusted. One single signature of a notary whose key is marked 'ultimate' is
     * sufficient for full transitive trust.
     * <p>
     * Usually, the user himself marks all his own keys with this owner-trust.
     */
    ULTIMATE(TrustConst.TRUST_ULTIMATE) // 6
    ;

    private final int numericValue;

    private static volatile Map<Integer, OwnerTrust> numericValue2OwnerTrust;

    private OwnerTrust(final int numericValue)
    {
        this.numericValue = numericValue;
    }

    public int getNumericValue()
    {
        return numericValue;
    }

    public static OwnerTrust fromNumericValue(final int numericValue)
    {
        final OwnerTrust ownerTrust = getNumericValue2OwnerTrust().get(numericValue);
        if (ownerTrust == null)
            throw new IllegalArgumentException("numericValue unknown: " + numericValue);

        return ownerTrust;
    }

    private static Map<Integer, OwnerTrust> getNumericValue2OwnerTrust()
    {
        if (numericValue2OwnerTrust == null)
        {
            Map<Integer, OwnerTrust> m = new HashMap<>(values().length);
            for (OwnerTrust ownerTrust : values())
                m.put(ownerTrust.getNumericValue(), ownerTrust);

            numericValue2OwnerTrust = m;
        }
        return numericValue2OwnerTrust;
    }
}
