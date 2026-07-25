package org.bouncycastle.pkix.jcajce;

import org.bouncycastle.asn1.x509.ReasonFlags;

/**
 * This class helps to handle CRL revocation reasons mask. Each CRL handles a certain set of
 * revocation reasons.
 */
class ReasonsMask
{
    /**
     * A mask with all revocation reasons.
     */
    static final int ALL_REASONS = ReasonFlags.aACompromise | ReasonFlags.affiliationChanged |
        ReasonFlags.cACompromise | ReasonFlags.certificateHold | ReasonFlags.cessationOfOperation |
        ReasonFlags.keyCompromise | ReasonFlags.privilegeWithdrawn | ReasonFlags.unused | ReasonFlags.superseded;
    
    private int _reasons;

    /**
     * A reason mask with no reason.
     */
    ReasonsMask()
    {
        this(0);
    }

    /**
     * Constructs a reason mask with the given reasons.
     *
     * @param reasons The reasons.
     */
    ReasonsMask(int reasons)
    {
        _reasons = reasons;
    }

    /**
     * Adds all reasons from the reasons mask to this mask.
     *
     * @param mask The reasons mask to add.
     */
    void addReasons(ReasonsMask mask)
    {
        _reasons |= mask._reasons;
    }

    /**
     * Returns <code>true</code> if this reasons mask contains all possible reasons.
     *
     * @return <code>true</code> if this reasons mask contains all possible reasons.
     */
    boolean isAllReasons()
    {
        return !hasNewReasons(this._reasons, ALL_REASONS);
    }

    /**
     * Returns <code>true</code> if the passed reasons mask has new reasons.
     * 
     * @param mask The reasons mask which should be tested for new reasons.
     * @return <code>true</code> if the passed reasons mask has new reasons.
     */
    boolean hasNewReasons(ReasonsMask mask)
    {
        return hasNewReasons(this._reasons, mask._reasons);
    }

    private static boolean hasNewReasons(int existingReasons, int candidateReasons)
    {
        return (candidateReasons & ~existingReasons) != 0;
    }
}
