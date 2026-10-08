package org.bouncycastle.pkix.jcajce;

import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;

/**
 * The revocation status of a certificate (cert_status, RFC 5280 sec. 6.3.2 (b)), as accumulated over the
 * CRLs checked for it.
 * <p>
 * The reason code is kept apart from whether the certificate is revoked, so no value found in a CRL can
 * be mistaken for a status. UNDETERMINED is not tracked: it is concluded once CRL processing ends with
 * the certificate not revoked and the checked CRLs not covering all reasons.
 * </p>
 */
class CertStatus
{
    // Indexed by CRLReason value
    static final String[] crlReasons = new String[]
    {
        "unspecified",
        "keyCompromise",
        "cACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "unknown",
        "removeFromCRL",
        "privilegeWithdrawn",
        "aACompromise"
    };

    /**
     * Whether a reason code is one of the CRLReason values defined by RFC 5280 sec. 5.3.1.
     */
    static boolean isReasonCodeKnown(int reasonCode)
    {
        return reasonCode >= CRLReason.unspecified
            && reasonCode <= CRLReason.aACompromise
            && reasonCode != 7; // value 7 is not used (RFC 5280 sec. 5.3.1)
    }

    /**
     * The CRLReason to process a CRL entry by: its reason code if defined, else unspecified.
     *
     * @param reasonCode the entry's reason code, or null if absent or outside the int range.
     */
    static int getReason(Integer reasonCode)
    {
        if (reasonCode != null && isReasonCodeKnown(reasonCode.intValue()))
        {
            return reasonCode.intValue();
        }

        return CRLReason.unspecified;
    }

    private Date revocationDate = null;
    private Integer reasonCode = null;

    boolean isRevoked()
    {
        return revocationDate != null;
    }

    /**
     * @return the CRL entry's revocation date, or null if the certificate has not been found revoked.
     */
    Date getRevocationDate()
    {
        return revocationDate;
    }

    /**
     * @return the CRL entry's reason code as given, or null if it is absent, outside the int range, or
     *         the certificate has not been found revoked.
     */
    Integer getReasonCode()
    {
        return reasonCode;
    }

    /**
     * @return the CRLReason to process the revocation by (see {@link #getReason(Integer)}).
     */
    int getReason()
    {
        return getReason(reasonCode);
    }

    /**
     * The reason for a revocation message: the name of {@link #getReason()}, or the reason code as given
     * if it is not a defined CRLReason.
     */
    String getReasonText()
    {
        if (reasonCode != null && !isReasonCodeKnown(reasonCode.intValue()))
        {
            return "(unknown code: " + reasonCode + ")";
        }

        return crlReasons[getReason()];
    }

    void setRevoked(Date revocationDate, Integer reasonCode)
    {
        this.revocationDate = revocationDate;
        this.reasonCode = reasonCode;
    }

    /**
     * Clear a removeFromCRL revocation (RFC 5280 sec. 6.3.3 (k)).
     */
    void setUnrevoked()
    {
        this.revocationDate = null;
        this.reasonCode = null;
    }
}
