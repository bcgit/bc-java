package org.bouncycastle.cades;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.SignerInformation;

/**
 * Inspect a {@link SignerInformation} and report the highest CAdES baseline
 * level (per ETSI EN&nbsp;319&nbsp;122-1) whose mandatory attributes are
 * present. The detector does not validate the timestamp token or run cert
 * path validation &mdash; it inspects the attribute table only.
 * <p>
 * Recognises B-B, B-T, B-LT and B-LTA. The B-LTA check accepts either the
 * legacy RFC&nbsp;5126 {@code id-aa-ets-archiveTimestamp} (v1) attribute or
 * the cleaned-up ETSI TS&nbsp;101&nbsp;733 v1.7.4
 * {@code id-aa-ets-archiveTimestampV2}; ETSI EN&nbsp;319&nbsp;122-1 v3 is not
 * yet recognised.
 */
public final class CAdESLevelDetector
{
    private CAdESLevelDetector()
    {
    }

    /**
     * Return the highest CAdES level whose mandatory attributes are present
     * on the supplied signer, or {@code null} if not even B-B is satisfied
     * (the ESS signing-certificate(-v2) reference is missing).
     */
    public static CAdESLevel attainedLevel(SignerInformation signer)
    {
        if (signer == null)
        {
            throw new NullPointerException("signer");
        }
        AttributeTable signed = signer.getSignedAttributes();
        AttributeTable unsigned = signer.getUnsignedAttributes();

        // B-B prerequisite: ESS signing-certificate (RFC 5035) or v2.
        if (signed == null
            || (signed.get(PKCSObjectIdentifiers.id_aa_signingCertificate) == null
                && signed.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) == null))
        {
            return null;
        }

        if (unsigned == null
            || unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) == null)
        {
            return CAdESLevel.B_B;
        }

        // B-LT prerequisite (RFC 5126 X-L / ETSI EN 319 122-1 B-LT): the
        // full quartet of long-term refs + values. Refs alone (the older
        // CAdES-C tier) collapses into B-T here, since refs without values
        // are not enough for offline validation.
        boolean ltAttrs = unsigned.get(PKCSObjectIdentifiers.id_aa_ets_certValues) != null
            && unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null
            && unsigned.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs) != null
            && unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs) != null;
        if (!ltAttrs)
        {
            return CAdESLevel.B_T;
        }

        // B-LTA prerequisite: at least one archive-time-stamp (v1 or v2)
        // unsigned attribute over the SignedData.
        if (unsigned.get(CAdESArchiveTimestampUtil.id_aa_ets_archiveTimestampV2) != null
            || unsigned.get(PKCSObjectIdentifiers.id_aa_ets_archiveTimestamp) != null)
        {
            return CAdESLevel.B_LTA;
        }

        return CAdESLevel.B_LT;
    }
}
