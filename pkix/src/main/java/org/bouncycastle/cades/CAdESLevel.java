package org.bouncycastle.cades;

/**
 * CAdES baseline profile levels per ETSI EN&nbsp;319&nbsp;122-1, with the
 * older RFC&nbsp;5126 names alongside for callers that still target the
 * legacy specification. Each level is a strict superset of the one before it.
 * <ul>
 *   <li>{@link #B_B} ({@code BES}) &mdash; basic electronic signature: CMS
 *       SignedData with the mandatory ESS signing-certificate(-v2) reference
 *       and optional commitment-type, signature-policy, signer-location and
 *       content-hints signed attributes.</li>
 *   <li>{@link #B_T} ({@code T}) &mdash; B-B plus an
 *       {@code id-aa-signatureTimeStampToken} unsigned attribute carrying an
 *       RFC&nbsp;3161 token over the SignerInfo signature value.</li>
 *   <li>{@link #B_LT} ({@code C} / {@code X-L}) &mdash; B-T plus complete
 *       certificate / revocation references and the corresponding certificate
 *       / revocation value sets needed for offline long-term validation.</li>
 *   <li>{@link #B_LTA} ({@code A}) &mdash; B-LT plus one or more
 *       {@code id-aa-ets-archiveTimestampV3} unsigned attributes that protect
 *       the entire signature against weakening of the original signature
 *       algorithm.</li>
 * </ul>
 */
public enum CAdESLevel
{
    /** ETSI EN&nbsp;319&nbsp;122-1 B-B / RFC&nbsp;5126 BES. */
    B_B,
    /** ETSI EN&nbsp;319&nbsp;122-1 B-T / RFC&nbsp;5126 T. */
    B_T,
    /** ETSI EN&nbsp;319&nbsp;122-1 B-LT / RFC&nbsp;5126 C-X-L. */
    B_LT,
    /** ETSI EN&nbsp;319&nbsp;122-1 B-LTA / RFC&nbsp;5126 A. */
    B_LTA;

    /** Legacy RFC&nbsp;5126 alias for {@link #B_B}. */
    public static final CAdESLevel BES = B_B;
    /** Legacy RFC&nbsp;5126 alias for {@link #B_T}. */
    public static final CAdESLevel T = B_T;
}
