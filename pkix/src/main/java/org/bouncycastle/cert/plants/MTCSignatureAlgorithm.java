package org.bouncycastle.cert.plants;

/**
 * String constants naming the cosigner signature algorithms this package binds.
 * draft-ietf-plants-merkle-tree-certs fixes no list of algorithms: Section 5.3.3
 * leaves the algorithm to the cosigner's public key, which the relying party is
 * configured with, so these names are BC's own and never appear on the wire.
 * They are the canonical names
 * passed to {@link MTCSignatureVerifier} implementations (and their concrete
 * {@code Bc*} / {@code Jca*} forms) to select a signature primitive.
 *
 * <p>Using the constant instead of an inline string lets a CI-time check catch
 * typos.</p>
 *
 * <p>The cosignature bytes under the two ECDSA names are the DER encoding of
 * the X9.62 {@code ECDSA-Sig-Value} SEQUENCE, as produced by the JCA
 * {@code SHA256withECDSA} / {@code SHA384withECDSA} algorithms and by the
 * working group's reference implementation; the draft leaves the encoding to
 * the cosigner, and releases before 1.87 used the fixed-width r||s form
 * instead.</p>
 */
public final class MTCSignatureAlgorithm
{
    public static final String ECDSA_P256_SHA256 = "ECDSA-P256-SHA256";
    public static final String ECDSA_P384_SHA384 = "ECDSA-P384-SHA384";
    public static final String ED25519           = "Ed25519";
    public static final String ML_DSA_44         = "ML-DSA-44";
    public static final String ML_DSA_65         = "ML-DSA-65";
    public static final String ML_DSA_87         = "ML-DSA-87";

    private MTCSignatureAlgorithm()
    {
    }
}
