package org.bouncycastle.cert.plants;

/**
 * String constants for the cosigner signature algorithms defined by Section
 * 5.3.2 of draft-ietf-plants-merkle-tree-certs. These are the canonical names
 * passed to {@link MTCSignatureVerifier} implementations (and their concrete
 * {@code Bc*} / {@code Jca*} forms) to select a signature primitive.
 *
 * <p>Using the constant instead of an inline string lets a CI-time check catch
 * typos.</p>
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
