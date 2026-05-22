package org.bouncycastle.cert.plants;

/**
 * Looks up an {@link MTCCosignerVerifier} for a given cosigner trust anchor ID.
 *
 * <p>Provider implementations encapsulate the relying party's table of trusted
 * cosigner public keys and the dispatch from a cosigner identifier to the
 * lightweight or JCA-side signature primitive that verifies that cosigner's
 * signatures. Section 7.2 of
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/">draft-ietf-plants-merkle-tree-certs</a>
 * requires unrecognised cosigners to be ignored rather than rejected, so this
 * method returns {@code null} for an unknown cosigner instead of throwing.</p>
 */
public interface MTCCosignerVerifierProvider
{
    /**
     * @param cosignerId the binary trust anchor ID of the cosigner
     * @return a verifier for the cosigner, or {@code null} if the cosigner is unknown
     */
    MTCCosignerVerifier get(byte[] cosignerId);
}
