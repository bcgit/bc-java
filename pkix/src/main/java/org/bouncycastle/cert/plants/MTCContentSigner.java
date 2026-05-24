package org.bouncycastle.cert.plants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.Arrays;

/**
 * Issuer-side {@link ContentSigner} that emits an MTC {@code signatureValue}
 * (an encoded {@link MTCProof}) for an EE Merkle Tree certificate per
 * Section 6.1 of draft-ietf-plants-merkle-tree-certs.
 *
 * <p>The signer is plugged into the standard
 * {@link org.bouncycastle.cert.X509v3CertificateBuilder#build(ContentSigner)
 * X509v3CertificateBuilder.build(ContentSigner)} flow. As the TBSCertificate
 * DER bytes stream out of the builder into {@link #getOutputStream()}, this
 * class captures them; when {@link #getSignature()} is invoked it:</p>
 * <ol>
 *   <li>Derives the {@code MerkleTreeCertEntry} leaf hash and climbs one
 *       Merkle level using the single-sibling {@code inclusionProof} via
 *       {@link MerkleTreeCertificateValidator#computeSubtreeHash}.</li>
 *   <li>Delegates to {@link MTCCosigner#cosignSubtree} to produce the
 *       cosigner's {@link MTCSignature}.</li>
 *   <li>Wraps the inclusion proof and the cosigner signature in an
 *       {@link MTCProof} and returns its TLS wire encoding.</li>
 * </ol>
 *
 * <p>This is the simple-case binding used by the worked example: one
 * cosigner, a two-leaf log where the EE is at index 0 with one sibling leaf
 * at index 1. Issuers with multi-level inclusion proofs or multiple cosigners
 * should compose the {@link MTCCosigner}, {@link MTCProof} and
 * {@link MerkleTreeHash} primitives directly.</p>
 */
public class MTCContentSigner
    implements ContentSigner
{
    private static final AlgorithmIdentifier MTC_SIG_ALG =
        new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);

    private final MerkleTreeHash hashFunc;
    private final MTCLog log;
    private final byte[] inclusionProof;
    private final MTCCosigner cosigner;
    private final ByteArrayOutputStream tbsBuf = new ByteArrayOutputStream();

    /**
     * The cosigner's identity is taken from {@link MTCCosigner#getCosignerId()}
     * — the CA-as-cosigner case is just a {@link MTCCosigner} constructed with
     * {@code log.getCa().getCaId()} as its cosigner ID (Section 5.3 of the
     * draft). Witnesses, regulators, federated peers or any other entity with
     * a distinct trust anchor ID work via the same constructor by constructing
     * the cosigner with their own ID.
     *
     * @param log             issuance log + subtree window
     *                        {@code [log.getStart(), log.getEnd())} — also
     *                        supplies the CA (via {@link MTCLog#getCa()}) and
     *                        therefore the hash function and log ID
     * @param inclusionProof  the single sibling leaf hash that, combined with
     *                        the EE's leaf hash, yields the subtree hash —
     *                        same bytes that land in the resulting MTCProof
     * @param cosigner        cosigner driver bound to its trust anchor ID,
     *                        signature algorithm and key
     */
    public MTCContentSigner(
        MTCLog log, byte[] inclusionProof,
        MTCCosigner cosigner)
    {
        this.hashFunc = log.getCa().getHashFunc();
        this.log = log;
        this.inclusionProof = Arrays.clone(inclusionProof);
        this.cosigner = cosigner;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return MTC_SIG_ALG;
    }

    public OutputStream getOutputStream()
    {
        tbsBuf.reset();
        return tbsBuf;
    }

    public byte[] getSignature()
    {
        try
        {
            byte[] subtreeHash = MerkleTreeCertificateValidator.computeSubtreeHash(
                tbsBuf.toByteArray(), inclusionProof, hashFunc);
            MTCSignature sig = cosigner.cosignSubtree(log, subtreeHash);
            return new MTCProof(log, inclusionProof, sig).encode();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("MTC content signing failed: " + e.getMessage(), e);
        }
    }
}
