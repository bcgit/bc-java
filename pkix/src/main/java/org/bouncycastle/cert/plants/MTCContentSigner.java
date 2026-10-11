package org.bouncycastle.cert.plants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.Arrays;

/**
 * Issuer-side {@link ContentSigner} that emits an MTC {@code signatureValue}
 * (an encoded {@link MTCProof}) for an EE Merkle Tree certificate per
 * Section 6.2 of draft-ietf-plants-merkle-tree-certs.
 *
 * <p>The signer is plugged into the standard
 * {@link org.bouncycastle.cert.X509v3CertificateBuilder#build(ContentSigner)
 * X509v3CertificateBuilder.build(ContentSigner)} flow. As the TBSCertificate
 * DER bytes stream out of the builder into {@link #getOutputStream()}, this
 * class captures them; when {@link #getSignature()} is invoked it:</p>
 * <ol>
 *   <li>Takes the entry's index from the serial number the builder wrote
 *       ({@code serial = (log_number << 48) | index}, Section 6.2), checking
 *       the log number is that of the supplied {@link MTCLog}.</li>
 *   <li>Derives the {@code MTCLogEntry} leaf hash via
 *       {@link MerkleTreeCertificateValidator#computeEntryHash(byte[], MerkleTreeHash)}
 *       and evaluates the supplied inclusion proof for that index within the
 *       log's subtree {@code [start, end)} (Section 4.3.2) to obtain the
 *       subtree hash.</li>
 *   <li>Delegates to {@link MTCCosigner#cosignSubtree} to produce the
 *       cosigner's {@link MTCCosignature}.</li>
 *   <li>Wraps the inclusion proof and the cosigner signature in an
 *       {@link MTCProof} and returns its TLS wire encoding.</li>
 * </ol>
 *
 * <p>This is the single-cosigner binding used by the worked examples: a
 * <em>standalone certificate</em> (Section 6.3 of the draft) carrying one
 * cosigner signature and no log-entry extensions. Issuers with multiple
 * cosigners or extensions should compose the {@link MTCCosigner},
 * {@link MTCProof} and {@link MerkleTreeHash} primitives directly;
 * landmark-relative certificates (Section 6.4, no signatures) are built via
 * {@link LandmarkCertificateManager#buildLandmarkCertificate}.</p>
 */
public class MTCContentSigner
    implements ContentSigner
{
    private static final AlgorithmIdentifier MTC_SIG_ALG =
        new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
    private static final BigInteger UINT48_MASK = BigInteger.valueOf(MTCProof.UINT48_MAX);

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
     * @param inclusionProof  the subtree inclusion proof (Section 4.3) for the
     *                        EE's entry, as the concatenated sibling hashes
     *                        from the leaf up to the subtree root — the same
     *                        bytes that land in the resulting MTCProof (a
     *                        single sibling hash for a two-entry subtree)
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
            byte[] tbsDer = tbsBuf.toByteArray();
            BigInteger serial = TBSCertificate.getInstance(tbsDer).getSerialNumber().getValue();
            if (serial.signum() <= 0 || serial.bitLength() > 64
                || serial.shiftRight(48).longValue() != log.getLogNumber())
            {
                throw new IllegalStateException(
                    "certificate serial " + serial + " does not name issuance log " + log.getLogNumber());
            }
            long index = serial.and(UINT48_MASK).longValue();

            MTCProof unsigned = new MTCProof(log, inclusionProof);
            byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(tbsDer, hashFunc);
            byte[] subtreeHash = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
                index, log.getStart(), log.getEnd(), entryHash,
                unsigned.getHashList(hashFunc.getHashSize()), hashFunc);

            MTCCosignature sig = cosigner.cosignSubtree(log, subtreeHash);
            return new MTCProof(log, inclusionProof, sig).encode();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("MTC content signing failed: " + e.getMessage(), e);
        }
        catch (InvalidProofException e)
        {
            throw new IllegalStateException("MTC content signing failed: " + e.getMessage(), e);
        }
    }
}
