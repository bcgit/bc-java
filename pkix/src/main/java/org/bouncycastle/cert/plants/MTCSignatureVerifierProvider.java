package org.bouncycastle.cert.plants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Arrays;

/**
 * Single-cosigner {@link ContentVerifierProvider} adapter for MTC verification.
 *
 * <p>Wraps a single {@link MTCCosignerVerifier} so it can be plugged into the
 * generic BC operator surface that accepts a {@link ContentVerifierProvider}.
 * The provider has two modes, selected by which constructor is used:</p>
 *
 * <ul>
 *   <li><b>Manual mode</b> ({@link #MTCSignatureVerifierProvider(MTCCosignerVerifier)})
 *       — {@link #get(AlgorithmIdentifier)} returns the wrapped verifier
 *       directly. Callers drive cosignature verification themselves: write the
 *       {@link MTCCosignedSubtree} bytes through
 *       {@link ContentVerifier#getOutputStream()} and call
 *       {@link ContentVerifier#verify(byte[])} with the cosigner's
 *       signature.</li>
 *   <li><b>Certificate mode</b>
 *       ({@link #MTCSignatureVerifierProvider(MTCCertAuth, MTCCosignerVerifier)})
 *       — {@link #get(AlgorithmIdentifier)} returns a wrapping verifier that
 *       integrates with
 *       {@link X509CertificateHolder#isSignatureValid(ContentVerifierProvider)
 *       certHolder.isSignatureValid(provider)} for an MTC certificate,
 *       following Section 7.2 of draft-ietf-plants-merkle-tree-certs:
 *       <ol>
 *         <li>The DER-encoded TBSCertificate is captured from
 *             {@link ContentVerifier#getOutputStream()}.</li>
 *         <li>{@link ContentVerifier#verify(byte[])} receives the MTCProof
 *             bytes (the cert's {@code signatureValue}), checks the
 *             TBSCertificate names {@code id-alg-mtcProof}, takes the entry
 *             index and log number from the serial, recomputes the leaf hash
 *             (including the MTCProof's extensions) via
 *             {@link MerkleTreeCertificateValidator#computeEntryHash(byte[], byte[], MerkleTreeHash)},
 *             evaluates the inclusion proof for the MTCProof's subtree, builds
 *             the {@link MTCCosignedSubtree} for the MTCCosignature whose
 *             {@code cosigner_id} matches the wrapped verifier's
 *             {@link MTCCosignerVerifier#getCosignerId()} (signatures naming
 *             any other cosigner are unrecognized and ignored), and returns
 *             {@code true} if that cosignature verifies. Anything that fails
 *             to decode, or a serial that does not name a valid log entry,
 *             is a signature that does not verify ({@code false}). This
 *             matches single-cosigner deployments — a multi-cosigner /
 *             {@code minCosignatures > 1} policy, a {@link CosignerRequirement}, trusted subtrees or revoked
 *             ranges need {@link MerkleTreeCertificateValidator}.</li>
 *       </ol>
 *   </li>
 * </ul>
 *
 * <p>The adapter has no associated certificate;
 * {@link #hasAssociatedCertificate()} returns {@code false} and
 * {@link #getAssociatedCertificate()} returns {@code null}.</p>
 *
 * @see MTCCosignerVerifier
 */
public class MTCSignatureVerifierProvider
    implements ContentVerifierProvider
{
    private static final AlgorithmIdentifier MTC_SIG_ALG =
        new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
    private static final BigInteger UINT48_MASK = BigInteger.valueOf(MTCProof.UINT48_MAX);

    private final MTCCertAuth ca;
    private final MTCCosignerVerifier verifier;

    /**
     * Manual-mode constructor — see class javadoc.
     */
    public MTCSignatureVerifierProvider(MTCCosignerVerifier verifier)
    {
        this(null, verifier);
    }

    /**
     * Certificate-mode constructor — see class javadoc. Use this when passing
     * the provider to
     * {@link X509CertificateHolder#isSignatureValid(ContentVerifierProvider)}.
     */
    public MTCSignatureVerifierProvider(MTCCertAuth ca, MTCCosignerVerifier verifier)
    {
        if (verifier == null)
        {
            throw new NullPointerException("verifier cannot be null");
        }
        this.ca = ca;
        this.verifier = verifier;
    }

    public boolean hasAssociatedCertificate()
    {
        return false;
    }

    public X509CertificateHolder getAssociatedCertificate()
    {
        return null;
    }

    public ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier)
    {
        if (ca == null)
        {
            return verifier;
        }
        return new CertContentVerifier();
    }

    /**
     * Capture-and-validate ContentVerifier used in certificate mode. Buffers
     * the TBSCertificate bytes flowing through {@link #getOutputStream()},
     * then in {@link #verify(byte[])} performs the Section 7.2 subtree-hash
     * recovery and cosignature verification.
     */
    private final class CertContentVerifier
        implements ContentVerifier
    {
        private final ByteArrayOutputStream tbsBuf = new ByteArrayOutputStream();

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return MTC_SIG_ALG;
        }

        public OutputStream getOutputStream()
        {
            tbsBuf.reset();
            return tbsBuf;
        }

        public boolean verify(byte[] expected)
        {
            try
            {
                byte[] tbsDer = tbsBuf.toByteArray();
                TBSCertificate tbs = TBSCertificate.getInstance(tbsDer);

                // Step 1: the TBSCertificate's signature field is id-alg-mtcProof with absent parameters.
                AlgorithmIdentifier sigAlg = tbs.getSignature();
                if (!MTCObjectIdentifiers.id_alg_mtcProof.equals(sigAlg.getAlgorithm())
                    || sigAlg.getParameters() != null)
                {
                    return false;
                }

                // Steps 3 and 5: serial = (log_number << 48) | index, with log_number in [1, 2^16-1].
                BigInteger serial = tbs.getSerialNumber().getValue();
                if (serial.signum() <= 0 || serial.bitLength() > 64)
                {
                    return false;
                }
                long logNumber = serial.shiftRight(48).longValue();
                if (logNumber < 1 || logNumber > 0xFFFFL)
                {
                    return false;
                }
                long index = serial.and(UINT48_MASK).longValue();

                // Step 2: decode the signatureValue as an MTCProof.
                MTCProof proof = new MTCProof(expected);
                MTCLog log = new MTCLog(ca, logNumber, proof.getStart(), proof.getEnd());
                MerkleTreeHash hashFunc = ca.getHashFunc();

                // Steps 7-10: leaf hash over the log entry (extensions included), then the inclusion proof.
                byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(
                    tbsDer, proof.getExtensionsWire(), hashFunc);
                byte[] subtreeHash;
                try
                {
                    subtreeHash = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
                        index, proof.getStart(), proof.getEnd(), entryHash,
                        proof.getHashList(hashFunc.getHashSize()), hashFunc);
                }
                catch (IllegalArgumentException e)
                {
                    return false;
                }
                catch (InvalidProofException e)
                {
                    return false;
                }

                // Step 12, for the one cosigner this adapter knows about.
                byte[] boundCosignerId = verifier.getCosignerId();
                for (MTCCosignature sig : proof.getSignatures())
                {
                    // Only the signature attributed to the wrapped verifier's
                    // cosigner counts; signatures naming any other cosigner_id
                    // are unrecognized and ignored (Section 7.2 step 12), even
                    // if the wrapped key would verify them.
                    if (!Arrays.areEqual(boundCosignerId, sig.getCosignerId()))
                    {
                        continue;
                    }
                    byte[] cosignedMessage = MTCCosignedSubtree.encode(
                        log, subtreeHash, sig.getCosignerId());
                    OutputStream sOut = verifier.getOutputStream();
                    sOut.write(cosignedMessage);
                    sOut.close();
                    if (verifier.verify(sig.getSignature()))
                    {
                        return true;
                    }
                }
                return false;
            }
            catch (IOException e)
            {
                // A signatureValue that does not decode as an MTCProof is an
                // invalid signature (Section 7.2 step 2), not an error.
                return false;
            }
        }
    }
}
