package org.bouncycastle.cert.plants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

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
 *       {@link MTCCosignedMessage} bytes through
 *       {@link ContentVerifier#getOutputStream()} and call
 *       {@link ContentVerifier#verify(byte[])} with the cosigner's
 *       signature.</li>
 *   <li><b>Certificate mode</b>
 *       ({@link #MTCSignatureVerifierProvider(MTCCertAuth, MTCCosignerVerifier)})
 *       — {@link #get(AlgorithmIdentifier)} returns a wrapping verifier that
 *       integrates with
 *       {@link X509CertificateHolder#isSignatureValid(ContentVerifierProvider)
 *       certHolder.isSignatureValid(provider)} for an MTC certificate:
 *       <ol>
 *         <li>The DER-encoded TBSCertificate is captured from
 *             {@link ContentVerifier#getOutputStream()}.</li>
 *         <li>{@link ContentVerifier#verify(byte[])} receives the MTCProof
 *             bytes (the cert's {@code signatureValue}), reparses them,
 *             recomputes the subtree hash via
 *             {@link MerkleTreeCertificateValidator#computeSubtreeHash},
 *             builds the {@link MTCCosignedMessage} for the MTCSignature whose
 *             {@code cosigner_id} matches the wrapped verifier's
 *             {@link MTCCosignerVerifier#getCosignerId()} (signatures naming
 *             any other cosigner are unrecognized and ignored), and returns
 *             {@code true} if that cosignature verifies. This matches
 *             single-cosigner deployments — a multi-cosigner /
 *             {@code minCosignatures > 1} policy should continue to use
 *             {@link MerkleTreeCertificateValidator}.</li>
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
     * then in {@link #verify(byte[])} performs the MTC subtree-hash recovery
     * and cosignature verification.
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
                long logNumber = BigIntegers.longValueExact(tbs.getSerialNumber().getValue().shiftRight(48));

                MTCProof proof = new MTCProof(expected);
                MTCLog log = new MTCLog(ca, logNumber, proof.getStart(), proof.getEnd());

                byte[] subtreeHash = MerkleTreeCertificateValidator.computeSubtreeHash(
                    tbsDer, proof.getInclusionProof(), ca.getHashFunc());

                byte[] boundCosignerId = verifier.getCosignerId();
                for (MTCSignature sig : proof.getSignatures())
                {
                    // Only the signature attributed to the wrapped verifier's
                    // cosigner counts; signatures naming any other cosigner_id
                    // are unrecognized and ignored (Section 7.2 step 12), even
                    // if the wrapped key would verify them.
                    if (!Arrays.areEqual(boundCosignerId, sig.getCosignerId()))
                    {
                        continue;
                    }
                    byte[] cosignedMessage = MTCCosignedMessage.encode(
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
                throw new IllegalStateException(
                    "MTC certificate verification failed: " + e.getMessage(), e);
            }
        }
    }
}
