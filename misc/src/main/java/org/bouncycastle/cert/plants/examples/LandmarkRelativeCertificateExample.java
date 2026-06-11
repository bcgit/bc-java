package org.bouncycastle.cert.plants.examples;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.Validity;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.plants.LandmarkCertificateManager;
import org.bouncycastle.cert.plants.LandmarkSequence;
import org.bouncycastle.cert.plants.MTCCertAuth;
import org.bouncycastle.cert.plants.MTCLog;
import org.bouncycastle.cert.plants.MTCSignature;
import org.bouncycastle.cert.plants.MerkleTreeCertificateValidator;
import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.TrustAnchorIDs;
import org.bouncycastle.cert.plants.bc.BcMTCCosigner;
import org.bouncycastle.cert.plants.bc.BcMTCCosignerVerifierProvider;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

/**
 * End-to-end walkthrough of a <em>landmark-relative</em> Merkle Tree
 * certificate (Section 6.3 of draft-ietf-plants-merkle-tree-certs) —
 * the signatureless counterpart of the standalone certificates built in
 * {@link MerkleTreeCertificateExample}.
 *
 * <p>The flow has three parts:</p>
 * <ol>
 *   <li><b>CA side</b> — a four-entry issuance log is built in-memory and a
 *       landmark sequence (Section 6.3.3) publishes landmark 1 at tree size 4.
 *       Its covering subtrees (Section 4.5) are {@code [0, 2)} and
 *       {@code [2, 4)}; the EE's log entry at index 1 lies in the first, and
 *       {@link LandmarkCertificateManager#buildLandmarkCertificate} wraps its
 *       inclusion proof into a certificate whose {@code MTCProof} carries
 *       <em>no signatures</em> (Section 6.3.4).</li>
 *   <li><b>Relying-party update channel</b> — before such a certificate can
 *       validate, the relying party must already trust the landmark subtree.
 *       {@link LandmarkCertificateManager.TrustedSubtreeManager} accepts it
 *       per Section 7.4: a reference checkpoint cosigned by enough trusted
 *       cosigners (here the CA cosigner itself) plus a subtree consistency
 *       proof relating the landmark subtree to that checkpoint.</li>
 *   <li><b>Validation</b> — {@link MerkleTreeCertificateValidator} matches the
 *       proof's {@code (log_number, start, end)} against the predistributed
 *       trusted subtree and compares hashes (Section 7.2 step 11); no
 *       cosignature check runs at validation time.</li>
 * </ol>
 */
public class LandmarkRelativeCertificateExample
{
    /** Trust anchor ID assigned to our example CA. */
    private static final String CA_TRUST_ANCHOR_ID = "32473.1";

    /** Log number used in the cert's 64-bit serial (top 16 bits). */
    private static final long LOG_NUMBER = 1L;

    public static void main(String[] args)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // 1. CA identity bundle and cosigner keypair, as in the standalone
        //    example.
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair caKp = gen.generateKeyPair();
        MTCCertAuth ca = new MTCCertAuth(
            CA_TRUST_ANCHOR_ID,
            new org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash(),
            MTCObjectIdentifiers.id_alg_mtcProof);
        MerkleTreeHash hashFunc = ca.getHashFunc();
        System.out.println("CA trust anchor ID:    " + ca.getDottedCaId());

        // 2. The CA publishes a landmark sequence (Section 6.3.3): landmark 1
        //    at tree size 4, landmark 0 always at size 0. Per Section 4.5 the
        //    interval [0, 4) is covered by the two landmark subtrees [0, 2)
        //    and [2, 4); the EE entry at index 1 lies in the first.
        LandmarkSequence landmarks = LandmarkSequence.parse("1 1\n4\n0\n");
        long[] landmarkSubtree = landmarks.activeLandmarkSubtrees().get(0);
        long start = landmarkSubtree[0];     // 0
        long end = landmarkSubtree[1];       // 2
        MTCLog landmark = new MTCLog(ca, LOG_NUMBER, start, end);
        System.out.println("Landmark subtree:      [" + start + ", " + end + ") of log "
            + TrustAnchorIDs.toDottedDecimal(landmark.getLogId()));

        // 3. The EE's TBSCertificateLogEntry (Section 5.2.1) — the log-entry
        //    form of the certificate, with the SubjectPublicKeyInfo replaced
        //    by its algorithm and hash.
        AsymmetricCipherKeyPair eeKp = gen.generateKeyPair();
        SubjectPublicKeyInfo eeSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(eeKp.getPublic());
        long now = System.currentTimeMillis();
        TBSCertificateLogEntry tbsEntry = new TBSCertificateLogEntry(
            new ASN1Integer(0),
            ca.issuerName(),
            new Validity(new Time(new Date(now)), new Time(new Date(now + 24L * 60 * 60 * 1000))),
            new X500Name("CN=mtc-landmark-example-ee"),
            eeSpki.getAlgorithm(),
            new DEROctetString(hashFunc.hashRaw(eeSpki.getEncoded(ASN1Encoding.DER))),
            null, null, null);

        // 4. The issuance log: four entries, the EE's at index 1. The
        //    inclusion proof does not affect the TBSCertificate, so the EE's
        //    leaf hash can be derived from a first pass with an empty proof;
        //    the certificate is then rebuilt with the real proof.
        long index = 1;
        X509CertificateHolder pass1 = LandmarkCertificateManager.buildLandmarkCertificate(
            landmark, index, tbsEntry, eeSpki, Collections.<byte[]>emptyList());
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(pass1, hashFunc);

        byte[] leaf0 = hashFunc.hashLeaf("entry-0".getBytes());
        byte[] leaf2 = hashFunc.hashLeaf("entry-2".getBytes());
        byte[] leaf3 = hashFunc.hashLeaf("entry-3".getBytes());
        byte[] landmarkHash = hashFunc.hashNode(leaf0, entryHash);     // MTH(D[0:2])
        byte[] node23 = hashFunc.hashNode(leaf2, leaf3);               // MTH(D[2:4])
        byte[] checkpointRoot = hashFunc.hashNode(landmarkHash, node23); // MTH(D[0:4])

        // Inclusion proof for index 1 in the landmark subtree [0, 2): the
        // single sibling leaf 0, combined on the left.
        List<byte[]> inclusionProof = Collections.singletonList(leaf0);

        X509CertificateHolder cert = LandmarkCertificateManager.buildLandmarkCertificate(
            landmark, index, tbsEntry, eeSpki, inclusionProof);
        System.out.println("Cert encoded length:   " + cert.getEncoded().length
            + " bytes (no signatures in the MTCProof)");

        // 5. Relying-party update channel (Section 7.4). The CA cosigner signs
        //    the reference checkpoint [0, 4); the landmark subtree [0, 2) is
        //    then related to it with a subtree consistency proof (Section 4.4)
        //    — here the single node MTH(D[2:4]).
        BcMTCCosignerVerifierProvider cosigners = new BcMTCCosignerVerifierProvider.Builder()
            .addCosigner(ca.getCaId(), caKp.getPublic())
            .build();
        LandmarkCertificateManager.TrustedSubtreeManager manager =
            new LandmarkCertificateManager.TrustedSubtreeManager(
                landmark.getLogId(), hashFunc, cosigners, /*minCosignaturesForCheckpoint=*/ 1);

        MTCLog checkpointWindow = new MTCLog(ca, LOG_NUMBER, 0, 4);
        MTCSignature checkpointSig = new BcMTCCosigner(ca.getCaId(), caKp.getPrivate())
            .cosignSubtree(checkpointWindow, checkpointRoot);
        boolean accepted = manager.addLandmarkSubtree(
            start, end, landmarkHash,
            new LandmarkCertificateManager.TrustedSubtreeManager.Checkpoint(4, checkpointRoot),
            Collections.singletonList(node23),
            Collections.singletonList(checkpointSig));
        System.out.println("Landmark accepted:     " + accepted);

        // 6. Validation (Section 7.2 step 11): the trusted subtree is matched
        //    on (log_number, start, end) and the hashes compared. The cosigner
        //    provider plays no role on this path.
        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                hashFunc,
                Collections.singletonList(
                    manager.getTrustedSubtrees().get(0).toTrustedSubtree(LOG_NUMBER)),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                /*minCosignatures=*/ 1);

        boolean valid = MerkleTreeCertificateValidator.validateCertificate(cert, params);
        System.out.println("Validation result:     " + (valid ? "PASS" : "FAIL"));
    }
}
