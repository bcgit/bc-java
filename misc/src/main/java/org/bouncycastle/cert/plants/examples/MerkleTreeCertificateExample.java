package org.bouncycastle.cert.plants.examples;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.MTCCertificationAuthority;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.Validity;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.plants.MTCCosignedMessage;
import org.bouncycastle.cert.plants.MTCProof;
import org.bouncycastle.cert.plants.MTCSignature;
import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.cert.plants.MerkleTreeCertificateValidator;
import org.bouncycastle.cert.plants.TrustAnchorIDs;
import org.bouncycastle.cert.plants.bc.BcMTCCosignerVerifierProvider;
import org.bouncycastle.cert.plants.bc.BcMTCSignatureVerifier;
import org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

/**
 * End-to-end Merkle Tree Certificate walkthrough using a single CA cosigner.
 *
 * <p>The example builds a two-leaf log in-memory, issues a Merkle Tree
 * certificate for entry index 0, then has a relying party validate it through
 * {@link MerkleTreeCertificateValidator}. The whole flow is exercised against
 * the lightweight bindings in {@code org.bouncycastle.cert.plants.bc} so no
 * JCA provider needs to be registered.</p>
 *
 * <p>The walkthrough is illustrative — production callers should rotate
 * checkpoints, fetch landmark sequences and use multiple cosigners as
 * described in Section 7.3 of the draft. Here we use a single CA cosigner
 * with {@code minCosignatures = 1} for clarity.</p>
 */
public class MerkleTreeCertificateExample
{
    /** Trust anchor ID assigned to our example CA. */
    private static final String CA_TRUST_ANCHOR_ID = "32473.1";

    /** Log number used in the cert's 64-bit serial (top 16 bits). */
    private static final long LOG_NUMBER = 1L;

    public static void main(String[] args)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // 1. CA keypair and identifiers.
        AsymmetricCipherKeyPair caKp = generateEd25519KeyPair(random);
        byte[] caId = TrustAnchorIDs.fromDottedDecimal(CA_TRUST_ANCHOR_ID);
        byte[] logId = TrustAnchorIDs.logId(caId, LOG_NUMBER);
        System.out.println("CA trust anchor ID:    " + CA_TRUST_ANCHOR_ID);
        System.out.println("Issuance log ID:       " + TrustAnchorIDs.toDottedDecimal(logId));

        // 2. End-entity keypair and a TBSCertificateLogEntry describing what
        //    the CA validated. The cert's issuer carries the CA's trust
        //    anchor ID; the validator reconstructs the log ID by appending
        //    the log_number from the cert's serial.
        AsymmetricCipherKeyPair eeKp = generateEd25519KeyPair(random);
        SubjectPublicKeyInfo eeSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(eeKp.getPublic());
        BcSha256MerkleTreeHash hashFunc = new BcSha256MerkleTreeHash();
        TBSCertificateLogEntry tbsEntry = buildTbsCertificateLogEntry(
            issuerName(CA_TRUST_ANCHOR_ID), eeSpki, hashFunc);

        // 3. Assemble the TBSCertificate and the synthetic 2-leaf log.
        //    The end-entity sits at index 0; a sibling leaf at index 1 lets us
        //    exercise a non-trivial inclusion proof.
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
        BigInteger serial = BigInteger.valueOf((LOG_NUMBER << 48) | 0L);
        TBSCertificate tbs = buildTbsCertificate(tbsEntry, serial, sigAlg, eeSpki);

        // We need an X509CertificateHolder to call computeEntryHash — the
        // signatureValue at this point is just a placeholder.
        X509CertificateHolder draft = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(new byte[0])}).getEncoded());
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(draft, hashFunc);
        byte[] siblingHash = hashFunc.hashLeaf("sibling-leaf-1".getBytes());
        byte[] subtreeHash = hashFunc.hashNode(entryHash, siblingHash);
        System.out.println("Subtree [0, 2) hash:   " + hex(subtreeHash));

        // 4. CA cosigns the subtree (start=0, end=2) under its own trust
        //    anchor ID. The cosigner_id IS the CA ID per Section 5.3.
        byte[] cosignedMessage = MTCCosignedMessage.encode(
            logId, /*timestamp=*/ 0L, /*start=*/ 0L, /*end=*/ 2L, subtreeHash, caId);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, caKp.getPrivate());
        signer.update(cosignedMessage, 0, cosignedMessage.length);
        byte[] caSignature = signer.generateSignature();

        // 5. Build the MTCProof and embed it as the cert's signatureValue.
        List<MTCSignature> sigs = Collections.singletonList(new MTCSignature(caId, caSignature));
        MTCProof proof = new MTCProof(/*start=*/ 0L, /*end=*/ 2L, siblingHash, sigs);
        DERBitString signatureValue = new DERBitString(proof.encode());

        X509CertificateHolder cert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, signatureValue}).getEncoded());
        System.out.println("Cert encoded length:   " + cert.getEncoded().length + " bytes");

        // 6. Relying-party side: build a cosigner verifier provider that maps
        //    the CA's trust anchor ID to the CA's public key + Ed25519
        //    algorithm, then assemble ValidationParams and validate.
        BcMTCSignatureVerifier caVerifier = new BcMTCSignatureVerifier(
            caKp.getPublic(), MTCSignatureAlgorithm.ED25519);
        BcMTCCosignerVerifierProvider cosigners = new BcMTCCosignerVerifierProvider.Builder()
            .addCosigner(caId, caVerifier)
            .build();

        // Construct the MTCCertificationAuthority info the relying party knows
        // out-of-band (it would normally be lifted from the CA certificate's
        // id-pe-mtcCertificationAuthority extension).
        MTCCertificationAuthority authority = new MTCCertificationAuthority(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
            new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof),
            BigInteger.ZERO);

        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                new HashSet<Long>(),       // no revocations
                1,                          // minCosignatures
                hashFunc,
                authority);

        boolean valid = MerkleTreeCertificateValidator.validateCertificate(cert, params);
        System.out.println("Validation result:     " + (valid ? "PASS" : "FAIL"));
    }

    // --- Builders -----------------------------------------------------------

    private static AsymmetricCipherKeyPair generateEd25519KeyPair(SecureRandom random)
    {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(random));
        return gen.generateKeyPair();
    }

    /**
     * Builds an issuer DN that names the CA via the experimental
     * {@code id-rdna-trustAnchorID} attribute with a UTF8String value. The
     * validator concatenates this with the cert serial's {@code log_number} to
     * recover the issuance log's full trust anchor ID.
     */
    private static X500Name issuerName(String caTrustAnchorIdDotted)
    {
        AttributeTypeAndValue attr = new AttributeTypeAndValue(
            MTCObjectIdentifiers.id_rdna_trustAnchorID,
            new DERUTF8String(caTrustAnchorIdDotted));
        return new X500Name(new RDN[]{new RDN(attr)});
    }

    private static TBSCertificateLogEntry buildTbsCertificateLogEntry(
        X500Name logName, SubjectPublicKeyInfo subjectSpki,
        BcSha256MerkleTreeHash hashFunc)
        throws Exception
    {
        long now = System.currentTimeMillis();
        Validity validity = new Validity(
            new Time(new Date(now)),
            new Time(new Date(now + 24L * 60 * 60 * 1000)));

        return new TBSCertificateLogEntry(
            new ASN1Integer(0L),                                      // version v1
            logName,                                                   // issuer
            validity,
            new X500Name("CN=mtc-example-ee"),                         // subject
            subjectSpki.getAlgorithm(),                                // subjectPublicKeyAlgorithm
            new org.bouncycastle.asn1.DEROctetString(
                hashFunc.hashRaw(subjectSpki.getEncoded(ASN1Encoding.DER))),
            null, null, null);                                         // unique IDs + extensions
    }

    private static TBSCertificate buildTbsCertificate(
        TBSCertificateLogEntry tbsEntry, BigInteger serial,
        AlgorithmIdentifier sigAlg, SubjectPublicKeyInfo spki)
        throws Exception
    {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        // [0] EXPLICIT Version is omitted when v1; serialNumber and signature
        // come from the cert (not from the TBSCertificateLogEntry).
        DERSequence seq = new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(serial),
            sigAlg,
            tbsEntry.getIssuer(),
            tbsEntry.getValidity(),
            tbsEntry.getSubject(),
            spki
        });
        return TBSCertificate.getInstance(seq);
    }

    private static String hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (int i = 0; i < b.length; i++)
        {
            sb.append(String.format("%02x", b[i] & 0xFF));
        }
        return sb.toString();
    }
}
