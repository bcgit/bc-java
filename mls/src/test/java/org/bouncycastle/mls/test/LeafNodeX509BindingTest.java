package org.bouncycastle.mls.test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LifeTime;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Certificate;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.CredentialType;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcEdECContentSignerBuilder;

/**
 * RFC 9420 sec. 5.3 requires a LeafNode's signature_key to be the public key certified by its X.509
 * credential's end-entity certificate. Without that binding the credential authenticates nothing: a
 * signer could attach any victim's certificate while signing the leaf with its own key, so
 * verification against the self-declared signature_key would succeed and the leaf would impersonate
 * the certificate's subject (and, through the resynchronization credential comparison, evict them).
 * These tests exercise LeafNode.verify() for an X.509 credential whose certificate key matches the
 * signature_key (accepted) and one where it does not (rejected).
 */
public class LeafNodeX509BindingTest
    extends TestCase
{
    public void testX509LeafWithMatchingCertificateKeyVerifies()
        throws Exception
    {
        MlsCipherSuite suite = suite();
        AsymmetricCipherKeyPair signing = suite.generateSignatureKeyPair();
        Credential credential = x509Credential("CN=alice@example.com", signing);

        LeafNode leaf = leafNode(suite, credential, signing);

        assertTrue("a leaf whose certificate certifies its signature_key must verify",
            leaf.verify(suite, leaf.toBeSigned(new byte[0], -1)));
    }

    public void testX509LeafWithForeignCertificateKeyRejected()
        throws Exception
    {
        MlsCipherSuite suite = suite();

        // the victim's certificate, over the victim's key
        AsymmetricCipherKeyPair victim = suite.generateSignatureKeyPair();
        Credential victimCredential = x509Credential("CN=victim@example.com", victim);

        // the attacker builds a self-consistent leaf - signed with its own key, declaring its own
        // signature_key - but carries the victim's certificate as the credential
        AsymmetricCipherKeyPair attacker = suite.generateSignatureKeyPair();
        LeafNode forged = leafNode(suite, victimCredential, attacker);

        assertFalse("a leaf carrying a certificate that does not certify its signature_key must be rejected",
            forged.verify(suite, forged.toBeSigned(new byte[0], -1)));
    }

    public void testX509LeafWithEmptyChainRejected()
        throws Exception
    {
        MlsCipherSuite suite = suite();
        AsymmetricCipherKeyPair signing = suite.generateSignatureKeyPair();
        Credential empty = new Credential(CredentialType.x509, null, new ArrayList<Certificate>());

        LeafNode leaf = leafNode(suite, empty, signing);

        assertFalse("an X.509 credential with no certificate binds no key and must be rejected",
            leaf.verify(suite, leaf.toBeSigned(new byte[0], -1)));
    }

    private static MlsCipherSuite suite()
        throws Exception
    {
        return MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    }

    private LeafNode leafNode(MlsCipherSuite suite, Credential credential, AsymmetricCipherKeyPair signing)
        throws Exception
    {
        AsymmetricCipherKeyPair encryption = suite.getHPKE().generatePrivateKey();

        return new LeafNode(
            suite,
            suite.getHPKE().serializePublicKey(encryption.getPublic()),
            suite.serializeSignaturePublicKey(signing.getPublic()),
            credential,
            new Capabilities(),
            new LifeTime(),
            new ArrayList<Extension>(),
            suite.serializeSignaturePrivateKey(signing.getPrivate()));
    }

    private Credential x509Credential(String dn, AsymmetricCipherKeyPair keyPair)
        throws Exception
    {
        X500Name name = new X500Name(dn);
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            name, BigInteger.ONE, new Date(now - 60000L), new Date(now + 86400000L), name,
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic()));
        ContentSigner signer = new BcEdECContentSignerBuilder(
            new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)).build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);

        List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(new Certificate(holder.getEncoded()));

        return new Credential(CredentialType.x509, null, certificates);
    }
}
