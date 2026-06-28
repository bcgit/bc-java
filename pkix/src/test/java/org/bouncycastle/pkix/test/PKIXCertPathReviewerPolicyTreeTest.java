package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyNode;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;

/**
 * Regression test for {@link PKIXCertPathReviewer#getPolicyTree()}: a successfully
 * validated path whose certificates carry the {@code certificatePolicies} extension
 * must expose a populated valid-policy-tree (RFC 3280 &sect;6.1.5(g)), matching the
 * JDK {@code CertPathValidator}'s {@code PKIXCertPathValidatorResult.getPolicyTree()}.
 * <p>
 * The field behind the getter was previously never assigned the tree computed in
 * {@code checkPolicy()}, so the method always returned {@code null}. This test is
 * deliberately self-contained (it builds its own root&rarr;CA&rarr;EE chain) so it
 * carries the fix independently of the wider cert-path policy coverage suite.
 */
public class PKIXCertPathReviewerPolicyTreeTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String POLICY_A = "1.3.6.1.4.1.55555.1";

    private static int serialCounter = 7000;

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testValidPolicyTreePopulated()
        throws Exception
    {
        // root -> CA -> EE; root is the (excluded) trust anchor, CA and EE both assert POLICY_A.
        KeyPair rootKp = rsa();
        X509Certificate rootCert = makeCert("CN=Policy Root CA", rootKp.getPublic(),
            "CN=Policy Root CA", rootKp.getPrivate(), true, null);
        KeyPair caKp = rsa();
        X509Certificate caCert = makeCert("CN=Policy CA", caKp.getPublic(),
            "CN=Policy Root CA", rootKp.getPrivate(), true, policies(POLICY_A));
        KeyPair eeKp = rsa();
        X509Certificate eeCert = makeCert("CN=Policy EE", eeKp.getPublic(),
            "CN=Policy CA", caKp.getPrivate(), false, policies(POLICY_A));

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
        CertPath cp = cf.generateCertPath(Arrays.asList(eeCert, caCert));

        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor(rootCert, null));
        PKIXParameters params = new PKIXParameters(trust);
        params.setRevocationEnabled(false);

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();
        reviewer.init(cp, params);

        assertTrue("matching policy chain must validate", reviewer.isValidCertPath());

        PolicyNode tree = reviewer.getPolicyTree();
        assertNotNull("getPolicyTree() must return the computed valid policy tree", tree);
        assertTrue("valid policy tree must contain asserted policy " + POLICY_A,
            containsPolicy(tree, POLICY_A));
    }

    /** Depth-first search of the valid-policy-tree for a node bearing {@code oid}. */
    private static boolean containsPolicy(PolicyNode node, String oid)
    {
        if (oid.equals(node.getValidPolicy()))
        {
            return true;
        }
        for (Iterator<? extends PolicyNode> it = node.getChildren(); it.hasNext(); )
        {
            if (containsPolicy(it.next(), oid))
            {
                return true;
            }
        }
        return false;
    }

    private static CertificatePolicies policies(String... oids)
    {
        PolicyInformation[] pi = new PolicyInformation[oids.length];
        for (int i = 0; i != oids.length; i++)
        {
            pi[i] = new PolicyInformation(new ASN1ObjectIdentifier(oids[i]));
        }
        return new CertificatePolicies(pi);
    }

    private static X509Certificate makeCert(String subjectDn, PublicKey subjectKey, String issuerDn,
                                            PrivateKey issuerKey, boolean ca, CertificatePolicies certPolicies)
        throws Exception
    {
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
            new X500Name(issuerDn), BigInteger.valueOf(serialCounter++),
            new Date(now - 3600000L), new Date(now + 3600000L),
            new X500Name(subjectDn), subjectKey);

        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(
            ca ? (KeyUsage.keyCertSign | KeyUsage.cRLSign) : KeyUsage.digitalSignature));
        if (certPolicies != null)
        {
            b.addExtension(Extension.certificatePolicies, false, certPolicies);
        }

        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(issuerKey);
        X509CertificateHolder holder = b.build(cs);
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
    }

    private static KeyPair rsa()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
