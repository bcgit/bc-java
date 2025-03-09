package org.bouncycastle.cert.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Arrays;

/**
 **/
public class PQCPKCS10Test
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public String getName()
    {
        return "PKCS10CertRequest";
    }

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    public void testMLDsa()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_65);

        KeyPair kp = kpg.genKeyPair();

        X500Name subject = getSubjectName();

        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
                            
        PKCS10CertificationRequest req1 = requestBuilder.build(new JcaContentSignerBuilder("ML-DSA").setProvider(BC).build(kp.getPrivate()));

        JcaPKCS10CertificationRequest req2 = new JcaPKCS10CertificationRequest(req1.getEncoded()).setProvider(BC);

        if (!req2.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic())))
        {
            fail("ML-DSA: Failed verify check.");
        }

        if (!Arrays.areEqual(req2.getPublicKey().getEncoded(), req1.getSubjectPublicKeyInfo().getEncoded()))
        {
            fail("ML-DSA: Failed public key check.");
        }
    }

    /**
     * ML-KEM basesd PKCS#10 request using ML-DSA signing key.
     */
    public void testMLKem()
        throws Exception
    {
        KeyPairGenerator signKpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        signKpg.initialize(MLDSAParameterSpec.ml_dsa_65);

        KeyPair signKp = signKpg.genKeyPair();
        X509Certificate signCert = getMLDSACertificate(signKp);
        
        KeyPairGenerator kemKpg = KeyPairGenerator.getInstance("ML-KEM", "BC");

        kemKpg.initialize(MLKEMParameterSpec.ml_kem_768);

        KeyPair kemKp = kemKpg.genKeyPair();

        X500Principal subject = signCert.getSubjectX500Principal();

        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, kemKp.getPublic());

        PKCS10CertificationRequest req1 = requestBuilder.build(new JcaContentSignerBuilder("ML-DSA").setProvider(BC).build(signKp.getPrivate()));

        JcaPKCS10CertificationRequest req2 = new JcaPKCS10CertificationRequest(req1.getEncoded()).setProvider(BC);

        if (!req2.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signCert.getPublicKey())))
        {
            fail("ML-KEM: Failed verify check.");
        }

        if (!Arrays.areEqual(req2.getPublicKey().getEncoded(), req1.getSubjectPublicKeyInfo().getEncoded()))
        {
            fail("ML-KEM: Failed public key check.");
        }
    }

    private X500Name getSubjectName()
    {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);

        x500NameBld.addRDN(BCStyle.C, "AU");
        x500NameBld.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        x500NameBld.addRDN(BCStyle.L, "Melbourne");
        x500NameBld.addRDN(BCStyle.ST, "Victoria");
        x500NameBld.addRDN(BCStyle.EmailAddress, "feedback-crypto@bouncycastle.org");

        X500Name    subject = x500NameBld.build();
        return subject;
    }

    private X509Certificate getMLDSACertificate(KeyPair kp)
        throws Exception
    {
        X500Name issuer = getSubjectName();   // self signed
        X509v3CertificateBuilder v3certBldr = new JcaX509v3CertificateBuilder(issuer,
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() - 5000L),
            new Date(System.currentTimeMillis() + 15000L),
            issuer, kp.getPublic()).addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider(BC).build(kp.getPrivate());

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(v3certBldr.build(signer));
    }
}
