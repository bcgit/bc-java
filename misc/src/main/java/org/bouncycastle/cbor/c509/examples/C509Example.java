package org.bouncycastle.cbor.c509.examples;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cbor.c509.C509Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.c509.C509CertificateBuilder;
import org.bouncycastle.cert.c509.C509CertificateHolder;
import org.bouncycastle.cert.c509.jcajce.JcaC509CertificateConverter;
import org.bouncycastle.cert.c509.jcajce.JcaC509ContentVerifierProviderBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;

/**
 * An example of working with C509 certificates (draft-ietf-cose-cbor-encoded-cert-20),
 * the CBOR encoding of X.509 for constrained environments.
 * <p>
 * Two things are shown: issuing a natively signed C509 certificate (type 2), where the
 * signature is computed directly over the CBOR encoding so verification needs no ASN.1
 * processing at all; and re-encoding an ordinary DER X.509 certificate as C509 (type 3),
 * an invertible compression - the original DER, and with it the original signature,
 * is recovered exactly.
 */
public class C509Example
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        kpGen.initialize(new ECGenParameterSpec("P-256"), new SecureRandom());
        KeyPair caKp = kpGen.generateKeyPair();
        KeyPair eeKp = kpGen.generateKeyPair();

        X500Name caName = new X500Name("CN=C509 Example CA");
        X500Name eeName = new X500Name("CN=C509 Example EE");
        Date notBefore = new Date((System.currentTimeMillis() / 1000) * 1000);
        Date notAfter = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        ContentSigner caSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC")
            .build(caKp.getPrivate());

        //
        // 1. a natively signed C509 certificate: compact, and verified over the CBOR itself
        //
        C509CertificateHolder nativeCert = new C509CertificateBuilder(caName, BigInteger.valueOf(1),
            notBefore, notAfter, eeName, SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded()))
            .addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature))
            .build(caSigner);

        System.out.println("native C509 certificate (" + nativeCert.getEncoded().length + " bytes):");
        System.out.println("  " + Hex.toHexString(nativeCert.getEncoded()));
        System.out.println("  signature valid: " + nativeCert.isSignatureValid(
            new JcaC509ContentVerifierProviderBuilder().setProvider("BC").build(
                SubjectPublicKeyInfo.getInstance(caKp.getPublic().getEncoded()))));

        //
        // 2. an X.509 certificate issued in the usual way, re-encoded as C509 and back
        //
        X509CertificateHolder x509 = new X509v3CertificateBuilder(caName, BigInteger.valueOf(2),
            notBefore, notAfter, eeName, SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded()))
            .addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature))
            .build(caSigner);

        C509Certificate reencoded = C509Certificate.fromX509Certificate(x509.getEncoded());
        System.out.println("X.509 certificate is " + x509.getEncoded().length + " bytes, its C509 re-encoding "
            + reencoded.getEncoded().length + " bytes");

        // the re-encoding is invertible, so the original signature still verifies
        X509Certificate recovered = new JcaC509CertificateConverter().setProvider("BC")
            .getCertificate(new C509CertificateHolder(reencoded));
        recovered.verify(caKp.getPublic());
        System.out.println("recovered X.509 certificate verifies: true");
    }
}
