package org.bouncycastle.cbor.c509.examples;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cbor.c509.C509AlgorithmIdentifier;
import org.bouncycastle.cbor.c509.C509Attribute;
import org.bouncycastle.cbor.c509.C509AttributeType;
import org.bouncycastle.cbor.c509.C509CertificationRequest;
import org.bouncycastle.cbor.c509.C509CertificationRequestTemplate;
import org.bouncycastle.cbor.c509.C509ExtensionType;
import org.bouncycastle.cbor.c509.C509PublicKeyAlgorithm;
import org.bouncycastle.cbor.c509.C509SignatureAlgorithm;
import org.bouncycastle.cert.c509.C509CertificationRequestBuilder;
import org.bouncycastle.cert.c509.C509CertificationRequestHolder;
import org.bouncycastle.cert.c509.bc.BcC509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.c509.jcajce.JcaC509ContentVerifierProviderBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * An example of working with C509 certification requests (Section 4 of
 * draft-ietf-cose-cbor-encoded-cert-20), the CBOR counterpart of PKCS#10.
 * <p>
 * Three things are shown: issuing a natively signed request (type 2), where the
 * proof-of-possession signature is computed directly over the CBOR so verification
 * needs no ASN.1 processing; re-encoding an ordinary DER PKCS#10 request as C509
 * (type 3), an invertible compression from which the original DER - and with it the
 * original signature - is recovered exactly; and reading a certification request
 * template of the kind an EST server returns from GET /csrattrs to say what it
 * expects a request to contain.
 */
public class C509CertificationRequestExample
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        kpGen.initialize(new ECGenParameterSpec("P-256"), new SecureRandom());
        KeyPair subjectKp = kpGen.generateKeyPair();

        X500Name subject = new X500Name("CN=C509 Example EE");
        SubjectPublicKeyInfo subjectPublicKeyInfo =
            SubjectPublicKeyInfo.getInstance(subjectKp.getPublic().getEncoded());

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

        //
        // 1. a natively signed C509 certification request, proof-of-possession over the CBOR
        //
        ContentSigner jcaSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC")
            .build(subjectKp.getPrivate());

        C509CertificationRequestHolder nativeRequest = new C509CertificationRequestBuilder(
            subject, subjectPublicKeyInfo)
            .setExtensionRequest(extGen.generate())
            .setChallengePassword("secret1234")
            .build(jcaSigner);

        System.out.println("native C509 certification request (" + nativeRequest.getEncoded().length + " bytes):");
        System.out.println("  " + Hex.toHexString(nativeRequest.getEncoded()));
        System.out.println("  subject: " + nativeRequest.getSubject());
        for (int i = 0; i != nativeRequest.getAttributes().length; i++)
        {
            C509Attribute attribute = nativeRequest.getAttributes()[i];
            System.out.println("  attribute: " + (attribute.getRegistryValue() != null
                ? "registered value " + attribute.getRegistryValue() : attribute.getAttrType().toString()));
        }

        // the proof-of-possession verifies against the request's own subject public key,
        // through the JCA/JCE operators ...
        System.out.println("  proof-of-possession valid (JCA): " + nativeRequest.isSignatureValid(
            new JcaC509ContentVerifierProviderBuilder().setProvider("BC")
                .build(nativeRequest.getSubjectPublicKeyInfo())));
        // ... and equally through the lightweight ones
        System.out.println("  proof-of-possession valid (lightweight): " + nativeRequest.isSignatureValid(
            new BcC509ContentVerifierProviderBuilder().build(nativeRequest.getSubjectPublicKeyInfo())));

        // signing works from either stack too - here the same request built with the
        // lightweight operators over the private key parameters
        DefaultSignatureAlgorithmIdentifierFinder sigFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
        ContentSigner bcSigner = new BcECContentSignerBuilder(
            sigFinder.find("SHA256withECDSA"), digFinder.find("SHA-256"))
            .build(PrivateKeyFactory.createKey(subjectKp.getPrivate().getEncoded()));

        C509CertificationRequestHolder lightweightRequest = new C509CertificationRequestBuilder(
            subject, subjectPublicKeyInfo)
            .setExtensionRequest(extGen.generate())
            .setChallengePassword("secret1234")
            .build(bcSigner);

        System.out.println("  lightweight-signed request verifies: " + lightweightRequest.isSignatureValid(
            new BcC509ContentVerifierProviderBuilder().build(subjectPublicKeyInfo)));

        //
        // 2. an ordinary PKCS#10 request, re-encoded as C509 and recovered
        //
        JcaPKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
            new X500Principal("CN=C509 Example EE"), subjectKp.getPublic());
        p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        PKCS10CertificationRequest p10 = p10Builder.build(jcaSigner);

        byte[] der = p10.getEncoded();
        C509CertificationRequest reencoded = C509CertificationRequest.fromCertificationRequest(der);
        System.out.println("PKCS#10 request is " + der.length + " bytes, its C509 re-encoding "
            + reencoded.getEncoded().length + " bytes");

        // the re-encoding is invertible, so the original request - signature included -
        // comes back byte for byte
        byte[] recovered = reencoded.toCertificationRequest().getEncoded(ASN1Encoding.DER);
        System.out.println("  recovered DER identical to the original: " + Arrays.areEqual(der, recovered));
        System.out.println("  proof-of-possession valid over the reconstruction: "
            + new C509CertificationRequestHolder(reencoded).isSignatureValid(
                new JcaC509ContentVerifierProviderBuilder().setProvider("BC").build(subjectPublicKeyInfo)));

        //
        // 3. a certification request template, as an EST server would supply it
        //    (ESTService.getC509CertificationRequestTemplate fetches one over EST)
        //
        C509CertificationRequestTemplate template = new C509CertificationRequestTemplate(
            C509CertificationRequestTemplate.TYPE_SIMPLE,
            new int[]{ C509CertificationRequest.TYPE_NATIVE },
            new C509AlgorithmIdentifier[]{ C509AlgorithmIdentifier.forSignatureAlgorithm(
                C509SignatureAlgorithm.getAlgorithmIdentifier(C509SignatureAlgorithm.ECDSA_WITH_SHA256)) },
            new C509CertificationRequestTemplate.RDNAttributeTemplate[]{
                // exactly one common name, whose value the client supplies (undefined)
                new C509CertificationRequestTemplate.RDNAttributeTemplate(
                    C509AttributeType.COMMON_NAME, 1, 1, null) },
            new C509AlgorithmIdentifier[]{ C509AlgorithmIdentifier.forPublicKeyAlgorithm(
                C509PublicKeyAlgorithm.getAlgorithmIdentifier(C509PublicKeyAlgorithm.EC_SECP256R1)) },
            new C509CertificationRequestTemplate.ExtensionTemplate[]{
                // a mandatory keyUsage of digitalSignature (the C509 int form of the bit)
                new C509CertificationRequestTemplate.ExtensionTemplate(
                    C509ExtensionType.KEY_USAGE, false, Hex.decode("01")) });

        byte[] templateEncoding = template.getEncoded();
        System.out.println("certification request template (" + templateEncoding.length + " bytes):");
        System.out.println("  " + Hex.toHexString(templateEncoding));

        C509CertificationRequestTemplate parsed =
            C509CertificationRequestTemplate.getInstance(templateEncoding);
        System.out.println("  accepted request types: " + parsed.getCertificationRequestTypes().length);
        System.out.println("  subject attributes demanded: " + parsed.getSubjectTemplate().length
            + " (client supplies the value: "
            + (parsed.getSubjectTemplate()[0].getValueEncoding() == null) + ")");
        System.out.println("  extensions demanded: " + parsed.getExtensionsTemplate().length
            + " (optional: " + parsed.getExtensionsTemplate()[0].isOptional() + ")");
    }
}
