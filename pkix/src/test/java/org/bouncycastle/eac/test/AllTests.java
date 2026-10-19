package org.bouncycastle.eac.test;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.eac.CVCertificate;
import org.bouncycastle.asn1.eac.CVCertificateRequest;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.asn1.eac.PackedDate;
import org.bouncycastle.eac.EACCertificateBuilder;
import org.bouncycastle.eac.EACCertificateHolder;
import org.bouncycastle.eac.EACCertificateRequestHolder;
import org.bouncycastle.eac.jcajce.JcaPublicKeyConverter;
import org.bouncycastle.eac.operator.EACSignatureVerifier;
import org.bouncycastle.eac.operator.EACSigner;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignatureVerifierBuilder;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignerBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class AllTests
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) != null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testLoadCertificate() throws Exception
    {
        EACCertificateHolder certHolder = new EACCertificateHolder(getInput("Belgique CVCA-02032010.7816.cvcert"));

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("signature test failed");
        }
    }

    private byte[] getInput(String name)
        throws IOException
    {
        return Streams.readAll(getClass().getResourceAsStream(name));
    }

    public void testLoadInvalidRequest() throws Exception
    {
        // this request contains invalid unsigned integers (see D 2.1.1)
        EACCertificateRequestHolder requestHolder = new EACCertificateRequestHolder(getInput("REQ_18102010.csr"));

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(requestHolder.getPublicKeyDataObject());
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(requestHolder.getPublicKeyDataObject().getUsage(), pubKey);

        if (requestHolder.isInnerSignatureValid(verifier))
        {
            fail("signature test failed");
        }
    }

    public void testLoadCSR() throws Exception
    {
        // this request contains invalid unsigned integers (see D 2.1.1)
        byte[] input = getInput("UTIS00100072.csr");
   
        EACCertificateRequestHolder requestHolder = new EACCertificateRequestHolder(input);

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(requestHolder.getPublicKeyDataObject());
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(requestHolder.getPublicKeyDataObject().getUsage(), pubKey);

        TestCase.assertTrue("signature test failed", requestHolder.isInnerSignatureValid(verifier));
        TestCase.assertTrue("comparison failed", Arrays.areEqual(input, requestHolder.toASN1Structure().getEncoded()));
    }

    private static ASN1TaggedObject app(int tagNo, ASN1Encodable[] elements)
    {
        return new DERTaggedObject(false, BERTags.APPLICATION, tagNo, new DERSequence(elements));
    }

    private static ASN1Encodable[] contents(ASN1Encodable tagged)
    {
        return ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(tagged).getBaseUniversal(false, BERTags.SEQUENCE)).toArray();
    }

    private static ASN1Encodable[] swap(ASN1Encodable[] elements, int i, int j)
    {
        ASN1Encodable[] copy = (ASN1Encodable[])elements.clone();
        copy[i] = elements[j];
        copy[j] = elements[i];
        return copy;
    }

    private static ASN1Encodable[] repeat(ASN1Encodable[] elements, int i)
    {
        ASN1Encodable[] copy = new ASN1Encodable[elements.length + 1];
        System.arraycopy(elements, 0, copy, 0, i + 1);
        System.arraycopy(elements, i, copy, i + 1, elements.length - i);
        return copy;
    }

    private static void assertCertRejected(String label, ASN1Encodable[] certElements)
        throws IOException
    {
        try
        {
            CVCertificate.getInstance(app(EACTags.CARDHOLDER_CERTIFICATE, certElements).getEncoded());
            fail(label + " accepted");
        }
        catch (RuntimeException e)
        {
            // expected
        }
    }

    /**
     * The data objects of a CV certificate, its body and its public key may each appear at most once
     * and only in the order TR-03110 defines (github #2516).
     */
    public void testSequenceFieldOrder() throws Exception
    {
        ASN1Encodable[] cert = contents(ASN1TaggedObject.getInstance(getInput("Belgique CVCA-02032010.7816.cvcert")));
        ASN1Encodable body = cert[0];
        ASN1Encodable signature = cert[1];

        CVCertificate.getInstance(app(EACTags.CARDHOLDER_CERTIFICATE, cert).getEncoded());
        assertCertRejected("signature before body", swap(cert, 0, 1));
        assertCertRejected("body repeated", repeat(cert, 0));
        assertCertRejected("signature repeated", repeat(cert, 1));

        ASN1Encodable[] fields = contents(body);
        assertCertRejected("authority reference before profile identifier",
            new ASN1Encodable[]{ app(EACTags.CERTIFICATE_CONTENT_TEMPLATE, swap(fields, 0, 1)), signature });
        assertCertRejected("holder reference repeated",
            new ASN1Encodable[]{ app(EACTags.CERTIFICATE_CONTENT_TEMPLATE, repeat(fields, 3)), signature });

        // the public key template: OID, then the domain parameters [1] .. [7]
        ASN1Encodable[] key = contents(fields[2]);
        assertTrue("CVCA key carries domain parameters", key.length > 3);
        ASN1Encodable[] reorderedFields = (ASN1Encodable[])fields.clone();
        reorderedFields[2] = app(EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE, swap(key, 1, 2));
        assertCertRejected("public key fields out of order",
            new ASN1Encodable[]{ app(EACTags.CERTIFICATE_CONTENT_TEMPLATE, reorderedFields), signature });

        // a request: the inner request, the authority reference, then the outer signature
        ASN1Encodable[] request = contents(ASN1TaggedObject.getInstance(getInput("UTIS00100072.csr")));
        assertEquals(3, request.length);
        CVCertificateRequest.getInstance(app(EACTags.AUTHENTIFICATION_DATA, request).getEncoded());
        try
        {
            CVCertificateRequest.getInstance(app(EACTags.AUTHENTIFICATION_DATA, repeat(request, 2)).getEncoded());
            fail("request trailing element accepted");
        }
        catch (RuntimeException e)
        {
            // expected
        }
        try
        {
            CVCertificateRequest.getInstance(app(EACTags.AUTHENTIFICATION_DATA, swap(request, 1, 2)).getEncoded());
            fail("request signature before authority reference accepted");
        }
        catch (RuntimeException e)
        {
            // expected
        }
    }

    public void testLoadRefCert() throws Exception
    {
        EACCertificateHolder certHolder = new EACCertificateHolder(getInput("at_cert_19a.cvcert"));


    }

    public void testGenerateEC()
        throws Exception
    {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPair kp = generateECKeyPair(ecSpec);

        JcaEACSignerBuilder signerBuilder = new JcaEACSignerBuilder().setProvider(BC);

        EACSigner signer = signerBuilder.build("SHA256withECDSA", kp.getPrivate());

        int role = CertificateHolderAuthorization.CVCA;
        int rights = CertificateHolderAuthorization.RADG3 | CertificateHolderAuthorization.RADG4;

        EACCertificateBuilder certBuilder = new EACCertificateBuilder(
            new CertificationAuthorityReference("AU", "BC TEST", "12345"),
            new JcaPublicKeyConverter().getPublicKeyDataObject(signer.getUsageIdentifier(), kp.getPublic()),
            new CertificateHolderReference("AU", "BC TEST", "12345"),
            new CertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport, role | rights),
            new PackedDate("110101"),
            new PackedDate("120101"));

        EACCertificateHolder certHolder = certBuilder.build(signer);

        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), kp.getPublic());

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("first signature test failed");
        }

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
        verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("second signature test failed");
        }
    }

    public void testGenerateRSA()
        throws Exception
    {
        KeyPair kp = generateRSAKeyPair();

        JcaEACSignerBuilder signerBuilder = new JcaEACSignerBuilder().setProvider(BC);

        EACSigner signer = signerBuilder.build("SHA256withRSA", kp.getPrivate());

        int role = CertificateHolderAuthorization.CVCA;
        int rights = CertificateHolderAuthorization.RADG3 | CertificateHolderAuthorization.RADG4;

        EACCertificateBuilder certBuilder = new EACCertificateBuilder(
            new CertificationAuthorityReference("AU", "BC TEST", "12345"),
            new JcaPublicKeyConverter().getPublicKeyDataObject(signer.getUsageIdentifier(), kp.getPublic()),
            new CertificateHolderReference("AU", "BC TEST", "12345"),
            new CertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport, role | rights),
            new PackedDate("110101"),
            new PackedDate("120101"));

        EACCertificateHolder certHolder = certBuilder.build(signer);

        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), kp.getPublic());

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("first signature test failed");
        }

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
        verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("second signature test failed");
        }
    }

    private KeyPair generateECKeyPair(ECParameterSpec spec) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA",BC);

        gen.initialize(spec, new SecureRandom());

        KeyPair generatedKeyPair = gen.generateKeyPair();
        return generatedKeyPair;
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA",BC);

        gen.initialize(1024, new SecureRandom());

        KeyPair generatedKeyPair = gen.generateKeyPair();
        return generatedKeyPair;
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("EAC tests");

        suite.addTestSuite(AllTests.class);

        return new EACTestSetup(suite);
    }
}
