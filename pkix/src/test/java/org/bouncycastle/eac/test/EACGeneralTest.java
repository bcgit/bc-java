package org.bouncycastle.eac.test;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
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
import org.bouncycastle.test.GeneralTest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class EACGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        EACGeneralTest test = new EACGeneralTest();
        test.setUp();
        test.testLoadCertificate();
        test.testLoadInvalidRequest();
        test.testGenerateEC();
    }

    public void testLoadCertificate()
        throws Exception
    {
        testException("malformed data: ", "EACIOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new EACCertificateHolder(new byte[100]);
            }
        });

        final EACCertificateHolder certHolder = new EACCertificateHolder(getInput("Belgique CVCA-02032010.7816.cvcert"));
        testException("unable to process signature: ", "EACException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                certHolder.isSignatureValid(null);
            }
        });
        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(new BouncyCastleProvider()).getKey(certHolder.toASN1Structure().getBody().getPublicKey());
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().setProvider(BC).build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

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

    public void testLoadInvalidRequest()
        throws Exception
    {
        testException("malformed data: ", "EACIOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new EACCertificateRequestHolder(new byte[100]);
            }
        });

        // this request contains invalid unsigned integers (see D 2.1.1)
        final EACCertificateRequestHolder requestHolder = new EACCertificateRequestHolder(getInput("REQ_18102010.csr"));
        testException("unable to process signature: ", "EACException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                requestHolder.isInnerSignatureValid(null);
            }
        });
        PublicKey pubKey = new JcaPublicKeyConverter().getKey(requestHolder.getPublicKeyDataObject());
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().setProvider(new BouncyCastleProvider()).build(requestHolder.getPublicKeyDataObject().getUsage(), pubKey);
        assertEquals(verifier.getUsageIdentifier(), requestHolder.getPublicKeyDataObject().getUsage());
        if (requestHolder.isInnerSignatureValid(verifier))
        {
            fail("signature test failed");
        }
    }

    public void testLoadCSR()
        throws Exception
    {
        // this request contains invalid unsigned integers (see D 2.1.1)
        byte[] input = getInput("UTIS00100072.csr");

        EACCertificateRequestHolder requestHolder = new EACCertificateRequestHolder(input);

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(requestHolder.getPublicKeyDataObject());
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(requestHolder.getPublicKeyDataObject().getUsage(), pubKey);

        TestCase.assertTrue("signature test failed", requestHolder.isInnerSignatureValid(verifier));
        TestCase.assertTrue("comparison failed", Arrays.areEqual(input, requestHolder.toASN1Structure().getEncoded()));
    }


    public void testGenerateEC()
        throws Exception
    {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPair kp = generateECKeyPair(ecSpec);

        JcaEACSignerBuilder signerBuilder = new JcaEACSignerBuilder().setProvider(new BouncyCastleProvider());

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

        assertFalse(verifier.verify(null));

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BC).getKey(certHolder.getPublicKeyDataObject());
        verifier = new JcaEACSignatureVerifierBuilder().build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

        if (!certHolder.isSignatureValid(verifier))
        {
            fail("second signature test failed");
        }
    }

    private KeyPair generateECKeyPair(ECParameterSpec spec)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA", BC);

        gen.initialize(spec, new SecureRandom());

        KeyPair generatedKeyPair = gen.generateKeyPair();
        return generatedKeyPair;
    }
}
