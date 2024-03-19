package org.bouncycastle.cert.cmp.test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.DSAParameterSpec;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.io.Streams;

public class InvalidMessagesTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testBadNoBodyWithProtection()
        throws Exception
    {
        try
        {
            new ProtectedPKIMessage(fetchPkiMessage("bad-no-body"));
        }
        catch (CertIOException e)
        {
            Assert.assertEquals("malformed data: malformed body found: body type of 0 has incorrect type got: class org.bouncycastle.asn1.DERBitString", e.getMessage());
        }
    }

    public void testBadNoBody()
        throws Exception
    {
        try
        {
            new ProtectedPKIMessage(fetchPkiMessage("bad-no-body-after-header"));
        }
        catch (CertIOException e)
        {
            Assert.assertEquals("malformed data: PKIMessage missing PKIBody structure", e.getMessage());
        }
    }

    public void testBadOidSigAlg()
        throws Exception
    {
        ProtectedPKIMessage message = new ProtectedPKIMessage(fetchPkiMessage("bad-oid-sigalg"));

        PKIBody body = message.getBody();

        Assert.assertEquals(body.getType(), PKIBody.TYPE_P10_CERT_REQ);

        PKCS10CertificationRequest certReq = new PKCS10CertificationRequest(CertificationRequest.getInstance(body.getContent()));
        try
        {
            certReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(certReq.getSubjectPublicKeyInfo()));
        }
        catch (PKCSException e)
        {
            Assert.assertEquals("unable to process signature: exception on setup: java.security.NoSuchAlgorithmException: no such algorithm: 1.2.840.113549.2097035 for provider BC", e.getMessage());
        }
    }

    public void testBadProtection()
        throws Exception
    {
        KeyPairGenerator dsaKpGen = KeyPairGenerator.getInstance("DSA", "BC");

        DSAParameters dsaParams = (DSAParameters)CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS, 2048);

        dsaKpGen.initialize(new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()));

        KeyPair dsaKp = dsaKpGen.generateKeyPair();

        X509CertificateHolder caCert = TestUtils.makeV3Certificate("CN=DSA Issuer", dsaKp);

        ProtectedPKIMessage message = new ProtectedPKIMessage(fetchPkiMessage("bad-protection"));

        try
        {
            message.verify(new JcaContentVerifierProviderBuilder().build(caCert));
        }
        catch (CMPException e)
        {
            Assert.assertEquals("unable to verify signature: exception on setup: java.security.NoSuchAlgorithmException: 1.2.840.113549.2.11 Signature not available", e.getMessage());
        }
    }

    public void testBadTagBody15vs4()
        throws Exception
    {
        try
        {
            new ProtectedPKIMessage(fetchPkiMessage("bad-tag-body-15-vs-4"));
        }
        catch (CertIOException e)
        {
            Assert.assertEquals("malformed data: malformed body found: body type of 15 has incorrect type got: class org.bouncycastle.asn1.DLSequence", e.getMessage());
        }
    }

    public void testBadTagBody29vs4()
        throws Exception
    {
        try
        {
            new ProtectedPKIMessage(fetchPkiMessage("bad-tag-body-29-vs-4"));
        }
        catch (IOException e)
        {
            Assert.assertEquals("unknown tag 29 encountered", e.getMessage());
        }
    }

    public void testBadTypeSequenceVsChoice()
        throws Exception
    {
        try
        {
            new ProtectedPKIMessage(fetchPkiMessage("bad-body-seq-vs-choice"));
        }
        catch (CertIOException e)
        {
            Assert.assertEquals("malformed data: Invalid object: org.bouncycastle.asn1.DLSequence", e.getMessage());
        }
    }

    private GeneralPKIMessage fetchPkiMessage(String s)
        throws IOException
    {
        return new GeneralPKIMessage(Streams.readAll(TestResourceFinder.findTestResource("cmp/invalid-messages", s)));
    }
}
