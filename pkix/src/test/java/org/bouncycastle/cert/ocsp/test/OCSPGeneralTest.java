package org.bouncycastle.cert.ocsp.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;
import java.util.Random;
import java.util.Set;
import java.util.Vector;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespData;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaRespID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.test.GeneralTest;


public class OCSPGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        OCSPGeneralTest test = new OCSPGeneralTest();
        test.setUp();
        test.testECDSA();
    }

    public void testECDSA()
        throws Exception
    {
        String signDN = "O=Bouncy Castle, C=AU";
        final KeyPair signKP = OCSPTestUtil.makeECKeyPair();
        final X509CertificateHolder testCert = new JcaX509CertificateHolder(OCSPTestUtil.makeECDSACertificate(signKP, signDN, signKP, signDN));
        final DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        GeneralName origName = new GeneralName(new X500Name(origDN));
        // Tests for CertificateID
        testException("'id' cannot be null", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new CertificateID(null);
            }
        });

        testException("problem creating ID: ", "OCSPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new CertificateID(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1), null, BigInteger.valueOf(1));
            }
        });

        final CertificateID id = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1));
        assertEquals(id.getHashAlgOID(), CertificateID.HASH_SHA1.getAlgorithm());
        assertNotNull(id.getIssuerKeyHash());
        assertNotNull(id.getIssuerNameHash());
        assertEquals(id.getSerialNumber(), BigInteger.ONE);
        assertTrue(id.matchesIssuer(testCert, digCalcProv));
        assertFalse(id.equals("test"));
        CertificateID id2 = CertificateID.deriveCertificateID(id, BigInteger.valueOf(2));
        assertTrue(id.hashCode() != id2.hashCode());

        testException("unable to create digest calculator: ", "OCSPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                id.matchesIssuer(testCert, new JcaDigestCalculatorProviderBuilder().setProvider(new BouncyCastlePQCProvider()).build());
            }
        });

        OCSPReqBuilder gen = new OCSPReqBuilder();


        byte[] sampleNonce = new byte[16];
        Random rand = new Random();

        rand.nextBytes(sampleNonce);
        gen.addRequest(id, new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(sampleNonce))));

        final OCSPReq req1 = gen.build();

        assertEquals(req1.getVersionNumber(), 1);
        assertFalse(req1.hasExtensions());
        assertNull(req1.getExtension(null));
        assertNull(req1.getSignatureAlgOID());
        assertNull(req1.getSignature());
        testException("attempt to verify signature on unsigned object", "OCSPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                req1.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic()));
            }
        });

        if (req1.isSigned())
        {
            fail("signed but shouldn't be");
        }

        X509CertificateHolder[] certs = req1.getCerts();

        if (certs.length != 0)
        {
            fail("0 certs expected, but not found");
        }

        Req[] requests = req1.getRequestList();

        assertNotNull(requests[0].getSingleRequestExtensions().getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // request generation with signing
        //
        X509CertificateHolder[] chain = new X509CertificateHolder[1];

        gen = new OCSPReqBuilder();

        assertNull(testException("requestorName must be specified if request is signed.", "OCSPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                OCSPReqBuilder gen = new OCSPReqBuilder();
                X509CertificateHolder[] chain = new X509CertificateHolder[1];
                OCSPReq req = gen.build(new JcaContentSignerBuilder("SHA1withECDSA").setProvider(BC).build(signKP.getPrivate()), chain);
            }
        }).getCause());


        testException("no signer specified", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                OCSPReqBuilder gen = new OCSPReqBuilder();
                gen.setRequestorName(new X500Name("CN=fred"));
                X509CertificateHolder[] chain = new X509CertificateHolder[1];
                OCSPReq req = gen.build(null, chain);
            }
        });

        gen.setRequestorName(new X500Name("CN=fred"));

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        testException("cannot create signer: ", "OperatorCreationException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JcaContentSignerBuilder("SHA1withECDSA").setProvider(new BouncyCastlePQCProvider()).build(signKP.getPrivate());
            }
        });

        OCSPReq req = gen.build(new JcaContentSignerBuilder("SHA1withECDSA").setProvider(BC).build(signKP.getPrivate()), null);

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("signature failed to verify");
        }

        assertNull(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic()).getAssociatedCertificate());

        assertEquals(req.getRequestorName(), new GeneralName(new X500Name("CN=fred")));
        assertEquals(req.getSignatureAlgOID(), X9ObjectIdentifiers.ecdsa_with_SHA1);
        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        certs = req.getCerts();

        if (certs == null)
        {
            fail("null certs found");
        }

//        if (certs.length != 1 || !certs[0].equals(testCert))
//        {
//            fail("incorrect certs found in request");
//        }

        //
        // encoding test
        //
        byte[] reqEnc = req.getEncoded();

        final OCSPReq newReq = new OCSPReq(reqEnc);

        if (!newReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("newReq signature failed to verify");
        }

        testException("exception processing signature: ", "OCSPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                newReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastlePQCProvider()).build(signKP.getPublic()));
            }
        });

        //
        // request generation with signing and nonce
        //
        chain = new X509CertificateHolder[1];

        gen = new OCSPReqBuilder();

        Vector oids = new Vector();
        Vector values = new Vector();


        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X500Name("CN=fred")));

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(sampleNonce));

        gen.setRequestExtensions(extGen.generate());

        gen.addRequest(
            new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.build(new JcaContentSignerBuilder("SHA1withECDSA").setProvider(BC).build(signKP.getPrivate()), chain);

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(signKP.getPublic())))
        {
            fail("signature failed to verify");
        }

        assertEquals(req.getExtensionOIDs().get(0), OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        //
        // extension check.
        //
        Set extOids = req.getCriticalExtensionOIDs();

        if (extOids.size() != 0)
        {
            fail("wrong number of critical extensions in OCSP request.");
        }

        extOids = req.getNonCriticalExtensionOIDs();

        if (extOids.size() != 1)
        {
            fail("wrong number of non-critical extensions in OCSP request.");
        }

        Extension extValue = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        ASN1Encodable extObj = extValue.getParsedValue();

        if (!(extObj instanceof ASN1OctetString))
        {
            fail("wrong extension type found.");
        }

        //assertArrayEquals(((ASN1OctetString)extObj).getOctets(), sampleNonce);

        //
        // request list check
        //
        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // response generation
        //
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(signKP.getPublic(), digCalcProv.get(RespID.HASH_SHA1));
        Date date = new Date();
        respGen.addResponse(id, CertificateStatus.GOOD, new Extensions(extValue));
        respGen.addResponse(id, CertificateStatus.GOOD, date, new Extensions(extValue));
        respGen.addResponse(id, CertificateStatus.GOOD, date, date);

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withECDSA").setProvider(BC).build(signKP.getPrivate()), null, date);
        assertNull(resp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertEquals(0, resp.getCerts().length);
        assertEquals(0, resp.getExtensionOIDs().size());
        assertEquals(0, resp.getCriticalExtensionOIDs().size());
        assertEquals(0, resp.getNonCriticalExtensionOIDs().size());
        int hashCode = resp.hashCode();

        respGen.setResponseExtensions(new Extensions(extValue));

        resp = respGen.build(new JcaContentSignerBuilder("SHA1withECDSA").setProvider(BC).build(signKP.getPrivate()), chain, date);

        assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA1, resp.getSignatureAlgOID());
        assertEquals(new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1), resp.getSignatureAlgorithmID());
        assertEquals(resp.getVersion(), 1);
        assertTrue(resp.hasExtensions());
        assertEquals(extValue, resp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertFalse(resp.getCriticalExtensionOIDs().contains(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertTrue(resp.getNonCriticalExtensionOIDs().contains(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertTrue(resp.getExtensionOIDs().contains(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertTrue(resp.equals(resp));
        assertFalse(resp.equals(resp.getResponses()));
        assertTrue(hashCode != resp.hashCode());

        // Tests for JcaRespID
        JcaRespID jcaRespID = new JcaRespID(signKP.getPublic(), new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1));
        assertEquals(jcaRespID, resp.getResponderId());

        // Tests for RespID
        assertEquals(new RespID(new ResponderID(new DEROctetString(id.getIssuerKeyHash()))), resp.getResponderId());
        assertFalse(resp.getResponderId().equals(id));
        assertEquals(new DERGeneralizedTime(date).getDate(), resp.getProducedAt());
        assertEquals(resp.getResponderId().hashCode(), new ResponderID(new DEROctetString(id.getIssuerKeyHash())).hashCode());
        testException("only SHA-1 can be used with RespID - found: ", "OCSPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new RespID(null, digCalcProv.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_224)));
            }
        });

        // Tests for RespData
        RespData data = new RespData(ResponseData.getInstance(resp.getTBSResponseData()));
        assertEquals(data.getVersion(), 1);
        assertEquals(new RespID(new ResponderID(new DEROctetString(id.getIssuerKeyHash()))), data.getResponderId());
        assertEquals(new DERGeneralizedTime(date).getDate(), data.getProducedAt());
        assertEquals(data.getResponses().length, resp.getResponses().length);
        assertEquals(data.getResponseExtensions().getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce), resp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));

        // Tests for SingleResp
        final SingleResp singleResp = resp.getResponses()[0];
        assertEquals(singleResp.getCertID(), id);
        assertNull(singleResp.getCertStatus());
        assertEquals(singleResp.getThisUpdate(), new DERGeneralizedTime(date).getDate());
        assertNull(singleResp.getNextUpdate());
        assertTrue(singleResp.hasExtensions());
        assertNotNull(singleResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertFalse(singleResp.getCriticalExtensionOIDs().contains(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertTrue(singleResp.getNonCriticalExtensionOIDs().contains(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        assertTrue(singleResp.getExtensionOIDs().contains(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));

        OCSPRespBuilder rGen = new OCSPRespBuilder();

        testException("unknown response object", "OCSPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                OCSPRespBuilder rGen = new OCSPRespBuilder();
                rGen.build(OCSPRespBuilder.SUCCESSFUL, singleResp);
            }
        });

        // Tests for OCSPResp
        OCSPResp resp1 = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, null);
        assertNull(resp1.getResponseObject());

        OCSPResp resp2 = rGen.build(OCSPRespBuilder.SUCCESSFUL, resp);
        assertEquals(resp2.getResponseObject(), resp);

        assertTrue(resp1.equals(resp1));
        assertFalse(resp1.equals( singleResp));
        assertFalse(resp1.hashCode()==resp2.hashCode());
    }
}
