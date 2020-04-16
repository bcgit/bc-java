package org.bouncycastle.cert.ocsp.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class PKIXRevocationTest
    extends SimpleTest
{
    private static final String BC = "BC";
    private static final int TEST_OCSP_RESPONDER_PORT = 10541;

    public String getName()
    {
        return "PKIXRevocationTest";
    }

    public void performTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        KeyPair rootKp = OCSPTestUtil.makeKeyPair();
        KeyPair caKp = OCSPTestUtil.makeKeyPair();
        KeyPair eeKp = OCSPTestUtil.makeKeyPair();
        KeyPair ocspKp = OCSPTestUtil.makeKeyPair();

        X509Certificate root = OCSPTestUtil.makeRootCertificate(rootKp, "CN=Root");
        X509Certificate ca = OCSPTestUtil.makeCertificate(caKp, "CN=CA", rootKp, root, true);
        X509Certificate ee = OCSPTestUtil.makeCertificate(eeKp, "CN=EE", caKp, ca, false);
        X509Certificate ocsp = OCSPTestUtil.makeRootCertificate(ocspKp, "CN=OCSP");

        byte[] eeResp = getOcspResponse(ocspKp, digCalcProv, ca, ee);
        byte[] caResp = getOcspResponse(ocspKp, digCalcProv, root, ca);

        List list = new ArrayList();
        list.add(ee);
        list.add(ca);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));

        // EE Only
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", BC);

        PKIXRevocationChecker rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        Map responses = new HashMap();

        responses.put(ee, eeResp);

        rv.setOcspResponses(responses);

        rv.setOcspResponderCert(ocsp);

        rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.ONLY_END_ENTITY));

        PKIXParameters param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        cpv.validate(certPath, param);

        // CA and EE

        cpv = CertPathValidator.getInstance("PKIX", BC);

        rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        rv.setOcspResponses(responses);

        rv.setOcspResponderCert(ocsp);

        param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        try
        {
            cpv.validate(certPath, param);
            fail("no exception ca check");
        }
        catch (CertPathValidatorException e)
        {
            // ignore -- should fail as can't tell status of CA.
        }

        cpv = CertPathValidator.getInstance("PKIX", BC);

        rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        responses = new HashMap();

        responses.put(ee, eeResp);
        responses.put(ca, caResp);

        rv.setOcspResponses(responses);

        rv.setOcspResponderCert(ocsp);

        param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        cpv.validate(certPath, param);

        // EE revoke
        cpv = CertPathValidator.getInstance("PKIX", BC);

        rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        responses = new HashMap();

        responses.put(ee, getRevokedOcspResponse(ocspKp, digCalcProv, ca, ee));
        responses.put(ca, caResp);

        rv.setOcspResponses(responses);

        rv.setOcspResponderCert(ocsp);

        param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        try
        {
            cpv.validate(certPath, param);
            fail("no exception");
        }
        catch (CertPathValidatorException e)
        {
            isEquals(0, e.getIndex());
            isTrue(e.getMessage().startsWith("certificate revoked, reason=(CRLReason: keyCompromise)"));
        }

        // EE request not successful
        cpv = CertPathValidator.getInstance("PKIX", BC);

        rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        responses = new HashMap();

        responses.put(ee, getFailedOcspResponse(ocspKp, digCalcProv, ca, ee));
        responses.put(ca, caResp);

        rv.setOcspResponses(responses);

        rv.setOcspResponderCert(ocsp);

        param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        try
        {
            cpv.validate(certPath, param);
            fail("no exception");
        }
        catch (CertPathValidatorException e)
        {
            isEquals(0, e.getIndex());
            isTrue(e.getMessage().startsWith("OCSP response failed: "));
        }

        // EE only, OCSP responder
        cpv = CertPathValidator.getInstance("PKIX", BC);

        rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        rv.setOcspResponder(new URI("http://localhost:" + TEST_OCSP_RESPONDER_PORT + "/"));
        rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.ONLY_END_ENTITY));
        rv.setOcspResponderCert(ocsp);

        final byte[] nonce = new DEROctetString(Hex.decode("DEADBEEF")).getEncoded();

        List<java.security.cert.Extension> extensions = new ArrayList<java.security.cert.Extension>();

        extensions.add(new NonceExtension(nonce));

        rv.setOcspExtensions(extensions);

        param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        Thread ocspResponder = new Thread(new OCSPResponderTask(TEST_OCSP_RESPONDER_PORT, getOcspResponse(ocspKp, digCalcProv, ca, ee, nonce)));

        ocspResponder.setDaemon(true);
        ocspResponder.start();

        cpv.validate(certPath, param);

        // faulty OCSP responder certificate
        ocsp = OCSPTestUtil.makeCertificate(ocspKp, "CN=OCSP", caKp, ca, KeyPurposeId.id_kp_codeSigning);

        cpv = CertPathValidator.getInstance("PKIX", BC);

        rv = (PKIXRevocationChecker)cpv.getRevocationChecker();
        // need to avoid cache.
        rv.setOcspResponder(new URI("http://localhost:" + (TEST_OCSP_RESPONDER_PORT + 1) + "/"));
        rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.ONLY_END_ENTITY));

        param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        ocspResponder = new Thread(new OCSPResponderTask(
            TEST_OCSP_RESPONDER_PORT + 1,
            getOcspResponse(ocspKp, ocsp, digCalcProv, ca, ee)));

        ocspResponder.setDaemon(true);
        ocspResponder.start();

        try
        {
            cpv.validate(certPath, param);
            fail("no exception");
        }
        catch (CertPathValidatorException e)
        {
            isEquals(0, e.getIndex());
            isTrue(e.getMessage().equals("responder certificate not valid for signing OCSP responses"));
        }

        // corrected certificate
        ocsp = OCSPTestUtil.makeCertificate(ocspKp, "CN=OCSP", caKp, ca, KeyPurposeId.id_kp_OCSPSigning);

        cpv = CertPathValidator.getInstance("PKIX", BC);

        rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        rv.setOcspResponder(new URI("http://localhost:" + (TEST_OCSP_RESPONDER_PORT + 2) + "/"));
        rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.ONLY_END_ENTITY));

        param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        ocspResponder = new Thread(new OCSPResponderTask(
            TEST_OCSP_RESPONDER_PORT + 2,
            getOcspResponse(ocspKp, ocsp, digCalcProv, ca, ee)));

        ocspResponder.setDaemon(true);
        ocspResponder.start();

        cpv.validate(certPath, param);

        // EE Only, CA using responder URL
        ca = OCSPTestUtil.makeCertificateWithOCSP(caKp, "CN=CA", rootKp, root, true, "http://localhost:" + TEST_OCSP_RESPONDER_PORT + "/");
        ee = OCSPTestUtil.makeCertificate(eeKp, "CN=EE", caKp, ca, false);

        eeResp = getOcspResponseName(caKp, digCalcProv, ca, ee);
        caResp = getOcspResponse(ocspKp, digCalcProv, root, ca);

        list = new ArrayList();
        list.add(ee);
        list.add(ca);

        certPath = cf.generateCertPath(list);
        cpv = CertPathValidator.getInstance("PKIX", "BC");

        rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        responses = new HashMap();

        responses.put(ee, eeResp);

        rv.setOcspResponses(responses);

        rv.setOcspResponderCert(ocsp);

        ocspResponder = new Thread(new OCSPResponderTask(TEST_OCSP_RESPONDER_PORT, caResp));

        ocspResponder.setDaemon(true);
        ocspResponder.start();

        param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        cpv.validate(certPath, param);

        ocspCertChainTest();
        dispPointCertChainTest();
    }

    private void ocspCertChainTest()
        throws Exception
    {
        PEMParser parser = new PEMParser(new InputStreamReader(this.getClass().getResourceAsStream("ee.pem")));

        X509CertificateHolder c1 = (X509CertificateHolder)parser.readObject();

        parser = new PEMParser(new InputStreamReader(this.getClass().getResourceAsStream("ca.pem")));

        X509CertificateHolder c2 = (X509CertificateHolder)parser.readObject();

        parser = new PEMParser(new InputStreamReader(this.getClass().getResourceAsStream("ta.pem")));

        X509CertificateHolder c3 = (X509CertificateHolder)parser.readObject();

        JcaX509CertificateConverter conv = new JcaX509CertificateConverter().setProvider("BC");

        List t = new ArrayList();

        t.add(conv.getCertificate(c1));
        t.add(conv.getCertificate(c2));

        System.setProperty("org.bouncycastle.x509.enableCRLDP", "true");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        CertPath certPath = cf.generateCertPath(t);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(conv.getCertificate(c3), null));

        // EE Only
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", BC);

        PKIXRevocationChecker rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.NO_FALLBACK));

        PKIXParameters param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        cpv.validate(certPath, param);
    }

    private void dispPointCertChainTest()
        throws Exception
    {
        PEMParser parser = new PEMParser(new InputStreamReader(this.getClass().getResourceAsStream("ee.pem")));

        X509CertificateHolder c1 = (X509CertificateHolder)parser.readObject();

        parser = new PEMParser(new InputStreamReader(this.getClass().getResourceAsStream("ca.pem")));

        X509CertificateHolder c2 = (X509CertificateHolder)parser.readObject();

        parser = new PEMParser(new InputStreamReader(this.getClass().getResourceAsStream("ta.pem")));

        X509CertificateHolder c3 = (X509CertificateHolder)parser.readObject();

        JcaX509CertificateConverter conv = new JcaX509CertificateConverter().setProvider("BC");

        List t = new ArrayList();

        t.add(conv.getCertificate(c1));
        t.add(conv.getCertificate(c2));

        System.setProperty("org.bouncycastle.x509.enableCRLDP", "true");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        CertPath certPath = cf.generateCertPath(t);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(conv.getCertificate(c3), null));

        // EE and CA
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", BC);

        PKIXRevocationChecker rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.PREFER_CRLS));

        PKIXParameters param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        cpv.validate(certPath, param);

        // exercise cache
        certPath = cf.generateCertPath(t);

        trust = new HashSet();
        trust.add(new TrustAnchor(conv.getCertificate(c3), null));

        // EE and CA
        cpv = CertPathValidator.getInstance("PKIX", BC);

        rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.PREFER_CRLS));

        param = new PKIXParameters(trust);

        param.addCertPathChecker(rv);

        cpv.validate(certPath, param);
        System.setProperty("org.bouncycastle.x509.enableCRLDP", "");
    }

    private byte[] getOcspResponse(KeyPair ocspKp, DigestCalculatorProvider digCalcProv, X509Certificate issuerCert, X509Certificate cert)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(ocspKp.getPublic(), digCalcProv.get(RespID.HASH_SHA1));

        CertificateID eeID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());

        respGen.addResponse(eeID, CertificateStatus.GOOD);

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(ocspKp.getPrivate()), null, new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();

        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp).getEncoded();
    }

    private byte[] getOcspResponseName(KeyPair ocspKp, DigestCalculatorProvider digCalcProv, X509Certificate issuerCert, X509Certificate cert)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(issuerCert.getSubjectX500Principal());

        CertificateID eeID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());

        respGen.addResponse(eeID, CertificateStatus.GOOD);

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(ocspKp.getPrivate()), null, new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();

        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp).getEncoded();
    }

    private byte[] getOcspResponse(KeyPair ocspKp, DigestCalculatorProvider digCalcProv, X509Certificate issuerCert, X509Certificate cert, byte[] nonce)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(ocspKp.getPublic(), digCalcProv.get(RespID.HASH_SHA1));

        CertificateID eeID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());

        respGen.addResponse(eeID, CertificateStatus.GOOD);

        Extensions exts = new Extensions(new Extension[]
            { new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce) });

        respGen.setResponseExtensions(exts);

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(ocspKp.getPrivate()), null, new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();

        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp).getEncoded();
    }

    private byte[] getOcspResponse(KeyPair ocspKp, X509Certificate ocsp, DigestCalculatorProvider digCalcProv, X509Certificate issuerCert, X509Certificate cert)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(ocspKp.getPublic(), digCalcProv.get(RespID.HASH_SHA1));

        CertificateID eeID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());

        respGen.addResponse(eeID, CertificateStatus.GOOD);

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(ocspKp.getPrivate()), new X509CertificateHolder[] { new JcaX509CertificateHolder(ocsp) }, new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();

        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp).getEncoded();
    }

    private byte[] getRevokedOcspResponse(KeyPair ocspKp, DigestCalculatorProvider digCalcProv, X509Certificate issuerCert, X509Certificate cert)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(ocspKp.getPublic(), digCalcProv.get(RespID.HASH_SHA1));

        CertificateID eeID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());

        respGen.addResponse(eeID, new RevokedStatus(new Date(), CRLReason.keyCompromise));

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(ocspKp.getPrivate()), null, new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();

        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp).getEncoded();
    }

    private byte[] getFailedOcspResponse(KeyPair ocspKp, DigestCalculatorProvider digCalcProv, X509Certificate issuerCert, X509Certificate cert)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(ocspKp.getPublic(), digCalcProv.get(RespID.HASH_SHA1));

        CertificateID eeID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());

        respGen.addResponse(eeID, new RevokedStatus(new Date(), CRLReason.keyCompromise));

        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(ocspKp.getPrivate()), null, new Date());
        OCSPRespBuilder rGen = new OCSPRespBuilder();

        return rGen.build(OCSPRespBuilder.UNAUTHORIZED, resp).getEncoded();
    }

    private class NonceExtension
        implements java.security.cert.Extension
    {
        private final byte[] nonce;

        NonceExtension(byte[] nonce)
        {
            this.nonce = nonce;
        }

        public String getId()
        {
            return OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId();
        }

        public boolean isCritical()
        {
            return false;
        }

        public byte[] getValue()
        {
            return nonce;
        }

        public void encode(OutputStream outputStream)
            throws IOException
        {
            outputStream.write(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce).getEncoded());
        }
    }

    private class OCSPResponderTask
        implements Runnable
    {
        private final byte[] resp;
        private final int portNo;

        OCSPResponderTask(int portNo, byte[] resp)
        {
            this.portNo = portNo;
            this.resp = resp;
        }

        public void run()
        {
            try
            {
                ServerSocket ss = new ServerSocket(portNo);
                Socket s = ss.accept();

                InputStream sIn = s.getInputStream();
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                int ch;
                int contentLength = 0;
                while ((ch = sIn.read()) >= 0)
                {
                    bOut.write(ch);
                    if (ch == '\n')
                    {
                        String line = Strings.fromByteArray(bOut.toByteArray()).trim();
                        if (line.startsWith("Content-Length"))
                        {
                             contentLength = Integer.parseInt(line.substring("Content-Length: ".length()));
                        }
                        if (line.length() == 0)
                        {
                            break;
                        }
                        bOut.reset();
                    }
                }

                byte[] request = new byte[contentLength];
                Streams.readFully(sIn, request);

                OutputStream sOut = s.getOutputStream();

                sOut.write(Strings.toByteArray("HTTP/1.1 200 OK\r\n"));
                sOut.write(Strings.toByteArray("Content-type: application/ocsp-response\r\n"));
                sOut.write(Strings.toByteArray("Content-Length: " + resp.length + "\r\n"));
                sOut.write(Strings.toByteArray("\r\n"));
                sOut.write(resp);
                sOut.flush();
                sOut.close();
                s.close();
                ss.close();
            }
            catch (Exception e)
            {
                // ignore
            }
        }
    }
    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PKIXRevocationTest());
    }
}
