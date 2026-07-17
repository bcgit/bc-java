package org.bouncycastle.cert.ocsp.test;

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

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Offline coverage for the JCA OCSP revocation path
 * ({@code java.security.cert.PKIXRevocationChecker} backed by Bouncy Castle's
 * {@code ProvOcspRevocationChecker}), driven entirely from stapled responses set
 * via {@link PKIXRevocationChecker#setOcspResponses}. This is the network-free
 * subset of the (otherwise dormant, responder-socket-based)
 * {@code PKIXRevocationTest}: a GOOD end-entity response validates, a missing
 * CA-status response and a REVOKED or unsuccessful response are each rejected
 * with the documented index and message.
 */
public class PKIXOcspRevocationCheckerTest
    extends SimpleTest
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public String getName()
    {
        return "PKIXOcspRevocationCheckerTest";
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

        // 1) EE only (ONLY_END_ENTITY), GOOD -> validates
        Map responses = new HashMap();
        responses.put(ee, eeResp);
        validate(certPath, trust, responses, ocsp, true);

        // 2) full chain but only the EE response present -> CA status unknown -> reject
        responses = new HashMap();
        responses.put(ee, eeResp);
        try
        {
            validate(certPath, trust, responses, ocsp, false);
            fail("no exception on missing CA status");
        }
        catch (CertPathValidatorException e)
        {
            // expected: CA status cannot be determined
        }

        // 3) full chain, both responses GOOD -> validates
        responses = new HashMap();
        responses.put(ee, eeResp);
        responses.put(ca, caResp);
        validate(certPath, trust, responses, ocsp, false);

        // 4) EE revoked -> reject with documented index/message
        responses = new HashMap();
        responses.put(ee, getRevokedOcspResponse(ocspKp, digCalcProv, ca, ee));
        responses.put(ca, caResp);
        try
        {
            validate(certPath, trust, responses, ocsp, false);
            fail("no exception on revoked EE");
        }
        catch (CertPathValidatorException e)
        {
            isEquals(0, e.getIndex());
            isTrue(e.getMessage().startsWith("certificate revoked, reason=(CRLReason: keyCompromise)"));
        }

        // 5) EE response not SUCCESSFUL -> reject
        responses = new HashMap();
        responses.put(ee, getFailedOcspResponse(ocspKp, digCalcProv, ca, ee));
        responses.put(ca, caResp);
        try
        {
            validate(certPath, trust, responses, ocsp, false);
            fail("no exception on failed OCSP response");
        }
        catch (CertPathValidatorException e)
        {
            isEquals(0, e.getIndex());
            isTrue(e.getMessage().startsWith("OCSP response failed: "));
        }

        // 6) caller configures a nonce but the (validly signed) response omits it. Many responders
        // do not echo nonces, so this must be a clean "nonce mismatch" rejection, NOT a
        // NullPointerException on the absent responseExtensions/nonce extension. The NPE mattered
        // because on the network-fetch path it escaped check() as a raw unchecked exception rather
        // than the documented CertPathValidatorException.
        responses = new HashMap();
        responses.put(ee, eeResp);
        try
        {
            validateWithNonce(certPath, trust, responses, ocsp);
            fail("no exception when response omits the caller-supplied OCSP nonce");
        }
        catch (CertPathValidatorException e)
        {
            isTrue("expected a nonce-mismatch rejection, got: " + e.getMessage(),
                e.getMessage() != null && e.getMessage().indexOf("nonce mismatch in OCSP response") >= 0);
        }
    }

    private void validateWithNonce(CertPath certPath, Set trust, Map responses, X509Certificate ocspCert)
        throws Exception
    {
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", BC);
        PKIXRevocationChecker rv = (PKIXRevocationChecker)cpv.getRevocationChecker();
        rv.setOcspResponses(responses);
        rv.setOcspResponderCert(ocspCert);
        rv.setOcspExtensions(Collections.singletonList(nonceExtension()));
        rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.ONLY_END_ENTITY));
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertPathChecker(rv);
        cpv.validate(certPath, param);
    }

    private static java.security.cert.Extension nonceExtension()
    {
        final String oid = OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId();
        final byte[] value = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        return new java.security.cert.Extension()
        {
            public String getId()
            {
                return oid;
            }

            public boolean isCritical()
            {
                return false;
            }

            public byte[] getValue()
            {
                return value;
            }

            public void encode(java.io.OutputStream out)
                throws java.io.IOException
            {
                // Not exercised by the revocation-checker path under test; emit a well-formed
                // extnID + extnValue OCTET STRING so the impl is nonetheless correct if called.
                out.write(new org.bouncycastle.asn1.x509.Extension(
                    new org.bouncycastle.asn1.ASN1ObjectIdentifier(oid), false,
                    new org.bouncycastle.asn1.DEROctetString(value)).getEncoded());
            }
        };
    }

    private void validate(CertPath certPath, Set trust, Map responses, X509Certificate ocspCert, boolean endEntityOnly)
        throws Exception
    {
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", BC);
        PKIXRevocationChecker rv = (PKIXRevocationChecker)cpv.getRevocationChecker();
        rv.setOcspResponses(responses);
        rv.setOcspResponderCert(ocspCert);
        if (endEntityOnly)
        {
            rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.ONLY_END_ENTITY));
        }
        PKIXParameters param = new PKIXParameters(trust);
        param.addCertPathChecker(rv);
        cpv.validate(certPath, param);
    }

    private byte[] getOcspResponse(KeyPair ocspKp, DigestCalculatorProvider digCalcProv, X509Certificate issuerCert, X509Certificate cert)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(ocspKp.getPublic(), digCalcProv.get(RespID.HASH_SHA1));
        CertificateID eeID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());
        respGen.addResponse(eeID, CertificateStatus.GOOD);
        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(ocspKp.getPrivate()), null, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, resp).getEncoded();
    }

    private byte[] getRevokedOcspResponse(KeyPair ocspKp, DigestCalculatorProvider digCalcProv, X509Certificate issuerCert, X509Certificate cert)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(ocspKp.getPublic(), digCalcProv.get(RespID.HASH_SHA1));
        CertificateID eeID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());
        respGen.addResponse(eeID, new RevokedStatus(new Date(), CRLReason.keyCompromise));
        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(ocspKp.getPrivate()), null, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, resp).getEncoded();
    }

    private byte[] getFailedOcspResponse(KeyPair ocspKp, DigestCalculatorProvider digCalcProv, X509Certificate issuerCert, X509Certificate cert)
        throws Exception
    {
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(ocspKp.getPublic(), digCalcProv.get(RespID.HASH_SHA1));
        CertificateID eeID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());
        respGen.addResponse(eeID, new RevokedStatus(new Date(), CRLReason.keyCompromise));
        BasicOCSPResp resp = respGen.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(ocspKp.getPrivate()), null, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.UNAUTHORIZED, resp).getEncoded();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new PKIXOcspRevocationCheckerTest());
    }
}
