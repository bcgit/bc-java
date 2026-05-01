package org.bouncycastle.cert.ocsp.test;

import java.security.KeyPair;
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

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for https://github.com/bcgit/bc-java/issues/2254 - a manually
 * supplied OCSP response whose signature does not verify must be rejected by
 * ProvOcspRevocationChecker rather than silently accepted.
 */
public class OCSPExceptionalSignatureRejectionTest
    extends SimpleTest
{
    private static final String BC = "BC";

    public String getName()
    {
        return "Issue2254Test";
    }

    public void performTest()
        throws Exception
    {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

        KeyPair rootKp = OCSPTestUtil.makeKeyPair();
        KeyPair caKp = OCSPTestUtil.makeKeyPair();
        KeyPair eeKp = OCSPTestUtil.makeKeyPair();
        KeyPair ocspKp = OCSPTestUtil.makeKeyPair();
        KeyPair bogusKp = OCSPTestUtil.makeKeyPair();

        X509Certificate root = OCSPTestUtil.makeRootCertificate(rootKp, "CN=Root");
        X509Certificate ca = OCSPTestUtil.makeCertificate(caKp, "CN=CA", rootKp, root, true);
        X509Certificate ee = OCSPTestUtil.makeCertificate(eeKp, "CN=EE", caKp, ca, false);
        X509Certificate ocsp = OCSPTestUtil.makeRootCertificate(ocspKp, "CN=OCSP");

        // ResponderID identifies ocspKp (matches setOcspResponderCert below) but
        // the response is signed by bogusKp - signature verification must fail.
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(
            ocspKp.getPublic(), digCalcProv.get(RespID.HASH_SHA1));

        CertificateID eeID = new CertificateID(
            digCalcProv.get(CertificateID.HASH_SHA1),
            new JcaX509CertificateHolder(ca), ee.getSerialNumber());

        respGen.addResponse(eeID, CertificateStatus.GOOD);

        BasicOCSPResp basicResp = respGen.build(
            new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(bogusKp.getPrivate()),
            null, new Date());

        byte[] eeBadResp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp).getEncoded();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);

        List list = new ArrayList();
        list.add(ee);
        list.add(ca);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", BC);

        PKIXRevocationChecker rv = (PKIXRevocationChecker)cpv.getRevocationChecker();

        Map responses = new HashMap();
        responses.put(ee, eeBadResp);

        rv.setOcspResponses(responses);
        rv.setOcspResponderCert(ocsp);
        rv.setOptions(Collections.singleton(PKIXRevocationChecker.Option.ONLY_END_ENTITY));

        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.addCertPathChecker(rv);

        try
        {
            cpv.validate(certPath, param);
            fail("no exception - invalid OCSP response signature was ignored");
        }
        catch (CertPathValidatorException e)
        {
            isEquals(0, e.getIndex());
            isTrue("unexpected message: " + e.getMessage(),
                "OCSP response failed to validate".equals(e.getMessage()));
        }
    }

    public static void main(String[] args)
    {
        runTest(new OCSPExceptionalSignatureRejectionTest());
    }
}
