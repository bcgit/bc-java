package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

/**
 * CertPath validation of a certificate listed on a CRL with a reasonCode that RFC 5280 sec. 5.3.1
 * does not define.
 * <p>
 * The CRL entry is what revokes the certificate; an undefined reason code is processed as
 * unspecified, and is reported as given if it fits in an int. Codes 11 and 12 once collided with
 * the values the provider's CRL status tracking used for unrevoked and undetermined, so a CRL
 * entry carrying them left the certificate unrevoked.
 * </p>
 */
public class CrlReasonCodeTest
    extends SimpleTest
{
    private static final String SIG_ALG = "SHA256withRSA";

    private KeyPair caKP;
    private X509Certificate caCert;
    private X509Certificate eeCert;

    public String getName()
    {
        return "CrlReasonCode";
    }

    public void performTest()
        throws Exception
    {
        caKP = TestUtils.generateRSAKeyPair();
        X500Name caName = new X500Name("CN=Root,O=BC");
        caCert = TestUtils.createSelfSignedCert(caName, SIG_ALG, caKP);

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        eeCert = TestUtils.createCert(caName, caKP.getPrivate(), new X500Name("CN=EE"), SIG_ALG, extGen.generate(),
            TestUtils.generateRSAKeyPair().getPublic());

        checkRevokedWithReasonCode(null, "unspecified");
        checkRevokedWithReasonCode(BigInteger.valueOf(1), "keyCompromise");
        checkRevokedWithReasonCode(BigInteger.valueOf(7), "(unknown code: 7)");
        checkRevokedWithReasonCode(BigInteger.valueOf(11), "(unknown code: 11)");
        checkRevokedWithReasonCode(BigInteger.valueOf(12), "(unknown code: 12)");
        checkRevokedWithReasonCode(BigInteger.valueOf(-1), "(unknown code: -1)");
        checkRevokedWithReasonCode(BigInteger.ONE.shiftLeft(40), "unspecified");
    }

    private void checkRevokedWithReasonCode(BigInteger reasonCode, String expectedReason)
        throws Exception
    {
        X509CRL crl = makeCrl(reasonCode);

        try
        {
            validate(crl);
            fail("reason code " + reasonCode + ": certificate not treated as revoked");
        }
        catch (CertPathValidatorException e)
        {
            isEquals("reason code " + reasonCode + ": index", 0, e.getIndex());
            isTrue("reason code " + reasonCode + ": " + e.getMessage(),
                e.getMessage().endsWith(", reason: " + expectedReason));
        }
    }

    private X509CRL makeCrl(BigInteger reasonCode)
        throws Exception
    {
        long now = System.currentTimeMillis();

        V2TBSCertListGenerator g = new V2TBSCertListGenerator();
        g.setIssuer(X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded()));
        g.setThisUpdate(new Time(new Date(now - 5 * 60 * 1000)));
        g.setNextUpdate(new Time(new Date(now + 60 * 60 * 1000)));
        g.setSignature(rsaSha256AlgId());

        Time revocationDate = new Time(new Date(now - 60 * 1000));
        if (reasonCode == null)
        {
            g.addCRLEntry(new ASN1Integer(eeCert.getSerialNumber()), revocationDate, null);
        }
        else
        {
            // Built directly, since the reasonCode values of interest are not all valid CRLReasons
            ExtensionsGenerator entryExtGen = new ExtensionsGenerator();
            entryExtGen.addExtension(Extension.reasonCode, false, new ASN1Enumerated(reasonCode));
            g.addCRLEntry(new ASN1Integer(eeCert.getSerialNumber()), revocationDate, entryExtGen.generate());
        }

        TBSCertList tbs = g.generateTBSCertList();
        Signature sig = Signature.getInstance(SIG_ALG, "BC");
        sig.initSign(caKP.getPrivate());
        sig.update(tbs.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(rsaSha256AlgId());
        v.add(new DERBitString(sig.sign()));

        return (X509CRL)CertificateFactory.getInstance("X.509", "BC")
            .generateCRL(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    private void validate(X509CRL crl)
        throws Exception
    {
        Set anchors = new HashSet();
        anchors.add(new TrustAnchor(caCert, null));

        List storeContents = new ArrayList();
        storeContents.add(caCert);
        storeContents.add(eeCert);
        storeContents.add(crl);

        PKIXParameters params = new PKIXParameters(anchors);
        params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(storeContents), "BC"));
        params.setRevocationEnabled(true);
        params.setDate(new Date());

        CertPath path = CertificateFactory.getInstance("X.509", "BC").generateCertPath(Collections.singletonList(eeCert));

        CertPathValidator.getInstance("PKIX", "BC").validate(path, params);
    }

    private static AlgorithmIdentifier rsaSha256AlgId()
    {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CrlReasonCodeTest());
    }
}
