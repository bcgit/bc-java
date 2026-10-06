package org.bouncycastle.cert.path.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.path.CertPath;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.cert.path.CertPathValidationResult;
import org.bouncycastle.cert.path.validations.BasicConstraintsValidation;
import org.bouncycastle.cert.path.validations.CRLValidation;
import org.bouncycastle.cert.path.validations.CertificatePoliciesValidationBuilder;
import org.bouncycastle.cert.path.validations.KeyUsageValidation;
import org.bouncycastle.cert.path.validations.ParentCertIssuedValidation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Asserts the individual rules of the lightweight cert.path API - the failure each validation
 * reports, the inputs each one accepts, that a Memoable copy or reset carries the working state on,
 * and how validate() and evaluate() report a path that breaks more than one rule.
 */
public class CertPathValidationRulesTest
    extends SimpleTest
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final X500Name ROOT_NAME = new X500Name("CN=Rules Root");
    private static final X500Name CA_NAME = new X500Name("CN=Rules CA");
    private static final X500Name EE_NAME = new X500Name("CN=Rules EE");

    private static final int CA_USAGE = KeyUsage.keyCertSign | KeyUsage.cRLSign;

    private final X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder().setProvider(BC);

    private KeyPair rootKp;
    private KeyPair caKp;
    private KeyPair eeKp;
    private KeyPair otherKp;

    private X509CertificateHolder root;
    private X509CertificateHolder ca;
    private X509CertificateHolder ee;

    private int serial = 1;

    public String getName()
    {
        return "CertPathValidationRules";
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
        kpGen.initialize(256);

        rootKp = kpGen.generateKeyPair();
        caKp = kpGen.generateKeyPair();
        eeKp = kpGen.generateKeyPair();
        otherKp = kpGen.generateKeyPair();

        root = cert(ROOT_NAME, rootKp.getPrivate(), ROOT_NAME, rootKp, new BasicConstraints(true), CA_USAGE);
        ca = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp, new BasicConstraints(true), CA_USAGE);
        ee = cert(CA_NAME, caKp.getPrivate(), EE_NAME, eeKp, null, KeyUsage.digitalSignature);

        keyUsageTest();
        parentCertIssuedTest();
        dsaInheritedParametersTest();
        crlTest();
        basicConstraintsTest();
        memoableTest();
        validateAndEvaluateTest();
        certificatePoliciesTest();
    }

    private void keyUsageTest()
        throws Exception
    {
        // a CA certificate whose KeyUsage does not include keyCertSign cannot issue
        X509CertificateHolder noCertSign = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp,
            new BasicConstraints(true), KeyUsage.digitalSignature | KeyUsage.cRLSign);
        X509CertificateHolder[] path = path(cert(CA_NAME, caKp.getPrivate(), EE_NAME, eeKp, null, 0), noCertSign);

        checkFails("CA without keyCertSign", new CertPath(path).validate(new CertPathValidation[]{ new KeyUsageValidation() }),
            1, 0, "Issuer certificate KeyUsage extension does not permit key signing");
        checkFails("CA without keyCertSign, KeyUsage optional", new CertPath(path).validate(new CertPathValidation[]{ new KeyUsageValidation(false) }),
            1, 0, "Issuer certificate KeyUsage extension does not permit key signing");

        // a CA certificate with no KeyUsage at all is refused only when the extension is mandatory
        X509CertificateHolder noKeyUsage = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp, new BasicConstraints(true), 0);
        path = path(cert(CA_NAME, caKp.getPrivate(), EE_NAME, eeKp, null, 0), noKeyUsage);

        checkFails("CA without KeyUsage", new CertPath(path).validate(new CertPathValidation[]{ new KeyUsageValidation() }),
            1, 0, "KeyUsage extension not present in CA certificate");
        checkValid("CA without KeyUsage, KeyUsage optional", new CertPath(path).validate(new CertPathValidation[]{ new KeyUsageValidation(false) }));

        // the end entity is not an issuer: its KeyUsage is not examined, present or absent
        checkValid("end entity with digitalSignature only", new CertPath(path(ee, ca)).validate(new CertPathValidation[]{ new KeyUsageValidation() }));
        checkValid("end entity without KeyUsage", new CertPath(path(cert(CA_NAME, caKp.getPrivate(), EE_NAME, eeKp, null, 0), ca))
            .validate(new CertPathValidation[]{ new KeyUsageValidation() }));
    }

    private void parentCertIssuedTest()
        throws Exception
    {
        checkValid("well formed path", new CertPath(path(ee, ca)).validate(new CertPathValidation[]{ new ParentCertIssuedValidation(verifier) }));

        // signed by the CA, but naming another issuer
        X509CertificateHolder wrongIssuer = cert(new X500Name("CN=Someone Else"), caKp.getPrivate(), EE_NAME, eeKp, null, 0);
        checkFails("issuer name not the parent's subject",
            new CertPath(path(wrongIssuer, ca)).validate(new CertPathValidation[]{ new ParentCertIssuedValidation(verifier) }),
            0, 0, "Certificate issue does not match parent");

        // naming the CA, but signed with another key
        X509CertificateHolder wrongKey = cert(CA_NAME, otherKp.getPrivate(), EE_NAME, eeKp, null, 0);
        checkFails("signature not by the parent's key",
            new CertPath(path(wrongKey, ca)).validate(new CertPathValidation[]{ new ParentCertIssuedValidation(verifier) }),
            0, 0, "Certificate signature not for public key in parent");
    }

    /**
     * RFC 5280 sec. 6.1.4 (f): a DSA key whose subjectPublicKeyInfo omits the domain parameters
     * inherits them from the issuer, and certificates it signs must be verified with them.
     */
    private void dsaInheritedParametersTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", BC);
        kpGen.initialize(2048);

        KeyPair dsaRootKp = kpGen.generateKeyPair();
        KeyPair dsaCaKp = kpGen.generateKeyPair();

        SubjectPublicKeyInfo caInfo = SubjectPublicKeyInfo.getInstance(dsaCaKp.getPublic().getEncoded());
        SubjectPublicKeyInfo caInfoNoParams = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(caInfo.getAlgorithm().getAlgorithm()), caInfo.parsePublicKey());

        X509CertificateHolder dsaRoot = cert(ROOT_NAME, dsaRootKp.getPrivate(), "SHA256withDSA", ROOT_NAME,
            SubjectPublicKeyInfo.getInstance(dsaRootKp.getPublic().getEncoded()), new BasicConstraints(true), CA_USAGE);
        X509CertificateHolder dsaCa = cert(ROOT_NAME, dsaRootKp.getPrivate(), "SHA256withDSA", CA_NAME,
            caInfoNoParams, new BasicConstraints(true), CA_USAGE);
        X509CertificateHolder dsaEe = cert(CA_NAME, dsaCaKp.getPrivate(), "SHA256withDSA", EE_NAME,
            SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded()), null, 0);

        isTrue("CA key still carries parameters", caInfoNoParams.getAlgorithm().getParameters() == null);

        checkValid("DSA key with inherited parameters",
            new CertPath(new X509CertificateHolder[]{ dsaEe, dsaCa, dsaRoot }).validate(new CertPathValidation[]{ new ParentCertIssuedValidation(verifier) }));

        // the inherited parameters are only used to verify, not to make another key's signature acceptable
        X509CertificateHolder dsaForged = cert(CA_NAME, dsaRootKp.getPrivate(), "SHA256withDSA", EE_NAME,
            SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded()), null, 0);
        checkFails("DSA signature by another key",
            new CertPath(new X509CertificateHolder[]{ dsaForged, dsaCa, dsaRoot }).validate(new CertPathValidation[]{ new ParentCertIssuedValidation(verifier) }),
            0, 0, "Certificate signature not for public key in parent");
    }

    private void crlTest()
        throws Exception
    {
        // the root is checked against a CRL from the trust anchor, the CA against the root's, and
        // the end entity against the CA's
        X509CRLHolder rootCrl = crl(ROOT_NAME, rootKp.getPrivate(), null);
        X509CRLHolder caCrl = crl(CA_NAME, caKp.getPrivate(), null);

        X509CertificateHolder[] path = path(ee, ca);

        checkValid("no certificate revoked", new CertPath(path).validate(new CertPathValidation[]{ crlValidation(rootCrl, caCrl) }));

        checkFails("end entity revoked",
            new CertPath(path).validate(new CertPathValidation[]{ crlValidation(rootCrl, crl(CA_NAME, caKp.getPrivate(), ee.getSerialNumber())) }),
            0, 0, "Certificate revoked");
        checkFails("CA revoked",
            new CertPath(path).validate(new CertPathValidation[]{ crlValidation(crl(ROOT_NAME, rootKp.getPrivate(), ca.getSerialNumber()), caCrl) }),
            1, 0, "Certificate revoked");

        checkFails("no CRL for the CA",
            new CertPath(path).validate(new CertPathValidation[]{ crlValidation(rootCrl, null) }),
            0, 0, "CRL for " + CA_NAME + " not found");

        // a CRL bearing the CA's name but not its signature must not count, either way
        X509CRLHolder forged = crl(CA_NAME, otherKp.getPrivate(), null);
        checkFails("CRL not signed by the issuer",
            new CertPath(path).validate(new CertPathValidation[]{ crlValidation(rootCrl, forged) }),
            0, 0, "CRL signature invalid for " + CA_NAME);

        // with no key to verify against, a matching CRL is refused rather than trusted
        Store crls = new CollectionStore(list(rootCrl, caCrl));
        checkFails("CRL verification not configured",
            new CertPath(path).validate(new CertPathValidation[]{ new CRLValidation(ROOT_NAME, crls) }),
            2, 0, "CRL signature verification not configured for " + ROOT_NAME);

        crlDatesTest(rootCrl, caCrl);
    }

    /**
     * Each certificate needs a CRL from its issuer that is current - thisUpdate not after the
     * validation date beyond the clock skew allowance, nextUpdate (if stated) not before it - while a
     * revocation on any CRL not dated in the future is honoured.
     */
    private void crlDatesTest(X509CRLHolder rootCrl, X509CRLHolder caCrl)
        throws Exception
    {
        X509CertificateHolder[] path = path(ee, ca);
        BigInteger eeSerial = ee.getSerialNumber();

        X509CRLHolder stale = crl(CA_NAME, caKp.getPrivate(), null, -180, Integers.valueOf(-60));
        X509CRLHolder staleRevoking = crl(CA_NAME, caKp.getPrivate(), eeSerial, -180, Integers.valueOf(-60));
        X509CRLHolder future = crl(CA_NAME, caKp.getPrivate(), null, 60, Integers.valueOf(120));
        X509CRLHolder futureRevoking = crl(CA_NAME, caKp.getPrivate(), eeSerial, 60, Integers.valueOf(120));

        checkFails("only an out of date CRL", validateCrls(path, null, list(rootCrl, stale)), 0, 0, "no current CRL for " + CA_NAME);
        checkValid("out of date CRL beside a current one", validateCrls(path, null, list(rootCrl, stale, caCrl)));
        checkFails("revocation on an out of date CRL", validateCrls(path, null, list(rootCrl, staleRevoking, caCrl)),
            0, 0, "Certificate revoked");

        checkFails("only a CRL from the future", validateCrls(path, null, list(rootCrl, future)), 0, 0, "no current CRL for " + CA_NAME);
        checkValid("revocation on a CRL from the future", validateCrls(path, null, list(rootCrl, futureRevoking, caCrl)));
        checkValid("CRL dated inside the clock skew allowance",
            validateCrls(path, null, list(rootCrl, crl(CA_NAME, caKp.getPrivate(), null, 5, Integers.valueOf(60)))));

        checkValid("CRL stating no nextUpdate",
            validateCrls(path, null, list(rootCrl, crl(CA_NAME, caKp.getPrivate(), null, -60, null))));

        // the root's own CRL is judged the same way
        checkFails("out of date CRL for the root", validateCrls(path, null,
            list(crl(ROOT_NAME, rootKp.getPrivate(), null, -180, Integers.valueOf(-60)), caCrl)), 2, 0, "no current CRL for " + ROOT_NAME);

        // a validation date moves the window: the out of date CRL was current two hours ago, the
        // current one will not be in two hours
        Date twoHoursAgo = new Date(System.currentTimeMillis() - 120 * 60 * 1000L);
        Date inTwoHours = new Date(System.currentTimeMillis() + 120 * 60 * 1000L);
        X509CRLHolder rootThen = crl(ROOT_NAME, rootKp.getPrivate(), null, -180, Integers.valueOf(-60));

        checkValid("out of date CRL at an earlier date", validateCrls(path, twoHoursAgo, list(rootThen, stale)));
        checkFails("current CRL at a later date", validateCrls(path, inTwoHours, list(rootCrl, caCrl)), 2, 0, "no current CRL for " + ROOT_NAME);

        // the validation date is copied, not shared with the caller
        Date mutable = new Date(twoHoursAgo.getTime());
        CRLValidation v = new CRLValidation(ROOT_NAME, root.getSubjectPublicKeyInfo(), verifier, new CollectionStore(list(rootThen, stale)), mutable);
        mutable.setTime(inTwoHours.getTime());
        checkValid("validation date changed after construction", new CertPath(path).validate(new CertPathValidation[]{ v }));

        // the validation date travels with a copy and a reset
        checkMemoable("CRLValidation date", new CRLValidation(ROOT_NAME, root.getSubjectPublicKeyInfo(), verifier,
            new CollectionStore(list(rootThen, stale)), twoHoursAgo), new CRLValidation(EE_NAME, new CollectionStore(new ArrayList())),
            path, 1, null);
    }

    private CertPathValidationResult validateCrls(X509CertificateHolder[] path, Date validDate, List crls)
    {
        return new CertPath(path).validate(new CertPathValidation[]{
            new CRLValidation(ROOT_NAME, root.getSubjectPublicKeyInfo(), verifier, new CollectionStore(crls), validDate) });
    }

    private void basicConstraintsTest()
        throws Exception
    {
        // a certificate issued by one that is not a CA
        X509CertificateHolder notCa = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp, new BasicConstraints(false), CA_USAGE);
        X509CertificateHolder[] path = path(ee, notCa);
        checkFails("issuer not a CA", new CertPath(path).validate(new CertPathValidation[]{ new BasicConstraintsValidation() }),
            0, 0, "Basic constraints violated: issuer is not a CA");

        // with no basicConstraints at all the issuer is accepted only when the extension is optional
        X509CertificateHolder noBc = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp, null, CA_USAGE);
        path = path(ee, noBc);
        checkFails("issuer without basicConstraints", new CertPath(path).validate(new CertPathValidation[]{ new BasicConstraintsValidation() }),
            0, 0, "Basic constraints violated: issuer is not a CA");
        checkValid("issuer without basicConstraints, extension optional",
            new CertPath(path).validate(new CertPathValidation[]{ new BasicConstraintsValidation(false) }));

        // RFC 5280 sec. 6.1.4 (m): a later, smaller pathLenConstraint takes over, a later larger one
        // does not widen the remaining length
        KeyPair ca2Kp = otherKp;
        X500Name ca2Name = new X500Name("CN=Rules CA 2");
        X500Name ca3Name = new X500Name("CN=Rules CA 3");
        KeyPair ca3Kp = eeKp;

        checkFails("smaller later constraint", pathLenChain(5, 0, ca2Name, ca2Kp, ca3Name, ca3Kp), 1, "Basic constraints violated: path length exceeded");
        checkValid("smaller later constraint, permitted", new CertPath(pathLenChainCerts(5, 1, ca2Name, ca2Kp, ca3Name, ca3Kp))
            .validate(new CertPathValidation[]{ new BasicConstraintsValidation() }));
        checkFails("larger later constraint", pathLenChain(1, 5, ca2Name, ca2Kp, ca3Name, ca3Kp), 1, "Basic constraints violated: path length exceeded");
    }

    // root -> CA (caPathLen) -> CA 2 (ca2PathLen) -> CA 3 -> end entity
    private X509CertificateHolder[] pathLenChainCerts(int caPathLen, int ca2PathLen, X500Name ca2Name, KeyPair ca2Kp,
        X500Name ca3Name, KeyPair ca3Kp)
        throws Exception
    {
        KeyPair leafKp = rootKp;

        X509CertificateHolder c1 = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp, new BasicConstraints(caPathLen), CA_USAGE);
        X509CertificateHolder c2 = cert(CA_NAME, caKp.getPrivate(), ca2Name, ca2Kp, new BasicConstraints(ca2PathLen), CA_USAGE);
        X509CertificateHolder c3 = cert(ca2Name, ca2Kp.getPrivate(), ca3Name, ca3Kp, new BasicConstraints(true), CA_USAGE);
        X509CertificateHolder leaf = cert(ca3Name, ca3Kp.getPrivate(), EE_NAME, leafKp, null, 0);

        return new X509CertificateHolder[]{ leaf, c3, c2, c1, root };
    }

    private CertPathValidationResult pathLenChain(int caPathLen, int ca2PathLen, X500Name ca2Name, KeyPair ca2Kp,
        X500Name ca3Name, KeyPair ca3Kp)
        throws Exception
    {
        return new CertPath(pathLenChainCerts(caPathLen, ca2PathLen, ca2Name, ca2Kp, ca3Name, ca3Kp))
            .validate(new CertPathValidation[]{ new BasicConstraintsValidation() });
    }

    /**
     * A copy taken part way along a path, or a fresh instance reset from one, must reach the same
     * outcome as the original on the rest of the path - so each validation's working state has to
     * travel with it.
     */
    private void memoableTest()
        throws Exception
    {
        // the path length is already used up when the copy is taken
        X509CertificateHolder ca0 = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp, new BasicConstraints(0), CA_USAGE);
        X500Name subName = new X500Name("CN=Rules Sub CA");
        X509CertificateHolder sub = cert(CA_NAME, caKp.getPrivate(), subName, otherKp, new BasicConstraints(true), CA_USAGE);
        X509CertificateHolder leaf = cert(subName, otherKp.getPrivate(), EE_NAME, eeKp, null, 0);
        checkMemoable("BasicConstraintsValidation path length", new BasicConstraintsValidation(), new BasicConstraintsValidation(),
            new X509CertificateHolder[]{ leaf, sub, ca0, root }, 2, "Basic constraints violated: path length exceeded");

        // the optional flag travels too
        X509CertificateHolder noBc = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp, null, CA_USAGE);
        checkMemoable("BasicConstraintsValidation optional", new BasicConstraintsValidation(false), new BasicConstraintsValidation(true),
            path(ee, noBc), 2, null);
        X509CertificateHolder noKu = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp, new BasicConstraints(true), 0);
        checkMemoable("KeyUsageValidation optional", new KeyUsageValidation(false), new KeyUsageValidation(true),
            path(ee, noKu), 2, null);

        // the parent's key: a copy that lost it would accept the wrongly signed certificate
        X509CertificateHolder wrongKey = cert(CA_NAME, otherKp.getPrivate(), EE_NAME, eeKp, null, 0);
        checkMemoable("ParentCertIssuedValidation", new ParentCertIssuedValidation(verifier), new ParentCertIssuedValidation(verifier),
            path(wrongKey, ca), 1, "Certificate signature not for public key in parent");

        // the CRL issuer and key: the end entity must still be found revoked on the CA's CRL
        X509CRLHolder rootCrl = crl(ROOT_NAME, rootKp.getPrivate(), null);
        X509CRLHolder caCrl = crl(CA_NAME, caKp.getPrivate(), ee.getSerialNumber());
        checkMemoable("CRLValidation", crlValidation(rootCrl, caCrl), new CRLValidation(EE_NAME, new CollectionStore(new ArrayList())),
            path(ee, ca), 1, "Certificate revoked");
    }

    /**
     * Runs v over the certificates from the root down to index split, then finishes the path with
     * v itself, with a copy of v, and with other reset from v, expecting the same outcome from all
     * three: success when expected is null, otherwise a failure with that message.
     */
    private void checkMemoable(String label, CertPathValidation v, CertPathValidation other,
        X509CertificateHolder[] certs, int split, String expected)
        throws Exception
    {
        CertPathValidationContext context = new CertPathValidationContext(new HashSet());

        for (int j = certs.length - 1; j >= split; j--)
        {
            context.setIsEndEntity(j == 0);
            v.validate(context, certs[j]);
        }

        CertPathValidation copy = (CertPathValidation)v.copy();
        other.reset((Memoable)v);

        checkRest(label + " (original)", v, certs, split, expected);
        checkRest(label + " (copy)", copy, certs, split, expected);
        checkRest(label + " (reset)", other, certs, split, expected);
    }

    private void checkRest(String label, CertPathValidation v, X509CertificateHolder[] certs, int split, String expected)
    {
        CertPathValidationContext context = new CertPathValidationContext(new HashSet());

        try
        {
            for (int j = split - 1; j >= 0; j--)
            {
                context.setIsEndEntity(j == 0);
                v.validate(context, certs[j]);
            }

            if (expected != null)
            {
                fail(label + ": accepted, expected \"" + expected + "\"");
            }
        }
        catch (CertPathValidationException e)
        {
            if (expected == null)
            {
                fail(label + ": rejected with \"" + e.getMessage() + "\"");
            }
            isEquals(label, expected, e.getMessage());
        }
    }

    /**
     * validate() stops at the first rule that fails, rules taken in order; evaluate() runs every rule
     * over every certificate and reports each failure with its certificate and rule index.
     */
    private void validateAndEvaluateTest()
        throws Exception
    {
        // the CA lacks keyCertSign and the end entity is signed with another key
        X509CertificateHolder noCertSign = cert(ROOT_NAME, rootKp.getPrivate(), CA_NAME, caKp,
            new BasicConstraints(true), KeyUsage.digitalSignature);
        X509CertificateHolder wrongKey = cert(CA_NAME, otherKp.getPrivate(), EE_NAME, eeKp, null, 0);
        CertPath path = new CertPath(path(wrongKey, noCertSign));

        CertPathValidationResult result = path.validate(rules());
        checkFails("validate", result, 0, 0, "Certificate signature not for public key in parent");
        isTrue("validate result detailed", !result.isDetailed());

        result = path.evaluate(rules());
        isTrue("evaluate accepted", !result.isValid());
        isTrue("evaluate result not detailed", result.isDetailed());
        isEquals("evaluate failure count", 2, result.getCauses().length);
        isTrue("evaluate cert indexes", org.bouncycastle.util.Arrays.areEqual(new int[]{ 0, 1 }, result.getFailingCertIndexes()));
        isTrue("evaluate rule indexes", org.bouncycastle.util.Arrays.areEqual(new int[]{ 0, 2 }, result.getFailingRuleIndexes()));
        isEquals("Certificate signature not for public key in parent", result.getCauses()[0].getMessage());
        isEquals("Issuer certificate KeyUsage extension does not permit key signing", result.getCauses()[1].getMessage());
        // the first failure is also what the single-failure accessors report
        isEquals(0, result.getFailingCertIndex());
        isEquals(0, result.getFailingRuleIndex());
        isTrue("evaluate first cause", result.getCause() == result.getCauses()[0]);

        // a good path is valid both ways and reports no failure
        CertPath good = new CertPath(path(ee, ca));
        CertPathValidationResult[] results = new CertPathValidationResult[]{ good.validate(rules()), good.evaluate(rules()) };
        for (int i = 0; i != results.length; i++)
        {
            checkValid("good path " + i, results[i]);
            isTrue("good path " + i + " detailed", !results[i].isDetailed());
            isEquals(-1, results[i].getFailingCertIndex());
            isEquals(-1, results[i].getFailingRuleIndex());
            isTrue("good path " + i + " causes", results[i].getCauses() == null);
        }
    }

    /**
     * CertificatePoliciesValidation does not process certificate policies, so it must not report
     * the critical policy extensions RFC 5280 requires as handled: a path carrying one is left
     * invalid for an unhandled critical extension rather than accepted with the constraint ignored.
     */
    private void certificatePoliciesTest()
        throws Exception
    {
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]{ Extension.policyConstraints, Extension.inhibitAnyPolicy };
        ASN1Encodable[] values = new ASN1Encodable[]{
            new PolicyConstraints(BigIntegers.ZERO, null), new ASN1Integer(0) };

        for (int i = 0; i != oids.length; i++)
        {
            long now = System.currentTimeMillis();
            X509v3CertificateBuilder bldr = new X509v3CertificateBuilder(ROOT_NAME, BigInteger.valueOf(serial++),
                new Date(now - 60 * 60 * 1000L), new Date(now + 60 * 60 * 1000L), CA_NAME,
                SubjectPublicKeyInfo.getInstance(caKp.getPublic().getEncoded()));
            bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            bldr.addExtension(Extension.keyUsage, true, new KeyUsage(CA_USAGE));
            bldr.addExtension(oids[i], true, values[i]);
            X509CertificateHolder constrained = bldr.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(rootKp.getPrivate()));

            CertPath path = new CertPath(path(ee, constrained));
            CertPathValidationResult result = path.validate(new CertPathValidation[]{ new ParentCertIssuedValidation(verifier),
                new BasicConstraintsValidation(), new KeyUsageValidation(), new CertificatePoliciesValidationBuilder().build(path) });

            isTrue(oids[i] + " accepted", !result.isValid());
            isEquals(oids[i] + " unhandled", 1, result.getUnhandledCriticalExtensionOIDs().size());
            isTrue(oids[i] + " not reported", result.getUnhandledCriticalExtensionOIDs().contains(oids[i]));
        }
    }

    private CertPathValidation[] rules()
    {
        return new CertPathValidation[]{ new ParentCertIssuedValidation(verifier), new BasicConstraintsValidation(), new KeyUsageValidation() };
    }

    private void checkValid(String label, CertPathValidationResult result)
    {
        if (!result.isValid())
        {
            fail(label + ": rejected with \"" + (result.getCause() == null ? null : result.getCause().getMessage()) + "\"");
        }
        isTrue(label + ": cause on a valid path", result.getCause() == null);
    }

    private void checkFails(String label, CertPathValidationResult result, int certIndex, String message)
    {
        checkFails(label, result, certIndex, 0, message);
    }

    private void checkFails(String label, CertPathValidationResult result, int certIndex, int ruleIndex, String message)
    {
        isTrue(label + ": accepted", !result.isValid());
        isEquals(label + ": message", message, result.getCause().getMessage());
        isEquals(label + ": cert index", certIndex, result.getFailingCertIndex());
        isEquals(label + ": rule index", ruleIndex, result.getFailingRuleIndex());
    }

    private CRLValidation crlValidation(X509CRLHolder rootCrl, X509CRLHolder caCrl)
    {
        return new CRLValidation(ROOT_NAME, root.getSubjectPublicKeyInfo(), verifier, new CollectionStore(list(rootCrl, caCrl)));
    }

    private X509CertificateHolder[] path(X509CertificateHolder leaf, X509CertificateHolder issuer)
    {
        return new X509CertificateHolder[]{ leaf, issuer, root };
    }

    private static List list(Object a, Object b)
    {
        return list(a, b, null);
    }

    private static List list(Object a, Object b, Object c)
    {
        List l = new ArrayList();
        if (a != null)
        {
            l.add(a);
        }
        if (b != null)
        {
            l.add(b);
        }
        if (c != null)
        {
            l.add(c);
        }
        return l;
    }

    private X509CertificateHolder cert(X500Name issuer, PrivateKey issuerKey, X500Name subject, KeyPair subjectKp,
        BasicConstraints bc, int keyUsage)
        throws Exception
    {
        return cert(issuer, issuerKey, "SHA256withECDSA", subject,
            SubjectPublicKeyInfo.getInstance(subjectKp.getPublic().getEncoded()), bc, keyUsage);
    }

    private X509CertificateHolder cert(X500Name issuer, PrivateKey issuerKey, String sigAlg, X500Name subject,
        SubjectPublicKeyInfo subjectKey, BasicConstraints bc, int keyUsage)
        throws Exception
    {
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder bldr = new X509v3CertificateBuilder(issuer, BigInteger.valueOf(serial++),
            new Date(now - 60 * 60 * 1000L), new Date(now + 60 * 60 * 1000L), subject, subjectKey);

        // non-critical, so a case running only the rule under test is not failed for leaving the
        // other extension unhandled - CertPathValidationTest covers unhandled critical extensions
        if (bc != null)
        {
            bldr.addExtension(Extension.basicConstraints, false, bc);
        }
        if (keyUsage != 0)
        {
            bldr.addExtension(Extension.keyUsage, false, new KeyUsage(keyUsage));
        }

        return bldr.build(new JcaContentSignerBuilder(sigAlg).setProvider(BC).build(issuerKey));
    }

    private X509CRLHolder crl(X500Name issuer, PrivateKey issuerKey, BigInteger revoked)
        throws Exception
    {
        return crl(issuer, issuerKey, revoked, 0, Integers.valueOf(60));
    }

    // thisUpdate and nextUpdate in minutes from now, nextUpdate null for none
    private X509CRLHolder crl(X500Name issuer, PrivateKey issuerKey, BigInteger revoked, int thisUpdate, Integer nextUpdate)
        throws Exception
    {
        long now = System.currentTimeMillis();
        Date thisDate = new Date(now + thisUpdate * 60 * 1000L);
        X509v2CRLBuilder bldr = new X509v2CRLBuilder(issuer, thisDate);

        if (nextUpdate != null)
        {
            bldr.setNextUpdate(new Date(now + nextUpdate.intValue() * 60 * 1000L));
        }
        if (revoked != null)
        {
            bldr.addCRLEntry(revoked, thisDate, CRLReason.keyCompromise);
        }

        return bldr.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(issuerKey));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertPathValidationRulesTest());
    }
}
