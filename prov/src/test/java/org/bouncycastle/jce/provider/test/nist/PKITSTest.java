package org.bouncycastle.jce.provider.test.nist;

import java.io.InputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jcajce.PKIXExtendedParameters;

/**
 * Utility class to support PKITS testing of the Cert Path library and associated functions.
 */

class PKITSTest
{
    private Set trustAnchors = new HashSet();
    private ArrayList certs = new ArrayList();
    private ArrayList crls = new ArrayList();
    private Set policies = new HashSet();

    //
    // Global to save reloading.
    //
    private static final Map certBuffer = new HashMap();
    private static final Map crlBuffer = new HashMap();

    private CertPath certPath;
    private CertStore certStore;
    private PKIXCertPathValidatorResult validatorResult;
    private X509Certificate endCert;
    private Boolean explicitPolicyRequired;
    private Boolean inhibitAnyPolicy;
    private Boolean policyMappingInhibited;
    private boolean deltaCRLsEnabled;


    private HashMap certsByName = new HashMap();
    private HashMap crlsByName = new HashMap();


    private static final HashMap<String, ASN1ObjectIdentifier> policiesByName = new HashMap<String, ASN1ObjectIdentifier>();

    static
    {
        policiesByName.put("anyPolicy", new ASN1ObjectIdentifier("2.5.29.32.0"));
        policiesByName.put("NIST-test-policy-1", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.1"));
        policiesByName.put("NIST-test-policy-2", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.2"));
        policiesByName.put("NIST-test-policy-3", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.3"));
        policiesByName.put("NIST-test-policy-4", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.4"));
        policiesByName.put("NIST-test-policy-5", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.5"));
        policiesByName.put("NIST-test-policy-6", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.6"));
        policiesByName.put("NIST-test-policy-7", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.7"));
        policiesByName.put("NIST-test-policy-8", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.8"));
        policiesByName.put("NIST-test-policy-9", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.9"));
        policiesByName.put("NIST-test-policy-10", new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.48.10"));
    }


    public static ASN1ObjectIdentifier[] resolvePolicyOid(String... nistNames)
    {
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[nistNames.length];

        int c = 0;
        for (String name : nistNames)
        {
            ASN1ObjectIdentifier oid = policiesByName.get(name);

            if (oid == null)
            {
                oid = new ASN1ObjectIdentifier(name);
            }
            oids[c++] = oid;
        }

        return oids;
    }


    public PKITSTest()
        throws Exception
    {
        trustAnchors.add(getTrustAnchor("TrustAnchorRootCertificate"));
        withCrls("TrustAnchorRootCRL");
    }

    PKITSTest enableDeltaCRLs(boolean enabled)
    {
        this.deltaCRLsEnabled = enabled;

        return this;
    }

    PKITSTest withCrls(String... crls)
        throws Exception
    {
        for (String name : crls)
        {
            name = name.replace(" ", "").replace("-", "");
            this.crls.add(loadCrl(name));
        }
        return this;
    }

    PKITSTest withCACert(String... certs)
    {
        for (String name : certs)
        {
            name = name.replace(" ", "").replace("-", "");
            this.certs.add(loadCert(name));
        }
        return this;
    }


    public PKITSTest withPolicyByName(String... policies)
    {
        withPolicyByOids(resolvePolicyOid(policies));
        return this;
    }


    public PKITSTest withExplicitPolicyRequired(boolean required)
    {
        this.explicitPolicyRequired = required;
        return this;
    }

    public PKITSTest withPolicyByOids(ASN1ObjectIdentifier... policies)
    {

        for (ASN1ObjectIdentifier policy : policies)
        {
            this.policies.add(policy.toString());
        }

        return this;
    }


    PKIXCertPathValidatorResult doTest()
        throws Exception
    {
        List certsAndCrls = new ArrayList();

        certsAndCrls.add(endCert);
        certsAndCrls.addAll(certs);

        certPath = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certsAndCrls);

        certsAndCrls.addAll(crls);

        certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCrls), "BC");

        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters params = new PKIXParameters(trustAnchors);

        params.addCertStore(certStore);
        params.setRevocationEnabled(true);
        params.setDate(new GregorianCalendar(2010, 1, 1).getTime());

        if (explicitPolicyRequired != null)
        {
            params.setExplicitPolicyRequired(explicitPolicyRequired);
        }

        if (inhibitAnyPolicy != null)
        {
            params.setAnyPolicyInhibited(inhibitAnyPolicy);
        }

        if (policyMappingInhibited != null)
        {
            params.setPolicyMappingInhibited(policyMappingInhibited);
        }

        if (!policies.isEmpty())
        {
            params.setExplicitPolicyRequired(true);
            params.setInitialPolicies(policies);
        }

        PKIXExtendedParameters.Builder extParams = new PKIXExtendedParameters.Builder(params);

        extParams.setUseDeltasEnabled(deltaCRLsEnabled);

        validatorResult = (PKIXCertPathValidatorResult)validator.validate(certPath, extParams.build());

        return validatorResult;
    }

    void doExceptionTest(
        int index,
        String message)
        throws Exception
    {
        try
        {
            doTest();

            throw new RuntimeException("path accepted when should be rejected");
        }
        catch (CertPathValidatorException e)
        {
            if (index != e.getIndex())
            {
                throw new RuntimeException("Index did not match: " + index + " got " + e.getIndex());
            }

            if (!message.equals(e.getMessage()))
            {
                throw new RuntimeException("Message did not match: '" + message + "', got '" + e.getMessage() + "'");
            }
        }
    }

    X509Certificate pathCert(int index)
    {
        List<? extends Certificate> certificates = certPath.getCertificates();
        if (index >= certificates.size())
        {
            throw new IllegalArgumentException("Index " + index + "  exceeds available certificates in path, " + certificates.size());
        }

        return (X509Certificate)certificates.get(index);
    }

    TBSCertificate pathTBSCert(int index)
        throws Exception
    {
        List<? extends Certificate> certificates = certPath.getCertificates();
        if (index >= certificates.size())
        {
            throw new IllegalArgumentException("Index " + index + "  exceeds available certificates in path, " + certificates.size());
        }

        X509Certificate cert = (X509Certificate)certificates.get(index);


        return TBSCertificate.getInstance(cert.getTBSCertificate());
    }

    /**
     * Test a certificate in the path has the folling usage
     *
     * @param certIndex The certificate index.
     * @param usage     An integer build from KeyUsage class constants, eg  KeyUsage.cRLSign | KeyUsage.keyCertSign
     * @return true if all are found.
     * @throws Exception
     */
    public boolean certHasKeyUsage(int certIndex, int usage)
        throws Exception
    {
        KeyUsage ku = KeyUsage.fromExtensions(pathTBSCert(certIndex).getExtensions());

        return ku.hasUsages(usage);
    }

    public BasicConstraints certBasicConstraints(int certIndex)
        throws Exception
    {
        return BasicConstraints.fromExtensions(pathTBSCert(certIndex).getExtensions());
    }


    public Set getTrustAnchors()
    {
        return trustAnchors;
    }

    public ArrayList getCerts()
    {
        return certs;
    }

    public ArrayList getCrls()
    {
        return crls;
    }

    public Set getPolicies()
    {
        return policies;
    }

    public static Map getCertBuffer()
    {
        return certBuffer;
    }

    public static Map getCrlBuffer()
    {
        return crlBuffer;
    }

    public CertPath getCertPath()
    {
        return certPath;
    }

    public CertStore getCertStore()
    {
        return certStore;
    }

    public PKIXCertPathValidatorResult getValidatorResult()
    {
        return validatorResult;
    }

    public X509Certificate getEndCert()
    {
        return endCert;
    }

    private X509Certificate loadCert(
        final String certName)
    {
        X509Certificate cert;
        synchronized (certBuffer)
        {
            cert = (X509Certificate)certBuffer.get(certName);
        }

        if (cert != null)
        {
            certsByName.put(certName, cert);
            return cert;
        }

        try
        {
            String path = getPkitsHome() + "/certs/" + certName + ".crt";
            InputStream in = this.getClass().getResourceAsStream(path);

            if (in == null)
            {
                throw new RuntimeException("Could not find: " + path);
            }


            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(in);

            synchronized (certBuffer)
            {
                certsByName.put(certName, cert);
                certBuffer.put(certName, cert);
            }
            return cert;
        }
        catch (Exception e)
        {
            throw new IllegalStateException("exception loading certificate " + certName + ": " + e);
        }
    }

    private X509CRL loadCrl(
        String crlName)
        throws Exception
    {
        X509CRL crl;
        synchronized (crlBuffer)
        {
            crl = (X509CRL)crlBuffer.get(crlName);
        }
        if (crl != null)
        {
            crlsByName.put(crlName, crl);
            return crl;
        }

        try
        {
            InputStream in = this.getClass().getResourceAsStream(getPkitsHome() + "/crls/" + crlName + ".crl");

            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

            crl = (X509CRL)fact.generateCRL(in);

            synchronized (crlBuffer)
            {
                crlsByName.put(crlName, crl);
                crlBuffer.put(crlName, crl);
            }


            return crl;
        }
        catch (Exception e)
        {
            throw new IllegalStateException("exception loading CRL: " + crlName);
        }
    }

    private TrustAnchor getTrustAnchor(String trustAnchorName)
        throws Exception
    {
        X509Certificate cert = loadCert(trustAnchorName);
        byte[] extBytes = cert.getExtensionValue(Extension.nameConstraints.getId());

        if (extBytes != null)
        {
            ASN1Encodable extValue = ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extBytes).getOctets());

            return new TrustAnchor(cert, extValue.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        }

        return new TrustAnchor(cert, null);
    }


    private String getPkitsHome()
    {
        return "/PKITS";
    }

    public PKITSTest withEndEntity(String endCert)
    {
        endCert = endCert.replace(" ", "").replace("-", "");
        this.endCert = loadCert(endCert);
        return this;
    }

    public boolean endCertMatchesPathCert(int certIndex)
    {
        return endCert.equals(this.pathCert(certIndex));
    }

    public PKITSTest withInhibitAnyPolicy(boolean inhibitAnyPolicy)
    {
        this.inhibitAnyPolicy = inhibitAnyPolicy;
        return this;
    }

    public PKITSTest withPolicyMappingInhibited(boolean policyMappingInhibited)
    {
        this.policyMappingInhibited = policyMappingInhibited;
        return this;
    }

}
