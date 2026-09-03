package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.ExtendedPKIXParameters;

/**
 * Tests that the BC "PKIX" {@link CertPathValidator} honours the validation date under both
 * {@link PKIXExtendedParameters#PKIX_VALIDITY_MODEL} (the shell model) and
 * {@link PKIXExtendedParameters#CHAIN_VALIDITY_MODEL}.
 * <p>
 * In the shell model every certificate in the path is checked against the validation date. In the chain
 * model only the end-entity certificate is checked against the validation date; each CA certificate is
 * checked at the time its subordinate certificate was issued, taken from the subordinate's notBefore or,
 * for the end-entity certificate, from its ISIS-MTT dateOfCertGen extension when present.
 * <p>
 * Every scenario is run through both ways the provider accepts a validity model: the current
 * {@link PKIXExtendedParameters}, and the deprecated {@link ExtendedPKIXParameters} (a
 * {@link PKIXParameters} subclass the validator SPI still translates). A plain {@link PKIXParameters}
 * is also checked to behave as the shell model.
 */
public class ValidityModelTest
    extends SimpleTest
{
    private static final int PKIX_MODEL = PKIXExtendedParameters.PKIX_VALIDITY_MODEL;
    private static final int CHAIN_MODEL = PKIXExtendedParameters.CHAIN_VALIDITY_MODEL;

    private static final Date D2019 = utc(2019, 1, 1);
    private static final Date D2020 = utc(2020, 1, 1);
    private static final Date D2021_03 = utc(2021, 3, 1);
    private static final Date D2021_05 = utc(2021, 5, 1);
    private static final Date D2021_06 = utc(2021, 6, 1);
    private static final Date D2021_07 = utc(2021, 7, 1);
    private static final Date D2030 = utc(2030, 1, 1);
    private static final Date D2040 = utc(2040, 1, 1);

    private KeyPair rootKp;
    private KeyPair interKp;
    private KeyPair eeKp;

    private boolean useLegacyParameters;

    public String getName()
    {
        return "ValidityModel";
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(2048);

        rootKp = kpGen.generateKeyPair();
        interKp = kpGen.generateKeyPair();
        eeKp = kpGen.generateKeyPair();

        for (int i = 0; i < 2; ++i)
        {
            useLegacyParameters = (i != 0);

            shellModelChecksEndEntityAgainstDate();
            chainModelChecksIssuerAtSubordinateNotBefore();
            chainModelUsesDateOfCertGenWhenPresent();
        }

        plainPKIXParametersUseShellModel();
    }

    private void shellModelChecksEndEntityAgainstDate()
        throws Exception
    {
        X509Certificate root = makeCert("CN=Root", rootKp.getPublic(), "CN=Root", rootKp.getPrivate(), D2020, D2040, true, null);
        X509Certificate inter = makeCert("CN=Inter", interKp.getPublic(), "CN=Root", rootKp.getPrivate(), D2020, D2040, true, null);
        // EE valid only during 2021-03 .. 2021-06
        X509Certificate ee = makeCert("CN=EE", eeKp.getPublic(), "CN=Inter", interKp.getPrivate(), D2021_03, D2021_06, false, null);

        // Inside the EE window
        validate(root, inter, ee, D2021_05, PKIX_MODEL);

        // After the EE window
        expectFailure(CertificateExpiredException.class, root, inter, ee, D2021_07, PKIX_MODEL);

        // Before the EE window
        expectFailure(CertificateNotYetValidException.class, root, inter, ee, D2020, PKIX_MODEL);

        // No date set => current time (after 2021-06) => expired
        expectFailure(CertificateExpiredException.class, root, inter, ee, null, PKIX_MODEL);
    }

    private void chainModelChecksIssuerAtSubordinateNotBefore()
        throws Exception
    {
        X509Certificate root = makeCert("CN=Root", rootKp.getPublic(), "CN=Root", rootKp.getPrivate(), D2020, D2040, true, null);
        // Intermediate expires 2021-06
        X509Certificate inter = makeCert("CN=Inter", interKp.getPublic(), "CN=Root", rootKp.getPrivate(), D2020, D2021_06, true, null);
        // EE issued 2021-03 (while inter still valid), valid until 2030
        X509Certificate ee = makeCert("CN=EE", eeKp.getPublic(), "CN=Inter", interKp.getPrivate(), D2021_03, D2030, false, null);

        // Shell model at 2021-07: intermediate has expired
        expectFailure(CertificateExpiredException.class, root, inter, ee, D2021_07, PKIX_MODEL);

        // Chain model at 2021-07: EE checked at the date, intermediate checked at EE.notBefore
        validate(root, inter, ee, D2021_07, CHAIN_MODEL);

        // Chain model with the date after EE expiry: the EE itself is still checked against the date
        expectFailure(CertificateExpiredException.class, root, inter, ee, D2040, CHAIN_MODEL);
    }

    private void chainModelUsesDateOfCertGenWhenPresent()
        throws Exception
    {
        X509Certificate root = makeCert("CN=Root", rootKp.getPublic(), "CN=Root", rootKp.getPrivate(), D2019, D2040, true, null);
        // Intermediate valid from 2020
        X509Certificate inter = makeCert("CN=Inter", interKp.getPublic(), "CN=Root", rootKp.getPrivate(), D2020, D2040, true, null);

        // EE notBefore (2019) predates inter.notBefore; without dateOfCertGen the intermediate is not yet valid
        X509Certificate eeNoExt = makeCert("CN=EE", eeKp.getPublic(), "CN=Inter", interKp.getPrivate(), D2019, D2030, false, null);
        expectFailure(CertificateNotYetValidException.class, root, inter, eeNoExt, D2021_07, CHAIN_MODEL);

        // Same EE with dateOfCertGen = 2021-05: the intermediate is checked at 2021-05 instead
        X509Certificate eeExt = makeCert("CN=EE", eeKp.getPublic(), "CN=Inter", interKp.getPrivate(), D2019, D2030, false, D2021_05);
        validate(root, inter, eeExt, D2021_07, CHAIN_MODEL);
    }

    private void plainPKIXParametersUseShellModel()
        throws Exception
    {
        X509Certificate root = makeCert("CN=Root", rootKp.getPublic(), "CN=Root", rootKp.getPrivate(), D2020, D2040, true, null);
        // Intermediate expires 2021-06
        X509Certificate inter = makeCert("CN=Inter", interKp.getPublic(), "CN=Root", rootKp.getPrivate(), D2020, D2021_06, true, null);
        // EE issued 2021-03 (while inter still valid), valid until 2030
        X509Certificate ee = makeCert("CN=EE", eeKp.getPublic(), "CN=Inter", interKp.getPrivate(), D2021_03, D2030, false, null);

        PKIXParameters params = new PKIXParameters(trustAnchors(root));
        params.setRevocationEnabled(false);

        // Inside the intermediate's window
        params.setDate(D2021_05);
        validate(certPath(inter, ee), params);

        // After the intermediate's window: with no validity model requested, the shell model applies
        params.setDate(D2021_07);
        expectFailure(CertificateExpiredException.class, certPath(inter, ee), params);
    }

    private static Date utc(int year, int month, int day)
    {
        Calendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.clear();
        cal.set(year, month - 1, day);
        return cal.getTime();
    }

    private static X509Certificate makeCert(String subject, PublicKey subjectKey, String issuer, PrivateKey issuerKey,
        Date notBefore, Date notAfter, boolean isCA, Date dateOfCertGen)
        throws Exception
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));
        if (dateOfCertGen != null)
        {
            extGen.addExtension(ISISMTTObjectIdentifiers.id_isismtt_at_dateOfCertGen, false,
                new ASN1GeneralizedTime(dateOfCertGen));
        }

        return TestCertificateGen.createCert(new X500Name(issuer), issuerKey, new X500Name(subject), "SHA256withRSA",
            notBefore, notAfter, extGen.generate(), subjectKey);
    }

    private static Set trustAnchors(X509Certificate root)
    {
        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));
        return trust;
    }

    private static CertPath certPath(X509Certificate inter, X509Certificate ee)
        throws Exception
    {
        List certs = new ArrayList();
        certs.add(ee);
        certs.add(inter);
        return CertificateFactory.getInstance("X.509", "BC").generateCertPath(certs);
    }

    private CertPathParameters parameters(X509Certificate root, Date date, int validityModel)
        throws Exception
    {
        if (useLegacyParameters)
        {
            ExtendedPKIXParameters params = new ExtendedPKIXParameters(trustAnchors(root));
            params.setDate(date);
            params.setRevocationEnabled(false);
            params.setValidityModel(validityModel);
            return params;
        }

        PKIXParameters baseParams = new PKIXParameters(trustAnchors(root));
        baseParams.setDate(date);
        baseParams.setRevocationEnabled(false);
        return new PKIXExtendedParameters.Builder(baseParams).setValidityModel(validityModel).build();
    }

    private static void validate(CertPath certPath, CertPathParameters params)
        throws Exception
    {
        CertPathValidator.getInstance("PKIX", "BC").validate(certPath, params);
    }

    private void validate(X509Certificate root, X509Certificate inter, X509Certificate ee, Date date, int validityModel)
        throws Exception
    {
        validate(certPath(inter, ee), parameters(root, date, validityModel));
    }

    private void expectFailure(Class causeClass, CertPath certPath, CertPathParameters params)
        throws Exception
    {
        try
        {
            validate(certPath, params);
        }
        catch (CertPathValidatorException e)
        {
            for (Throwable cause = e; cause != null; cause = cause.getCause())
            {
                if (causeClass.isInstance(cause))
                {
                    return;
                }
            }
            fail("unexpected failure: " + e);
        }
        fail("expected failure with cause " + causeClass.getName());
    }

    private void expectFailure(Class causeClass, X509Certificate root, X509Certificate inter, X509Certificate ee,
        Date date, int validityModel)
        throws Exception
    {
        expectFailure(causeClass, certPath(inter, ee), parameters(root, date, validityModel));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ValidityModelTest());
    }
}
