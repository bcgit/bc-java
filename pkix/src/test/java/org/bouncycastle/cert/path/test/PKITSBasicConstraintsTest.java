package org.bouncycastle.cert.path.test;

import java.io.IOException;
import java.security.Security;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.path.CertPath;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationResult;
import org.bouncycastle.cert.path.validations.BasicConstraintsValidation;
import org.bouncycastle.cert.path.validations.KeyUsageValidation;
import org.bouncycastle.cert.path.validations.ParentCertIssuedValidation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.test.SimpleTest;

public class PKITSBasicConstraintsTest
    extends SimpleTest
{
    public static final String PKITS_DATA_RESOURCE_PREFIX = "/PKITS/certs/";

    public String getName()
    {
        return "PKITSBasicConstraintsTest";
    }

    private static X509CertificateHolder readPKITSCert(String fileName)
        throws IOException
    {
        ASN1InputStream asn1In = new ASN1InputStream(TestResourceFinder.findTestResource(PKITS_DATA_RESOURCE_PREFIX, fileName));
        return new X509CertificateHolder(Certificate.getInstance(asn1In.readObject()));
    }

    private static CertPath readPKITSPath(String eeCertFile, String[] intermCertFiles)
        throws IOException
    {
        X509CertificateHolder[] certsInPath = new X509CertificateHolder[intermCertFiles.length + 2];
        certsInPath[certsInPath.length - 1] = readPKITSCert("TrustAnchorRootCertificate.crt");
        certsInPath[0] = readPKITSCert(eeCertFile);
        // order specified in PKITS is reversed from the one the validation API expects
        for (int i = 0; i < intermCertFiles.length; i++)
        {
            certsInPath[certsInPath.length - 2 - i] = readPKITSCert(intermCertFiles[i]);
        }
        return new CertPath(certsInPath);
    }

    // we don't run CRL checks here, since we only want to test the basic constraint validation
    private static CertPathValidationResult checkPKITSPath(String eeCertFile, String[] intermCertFiles)
        throws IOException
    {
        CertPath path = readPKITSPath(eeCertFile, intermCertFiles);

        X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder();
        CertPathValidation[] validators = new CertPathValidation[]
            {new BasicConstraintsValidation(), new KeyUsageValidation(), new ParentCertIssuedValidation(verifier)};
        return path.validate(validators);
    }

    private void expectBCValidationSuccess(String eeCertFile, String[] intermCertFiles)
        throws IOException
    {
        CertPathValidationResult cpvr = checkPKITSPath(eeCertFile, intermCertFiles);
        isTrue("Valid path was rejected", cpvr.isValid());
    }

    private void expectBCValidationFailure(String eeCertFile, String[] intermCertFiles, String expectedMessage)
        throws IOException
    {
        CertPathValidationResult cpvr = checkPKITSPath(eeCertFile, intermCertFiles);
        isTrue("Invalid path was accepted", !cpvr.isValid());
        String reasonMessage = cpvr.getCause().getMessage();
        isEquals("Rejection reasons do not match: expected " + expectedMessage + ", got " + reasonMessage,
            expectedMessage, reasonMessage);

    }
    
    public void performTest()
        throws Exception
    {
        // PKITS 4.6.1
        expectBCValidationFailure(
            "InvalidMissingbasicConstraintsTest1EE.crt",
            new String[]{"MissingbasicConstraintsCACert.crt"},
            "Basic constraints violated: issuer is not a CA");

        // this test should pass with isMandatory=false
        CertPath invalidPath = readPKITSPath(
            "InvalidMissingbasicConstraintsTest1EE.crt",
            new String[]{"MissingbasicConstraintsCACert.crt"});

        CertPathValidation[] lenientValidators = new CertPathValidation[]
            {new BasicConstraintsValidation(false), new KeyUsageValidation(),
                new ParentCertIssuedValidation(new JcaX509ContentVerifierProviderBuilder())};
        isTrue(invalidPath.validate(lenientValidators).isValid());

        // PKITS 4.6.2
        expectBCValidationFailure(
            "InvalidcAFalseTest2EE.crt",
            new String[]{"basicConstraintsCriticalcAFalseCACert.crt"},
            "Basic constraints violated: issuer is not a CA");

        // PKITS 4.6.3
        expectBCValidationFailure(
            "InvalidcAFalseTest3EE.crt",
            new String[]{"basicConstraintsNotCriticalcAFalseCACert.crt"},
            "Basic constraints violated: issuer is not a CA");

        // PKITS 4.6.4
        expectBCValidationSuccess(
            "ValidbasicConstraintsNotCriticalTest4EE.crt",
            new String[]{"basicConstraintsNotCriticalCACert.crt"});

        // PKITS 4.6.5
        expectBCValidationFailure("InvalidpathLenConstraintTest5EE.crt",
            new String[]{"pathLenConstraint0CACert.crt", "pathLenConstraint0subCACert.crt"},
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.6
        expectBCValidationFailure("InvalidpathLenConstraintTest6EE.crt",
            new String[]{"pathLenConstraint0CACert.crt", "pathLenConstraint0subCACert.crt"},
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.7
        expectBCValidationSuccess(
            "ValidpathLenConstraintTest7EE.crt",
            new String[]{"pathLenConstraint0CACert.crt"});

        // PKITS 4.6.8
        expectBCValidationSuccess(
            "ValidpathLenConstraintTest8EE.crt",
            new String[]{"pathLenConstraint0CACert.crt"});

        // PKITS 4.6.9
        expectBCValidationFailure("InvalidpathLenConstraintTest9EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA0Cert.crt",
                "pathLenConstraint6subsubCA00Cert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.10
        expectBCValidationFailure("InvalidpathLenConstraintTest10EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA0Cert.crt",
                "pathLenConstraint6subsubCA00Cert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.11
        expectBCValidationFailure("InvalidpathLenConstraintTest11EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA1Cert.crt",
                "pathLenConstraint6subsubCA11Cert.crt",
                "pathLenConstraint6subsubsubCA11XCert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.12
        expectBCValidationFailure("InvalidpathLenConstraintTest12EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA1Cert.crt",
                "pathLenConstraint6subsubCA11Cert.crt",
                "pathLenConstraint6subsubsubCA11XCert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.13
        expectBCValidationSuccess("ValidpathLenConstraintTest13EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA4Cert.crt",
                "pathLenConstraint6subsubCA41Cert.crt",
                "pathLenConstraint6subsubsubCA41XCert.crt",
            });

        // PKITS 4.6.14
        expectBCValidationSuccess("ValidpathLenConstraintTest14EE.crt",
            new String[]{
                "pathLenConstraint6CACert.crt",
                "pathLenConstraint6subCA4Cert.crt",
                "pathLenConstraint6subsubCA41Cert.crt",
                "pathLenConstraint6subsubsubCA41XCert.crt",
            });

        // PKITS 4.6.15
        expectBCValidationSuccess("ValidSelfIssuedpathLenConstraintTest15EE.crt",
            new String[]{
                "pathLenConstraint0CACert.crt",
                "pathLenConstraint0SelfIssuedCACert.crt",
            });

        // PKITS 4.6.16
        expectBCValidationFailure("InvalidSelfIssuedpathLenConstraintTest16EE.crt",
            new String[]{
                "pathLenConstraint0CACert.crt",
                "pathLenConstraint0SelfIssuedCACert.crt",
                "pathLenConstraint0subCA2Cert.crt",
            },
            "Basic constraints violated: path length exceeded");

        // PKITS 4.6.17
        expectBCValidationSuccess("ValidSelfIssuedpathLenConstraintTest17EE.crt",
            new String[]{
                "pathLenConstraint1CACert.crt",
                "pathLenConstraint1SelfIssuedCACert.crt",
                "pathLenConstraint1subCACert.crt",
                "pathLenConstraint1SelfIssuedsubCACert.crt",
            });
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PKITSBasicConstraintsTest());
    }
}
