package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.QcType;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;

/**
 * Regression test for github #1239: PKIXCertPathReviewer.processQcStatements only recognised
 * a handful of legacy ETSI TS 101 862 / RFC 3739 QC statements, so a qualified certificate
 * carrying the modern ETSI EN 319 412-5 statements (QcType, QcRetentionPeriod, QcPDS,
 * QcCClegislation) in a <i>critical</i> qcStatements extension was reported as having an
 * "unknown critical extension".
 */
public class QcStatementReviewerTest
    extends TestCase
{
    public void testModernQcStatementsAreRecognised()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);

        KeyPair rootKp = kpg.generateKeyPair();
        KeyPair eeKp = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60L * 60 * 1000);
        Date notAfter = new Date(now + 365L * 24 * 60 * 60 * 1000);

        X500Name rootDN = new X500Name("CN=QC Test Root");
        X500Name eeDN = new X500Name("CN=QC Test EE");

        // self-signed root CA
        X509v3CertificateBuilder rootBldr = new JcaX509v3CertificateBuilder(
            rootDN, BigInteger.valueOf(1), notBefore, notAfter, rootDN, rootKp.getPublic());
        rootBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        X509Certificate root = sign(rootBldr, rootKp.getPrivate());

        // EE cert with a CRITICAL qcStatements carrying QcCompliance + QcType (esign)
        ASN1Encodable[] statements = new ASN1Encodable[]
        {
            new QCStatement(QCStatement.id_etsi_qcs_QcCompliance),
            new QCStatement(QCStatement.id_etsi_qcs_QcType, new QcType(QCStatement.id_etsi_qct_esign))
        };

        X509v3CertificateBuilder eeBldr = new JcaX509v3CertificateBuilder(
            rootDN, BigInteger.valueOf(2), notBefore, notAfter, eeDN, eeKp.getPublic());
        eeBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        eeBldr.addExtension(Extension.qCStatements, true, new DERSequence(statements));
        X509Certificate ee = sign(eeBldr, rootKp.getPrivate());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        List certs = new ArrayList();
        certs.add(ee);
        CertPath cp = cf.generateCertPath(certs);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));

        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.setDate(new Date(now));

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();
        reviewer.init(cp, param);

        // The qcStatements extension must no longer be reported as an unknown critical extension.
        assertFalse("qcStatements wrongly reported as an unknown critical extension",
            anyFindingContains(reviewer.getErrors(), Extension.qCStatements.getId()));

        // The QcType statement should be recognised and surfaced as a notification.
        assertTrue("QcType statement was not recognised",
            anyFindingContains(reviewer.getNotifications(), "electronic signature"));
    }

    private static X509Certificate sign(X509v3CertificateBuilder builder, PrivateKey signingKey)
        throws Exception
    {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signingKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static boolean anyFindingContains(List[] findingsByIndex, String needle)
    {
        for (int i = 0; i != findingsByIndex.length; i++)
        {
            List findings = findingsByIndex[i];
            if (findings == null)
            {
                continue;
            }
            for (int j = 0; j != findings.size(); j++)
            {
                ErrorBundle msg = (ErrorBundle)findings.get(j);
                try
                {
                    if (msg.getText(Locale.ENGLISH).contains(needle)
                        || msg.getDetail(Locale.ENGLISH).contains(needle))
                    {
                        return true;
                    }
                }
                catch (Exception e)
                {
                    // ignore findings without the queried entry
                }
            }
        }
        return false;
    }
}
