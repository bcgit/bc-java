package org.bouncycastle.asn1.examples;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.Streams;

/**
 * Decode-only example for the qualified-certificate QCStatements extension
 * (github #1416). Reads an X.509 certificate (DER or PEM) and prints any
 * RFC 3739 syntax statements it carries — both
 * {@code id-qcs-pkixQCSyntax-v1} ({@code 1.3.6.1.5.5.7.11.1}, RFC 3039) and
 * {@code id-qcs-pkixQCSyntax-v2} ({@code 1.3.6.1.5.5.7.11.2}, RFC 3739).
 *
 * <p>RFC 3739 sec. 3.2.6 defines the {@code qCStatements} extension
 * ({@code 1.3.6.1.5.5.7.1.3}) as a {@code SEQUENCE OF QCStatement}, where
 * each {@code QCStatement} is {@code { statementId, statementInfo OPTIONAL }}.
 * For {@code id-qcs-pkixQCSyntax-v2} (sec. 3.2.6.1) the {@code statementInfo}
 * is a {@link SemanticsInformation} carrying an optional semantics-identifier
 * OID and an optional list of {@code nameRegistrationAuthorities} general
 * names. For v1 there is no {@code statementInfo}.</p>
 *
 * <p>Statements with any other {@code statementId} (e.g. the ETSI EN 319 412-5
 * statements such as {@code id-etsi-qcs-QcCompliance}) are printed as a raw
 * ASN.1 dump of their {@code statementInfo}, so this example also serves as a
 * starting point for inspecting unfamiliar qualified-certificate profiles.</p>
 *
 * <pre>
 *     java org.bouncycastle.asn1.examples.QCSyntaxExample &lt;cert.pem|cert.der&gt;
 * </pre>
 */
public class QCSyntaxExample
{
    public static void main(String[] args)
        throws Exception
    {
        if (args.length != 1)
        {
            // -DM System.err.println
            System.err.println("Usage: QCSyntaxExample <cert-file>");
            // -DM System.exit
            System.exit(1);
        }

        X509CertificateHolder certificate = readCertificate(args[0]);

        Extension qcExt = certificate.getExtension(Extension.qCStatements);
        if (qcExt == null)
        {
            // -DM System.out.println
            System.out.println("Certificate carries no qCStatements extension ("
                + Extension.qCStatements + ").");
            return;
        }

        ASN1Sequence statements = ASN1Sequence.getInstance(qcExt.getParsedValue());
        // -DM System.out.println
        System.out.println("qCStatements (critical=" + qcExt.isCritical()
            + ", count=" + statements.size() + "):");

        for (int i = 0; i != statements.size(); i++)
        {
            QCStatement qcs = QCStatement.getInstance(statements.getObjectAt(i));
            printStatement(i, qcs);
        }
    }

    private static void printStatement(int index, QCStatement qcs)
    {
        ASN1ObjectIdentifier id = qcs.getStatementId();
        ASN1Encodable info = qcs.getStatementInfo();

        // -DM System.out.println
        System.out.println("  [" + index + "] statementId = " + id);

        if (RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1.equals(id))
        {
            // -DM System.out.println
            System.out.println("        (RFC 3039 / RFC 3739 v1 — no statementInfo expected"
                + (info != null ? "; unexpected info present" : "") + ")");
        }
        else if (RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2.equals(id))
        {
            if (info == null)
            {
                // -DM System.out.println
                System.out.println("        (RFC 3739 v2 — statementInfo absent)");
                return;
            }

            SemanticsInformation si = SemanticsInformation.getInstance(info);
            ASN1ObjectIdentifier semId = si.getSemanticsIdentifier();
            GeneralName[] nras = si.getNameRegistrationAuthorities();

            if (semId != null)
            {
                // -DM System.out.println
                System.out.println("        semanticsIdentifier = " + semId);
            }
            if (nras != null)
            {
                for (int j = 0; j != nras.length; j++)
                {
                    // -DM System.out.println
                    System.out.println("        nameRegistrationAuthority[" + j + "] = " + nras[j]);
                }
            }
            if (semId == null && nras == null)
            {
                // -DM System.out.println
                System.out.println("        (SemanticsInformation is empty)");
            }
        }
        else if (info != null)
        {
            // -DM System.out.println
            System.out.println("        statementInfo =");
            // -DM System.out.println
            System.out.println(ASN1Dump.dumpAsString(info, true));
        }
    }

    private static X509CertificateHolder readCertificate(String path)
        throws IOException
    {
        FileInputStream fis = new FileInputStream(path);
        try
        {
            byte[] bytes = Streams.readAll(fis);

            // Best-effort PEM detection.
            if (bytes.length > 0 && (bytes[0] == '-' || bytes[0] == '\n' || bytes[0] == '\r'))
            {
                Reader reader = new InputStreamReader(new ByteArrayInputStream(bytes), "US-ASCII");
                PEMParser parser = new PEMParser(reader);
                try
                {
                    Object obj = parser.readObject();
                    if (!(obj instanceof X509CertificateHolder))
                    {
                        throw new IOException("expected a CERTIFICATE PEM in " + path
                            + ", got " + (obj == null ? "null" : obj.getClass().getName()));
                    }
                    return (X509CertificateHolder)obj;
                }
                finally
                {
                    parser.close();
                }
            }

            return new X509CertificateHolder(bytes);
        }
        finally
        {
            fis.close();
        }
    }
}
