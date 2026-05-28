package org.bouncycastle.cert.examples;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ct.SctExtension;
import org.bouncycastle.cert.ct.SignedCertificateTimestamp;
import org.bouncycastle.cert.ct.SignedCertificateTimestampDataV2;
import org.bouncycastle.cert.ct.SignedCertificateTimestampList;
import org.bouncycastle.cert.ct.TransItem;
import org.bouncycastle.cert.ct.TransItemList;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * Decode-only example for Certificate Transparency (github #228). Reads an
 * X.509 certificate (DER or PEM) and prints the contents of any embedded SCT
 * extensions it carries — both the RFC 6962 (CT v1) form
 * ({@code 1.3.6.1.4.1.11129.2.4.2}) and the RFC 9162 (CT v2)
 * {@code TransItemList} form ({@code 1.3.101.75}).
 *
 * <p>This is the first half of "is this certificate in a CT log?": fetching
 * an inclusion proof from the named log and verifying it against the log's
 * STH is a separate (network-using) step intentionally not implemented
 * here. The log ID printed below identifies which log the SCT came from —
 * for v1, SHA-256 of the log's DER-encoded public key; for v2, the
 * log-chosen variable-length identifier.</p>
 *
 * <pre>
 *     java org.bouncycastle.cert.examples.CTSCTListExample &lt;cert.pem|cert.der&gt;
 * </pre>
 */
public class CTSCTListExample
{
    public static void main(String[] args)
        throws Exception
    {
        if (args.length != 1)
        {
            System.err.println("Usage: CTSCTListExample <cert-file>");
            System.exit(1);
        }

        X509CertificateHolder certificate = readCertificate(args[0]);
        Extensions extensions = certificate.getExtensions();
        if (extensions == null)
        {
            System.out.println("Certificate carries no extensions.");
            return;
        }

        boolean printed = false;

        SignedCertificateTimestampList v1 = SignedCertificateTimestampList.fromExtensions(extensions);
        if (v1 != null)
        {
            printV1(v1);
            printed = true;
        }

        TransItemList v2 = TransItemList.fromExtensions(extensions);
        if (v2 != null)
        {
            printV2(v2);
            printed = true;
        }

        if (!printed)
        {
            System.out.println("No embedded SCT extension found "
                + "(checked 1.3.6.1.4.1.11129.2.4.2 and 1.3.101.75).");
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

    private static void printV1(SignedCertificateTimestampList list)
    {
        System.out.println("RFC 6962 SignedCertificateTimestampList ("
            + list.size() + " SCT" + (list.size() == 1 ? "" : "s") + "):");

        List items = list.getSCTs();
        for (int i = 0; i != items.size(); i++)
        {
            SignedCertificateTimestamp sct = (SignedCertificateTimestamp)items.get(i);
            System.out.println("  SCT #" + (i + 1));
            System.out.println("    version:   v" + (sct.getSctVersion() + 1));
            System.out.println("    log id:    " + Hex.toHexString(sct.getLogID()));
            System.out.println("    timestamp: " + formatTimestamp(sct.getTimestamp()));
            System.out.println("    algorithm: hash=" + sct.getHashAlgorithm()
                + " sig=" + sct.getSignatureAlgorithm()
                + " (TLS 1.2 sec. 7.4.1.4.1)");
            System.out.println("    signature: " + sct.getSignature().length + " bytes");
            if (sct.getExtensions().length > 0)
            {
                System.out.println("    extensions:" + sct.getExtensions().length + " bytes");
            }
        }
    }

    private static void printV2(TransItemList list)
    {
        System.out.println("RFC 9162 TransItemList (" + list.size()
            + " item" + (list.size() == 1 ? "" : "s") + "):");

        List items = list.getItems();
        for (int i = 0; i != items.size(); i++)
        {
            TransItem item = (TransItem)items.get(i);
            String typeName = describeVersionedType(item.getVersionedType());
            System.out.println("  TransItem #" + (i + 1) + " — " + typeName
                + " (0x" + Integer.toHexString(item.getVersionedType()) + ")");

            SignedCertificateTimestampDataV2 sct = item.getSignedCertificateTimestampDataV2();
            if (sct != null)
            {
                System.out.println("    log id:        " + Hex.toHexString(sct.getLogID()));
                System.out.println("    timestamp:     " + formatTimestamp(sct.getTimestamp()));
                System.out.println("    signature:     " + sct.getSignature().length + " bytes");
                if (!sct.getSctExtensions().isEmpty())
                {
                    System.out.println("    sct_extensions: " + sct.getSctExtensions().size() + " entr"
                        + (sct.getSctExtensions().size() == 1 ? "y" : "ies"));
                    for (int j = 0; j != sct.getSctExtensions().size(); j++)
                    {
                        SctExtension ext = (SctExtension)sct.getSctExtensions().get(j);
                        System.out.println("      type 0x" + Integer.toHexString(ext.getExtensionType())
                            + " (" + ext.getExtensionData().length + " bytes)");
                    }
                }
            }
            else
            {
                System.out.println("    raw payload:   " + item.getRawData().length
                    + " bytes (no structured decoder for this type)");
            }
        }
    }

    private static String describeVersionedType(int versionedType)
    {
        switch (versionedType)
        {
        case TransItem.x509_entry_v2:        return "x509_entry_v2";
        case TransItem.precert_entry_v2:     return "precert_entry_v2";
        case TransItem.x509_sct_v2:          return "x509_sct_v2";
        case TransItem.precert_sct_v2:       return "precert_sct_v2";
        case TransItem.signed_tree_head_v2:  return "signed_tree_head_v2";
        case TransItem.consistency_proof_v2: return "consistency_proof_v2";
        case TransItem.inclusion_proof_v2:   return "inclusion_proof_v2";
        default:                             return "unknown";
        }
    }

    private static String formatTimestamp(long msSinceEpoch)
    {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(new Date(msSinceEpoch));
    }
}
