package org.bouncycastle.openpgp.api.util;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPDefaultPolicy;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Date;

/**
 * Class to debug-print OpenPGP certificates and keys.
 */
public class OpenPGPKeyPrinter
{

    public static void main(String[] args)
            throws IOException
    {
        OpenPGPApi api = new BcOpenPGPApi();

        if (args.length == 0)
        {
            // -DM System.err.println
            System.err.println("Usage: OpenPGPKeyPrinter path/to/file...");
            // -DM System.exit
            System.exit(1);
        }

        for (String path : args)
        {
            File file = new File(path);
            if (!file.exists() || !file.isFile())
            {
                // -DM System.err.println
                System.err.println("Error: " + path + " is not a file or does not exist.");
                // -DM System.exit
                System.exit(1);
            }

            try (FileInputStream fIn = new FileInputStream(file))
            {
                OpenPGPCertificate certOrKey = api.readKeyOrCertificate()
                        .parseCertificateOrKey(fIn);
                // -DM System.out.println
                System.out.println(toString(certOrKey, new Date()));
            }
        }
    }

    public static String toString(OpenPGPCertificate certificate, Date evaluationTime)
    {
        StringBuilder sb = new StringBuilder();
        for (OpenPGPCertificate.OpenPGPCertificateComponent component : certificate.getComponents())
        {
            if (component.isBoundAt(evaluationTime))
            {
                green(sb, component.toDetailString()).append("\n");
            }
            else
            {
                red(sb, component.toDetailString()).append("\n");
            }

            OpenPGPCertificate.OpenPGPSignatureChains chains = component.getSignatureChains();
            for (OpenPGPCertificate.OpenPGPSignatureChain chain : chains)
            {
                boolean revocation = chain.isRevocation();
                boolean isHardRevocation = chain.isHardRevocation();
                String indent = "";
                for (OpenPGPCertificate.OpenPGPSignatureChain.Link link : chain)
                {
                    indent = indent + "  ";
                    sb.append(indent);
                    try
                    {
                        link.verify(new BcPGPContentVerifierBuilderProvider(), new OpenPGPDefaultPolicy());
                        if (revocation)
                        {
                            if (isHardRevocation)
                            {
                                red(sb, link.toString()).append("\n");
                            }
                            else
                            {
                                yellow(sb, link.toString()).append("\n");
                            }
                        }
                        else
                        {
                            green(sb, link.toString()).append("\n");
                        }
                    }
                    catch (PGPException e)
                    {
                        red(sb, link.toString()).append("\n");
                    }
                }
            }
        }

        return sb.toString();
    }

    private static StringBuilder red(StringBuilder sb, String text)
    {
        return sb.append("\033[31m").append(text).append("\033[0m");
    }

    private static StringBuilder redBg(StringBuilder sb, String text)
    {
        return sb.append("\033[41m").append(text).append("\033[0m");
    }

    private static StringBuilder green(StringBuilder sb, String text)
    {
        return sb.append("\033[32m").append(text).append("\033[0m");
    }

    private static StringBuilder greenBg(StringBuilder sb, String text)
    {
        return sb.append("\033[42m").append(text).append("\033[0m");
    }

    private static StringBuilder yellow(StringBuilder sb, String text)
    {
        return sb.append("\033[33m").append(text).append("\033[0m");
    }

    private static StringBuilder yellowBg(StringBuilder sb, String text)
    {
        return sb.append("\033[43m").append(text).append("\033[0m");
    }

}
