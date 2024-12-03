package org.bouncycastle.openpgp.api.util;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.IOException;
import java.util.Date;

public class DebugPrinter
{

    private static final String hardRevokedPrimaryKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "=x/EN\n" +
        "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String v6SecretKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
            "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
            "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
            "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
            "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
            "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
            "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
            "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
            "k0mXubZvyl4GBg==\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static void main(String[] args)
            throws IOException
    {

        OpenPGPCertificate certificate = OpenPGPCertificate.fromAsciiArmor(v6SecretKey);
        // -DM System.out.println
        System.out.println(toString(certificate, new Date()));
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
                        link.verify(new BcPGPContentVerifierBuilderProvider());
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
