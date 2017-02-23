package org.bouncycastle.test.est.examples;


import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.security.cert.TrustAnchor;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.est.CSRRequestResponse;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * CaCertsExample gives examples of fetching CA certs.
 */
public class CSRAttributesExample
{

    public CSRAttributesExample(String[] args)
        throws Exception
    {

        if (args.length == 0)
        {
            printArguments();
        }

        Security.addProvider(new BouncyCastleProvider());

        File trustAnchorFile = null;
        String serverRootUrl = null;
        boolean printTLSCerts = false;
        String tlsVersion = "TLS";
        String tlsProvider = null;
        String tlsProviderClass = null;
        int timeout = 0;

        try
        {
            for (int t = 0; t < args.length; t++)
            {
                String arg = args[t];
                if (arg.equals("-t"))
                {
                    trustAnchorFile = ExampleUtils.nextArgAsFile("Trust Anchor File", args, t);
                    t += 1;
                }
                else if (arg.equals("-u"))
                {
                    serverRootUrl = ExampleUtils.nextArgAsString("Server URL", args, t);
                    t += 1;
                }
                else if (arg.equals("--tls"))
                {
                    tlsVersion = ExampleUtils.nextArgAsString("TLS version", args, t);
                    t += 1;
                }
                else if (arg.equals("--tlsProvider"))
                {
                    tlsProvider = ExampleUtils.nextArgAsString("TLS Provider", args, t);
                    t += 1;
                    tlsProviderClass = ExampleUtils.nextArgAsString("TLS Provider Class", args, t);
                    t += 1;
                }
                else if (arg.equals("--to"))
                {
                    timeout = ExampleUtils.nextArgAsInteger("Timeout", args, t);
                    t += 1;
                }
                else
                {
                    throw new IllegalArgumentException("Unknown argument " + arg);
                }

            }
        }
        catch (IllegalArgumentException ilex)
        {
            System.err.println(ilex.getMessage());

            printArguments();

            System.exit(1);
        }

        if (serverRootUrl == null)
        {
            System.err.println("Server url (-u) must be defined.");
            System.exit(-1);
        }

        //
        // Read the trust anchor.
        //
        Set<TrustAnchor> trustAnchors = null;
        if (trustAnchorFile != null)
        {
            trustAnchors = ExampleUtils.toTrustAnchor(ExampleUtils.readPemCertificate(trustAnchorFile));
        }

        if (tlsProviderClass != null)
        {
            Security.addProvider((Provider)Class.forName(tlsProviderClass).newInstance());
        }

        //
        // Make est client builder
        //
        JcaESTServiceBuilder builder = new JcaESTServiceBuilder(serverRootUrl, trustAnchors);

        builder.withTlsVersion(tlsVersion);
        builder.withTlSProvider(tlsProvider);
        builder.withTimeout(timeout);

        //
        // Make a client.
        //
        ESTService estService = builder.build();

        CSRRequestResponse csrAttributes = estService.getCSRAttributes();

        for (ASN1ObjectIdentifier id : csrAttributes.getAttributesResponse().getRequirements())
        {
            System.out.println(id.toString());
        }

    }

    public static void main(String[] args)
        throws Exception
    {
        new CSRAttributesExample(args);
    }

    public void printArguments()
    {
        System.out.println("-t <file>                         Trust anchor file. (PEM)");
        System.out.println("-u <url>                          Server URL");
        System.out.println("--tls <version>                   Use this TLS version when creating socket factory, Eg TLSv1.2");
        System.out.println("--tlsProvider <provider> <class>  The JSSE Provider.");
        System.out.println("--to <milliseconds>               Timeout in milliseconds.");
    }

}
