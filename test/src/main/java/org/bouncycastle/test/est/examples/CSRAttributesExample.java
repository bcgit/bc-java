package org.bouncycastle.test.est.examples;


import java.io.File;
import java.security.Security;
import java.security.cert.TrustAnchor;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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

        try
        {
            for (int t = 0; t < args.length; t++)
            {
                String arg = args[t];
                if (arg.equals("-t"))
                {
                    trustAnchorFile = ExampleUtils.nextArgAsFile("Trust Anchor File", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("-u"))
                {
                    serverRootUrl = ExampleUtils.nextArgAsString("Server URL", args, t);
                    t += 1;
                    continue;
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

        //
        // Make est client builder
        //
        JcaESTServiceBuilder builder = new JcaESTServiceBuilder(serverRootUrl, trustAnchors);

        //
        // Make a client.
        //
        ESTService estService = builder.build();

        ESTService.CSRRequestResponse csrAttributes = estService.getCSRAttributes();

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
        System.out.println("-t <file>        Trust anchor file. (PEM)");
        System.out.println("-u <url>         Server URL");
    }

}
