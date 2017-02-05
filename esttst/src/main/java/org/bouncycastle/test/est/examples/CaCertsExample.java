package org.bouncycastle.test.est.examples;


import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.TrustAnchor;
import java.util.Set;

import javax.net.ssl.SSLSession;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.util.Strings;

/**
 * CaCertsExample gives examples of fetching CA certs.
 */
public class CaCertsExample
{

    public CaCertsExample(String[] args)
        throws Exception
    {
        File trustAnchorFile = null;
        String serverRootUrl = null;

        try
        {
            for (int t = 0; t < args.length; t++)
            {
                String arg = args[t];
                if (arg.equals("-ta"))
                {
                    trustAnchorFile = nextArgAsFile("Trust Anchor File", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("-url"))
                {
                    serverRootUrl = nextArgAsString("Server URL", args, t);
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
            System.exit(1);
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
        JcaESTServiceBuilder builder = null;
        if (trustAnchors != null && !trustAnchors.isEmpty())
        {
            builder = new JcaESTServiceBuilder(serverRootUrl, trustAnchors);
        }
        else
        {
            builder = new JcaESTServiceBuilder(serverRootUrl);
        }

        //
        // Make a client.
        //

        ESTService estService = builder.build();

        ESTService.CACertsResponse caCertsResponse = estService.getCACerts();
        //
        // We must check the response is trusted. If it is not trusted we have fetched the CAs
        // without verifying the source using a trust anchor. At this point an out of band 'ie user' must
        // accept the CA certs returned.
        // This is congruent with <https://tools.ietf.org/html/rfc7030#section-4.1.1> Bootstrapping.
        //

        if (!caCertsResponse.isTrusted())
        {
           javax.security.cert.X509Certificate[] certs = ((SSLSession)caCertsResponse.getSession()).getPeerCertificateChain();
           for (javax.security.cert.X509Certificate cert: certs) {
               System.out.println(cert.toString());
           }

           System.out.println("As part of the TLS handshake, the server tendered to us these certificates.");
           if (!userSaysYes("Do you accept these certificates (y,n) ?")) {
               System.exit(0);
           }

           for (X509CertificateHolder holder: ESTService.storeToArray(caCertsResponse.getStore())) {
               System.out.println(ExampleUtils.toJavaX509Certificate(holder).toString());
           }
            System.out.println("The untrusted server tendered to us these certificates as CA certs");
            if (!userSaysYes("Do you accept these certificates (y,n) ?")) {
                System.exit(0);
            }
        }



    }

    public static void main(String[] args)
        throws Exception
    {
        new CaCertsExample(args);
    }

    private File nextArgAsFile(String label, String[] args, int t)
    {
        if (t + 1 >= args.length || args[t + 1].startsWith("-"))
        {
            throw new IllegalArgumentException(label + ": Missing File argument");
        }

        return new File(args[t + 1]);
    }

    private String nextArgAsString(String label, String[] args, int t)
    {
        if (t + 1 >= args.length || args[t + 1].startsWith("-"))
        {
            throw new IllegalArgumentException(label + ": Missing File argument");
        }

        return args[t + 1];
    }

    private boolean userSaysYes(String question)
        throws IOException
    {
        BufferedReader bin = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = bin.readLine()) != null)
        {
            System.out.println();
            System.out.print(question + " ");
            if (Strings.toLowerCase(line).startsWith("y"))
            {
                return true;
            }
            else if (Strings.toLowerCase(line).startsWith("n"))
            {
                break;
            }
        }
        return false;
    }
}
