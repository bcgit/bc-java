package org.bouncycastle.test.est.examples;


import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.Security;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.net.ssl.SSLSession;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * CaCertsExample gives examples of fetching CA certs.
 */
public class CaCertsExample
{

    public CaCertsExample(String[] args)
        throws Exception
    {

        Security.addProvider(new BouncyCastleProvider());

        File trustAnchorFile = null;
        String serverRootUrl = null;
        boolean printTLSCerts = false;

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
                } else if (arg.equals("-printTLS")) {
                    printTLSCerts = true;
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

        if (serverRootUrl == null)
        {
            System.err.println("Server url (-url) must be defined.");
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

        javax.security.cert.X509Certificate[] certs = ((SSLSession)caCertsResponse.getSession()).getPeerCertificateChain();

        if (!caCertsResponse.isTrusted())
        {

            System.out.println();

            for (javax.security.cert.X509Certificate cert : certs)
            {

                //
                // Limited the amount of information for the sake of the example.
                // The default too string prints everything and is hard to follow.
                // It is at this point developers should present users with enough information to make an informed
                // decision.
                //

                System.out.println("Subject: " + cert.getSubjectDN());
                System.out.println("Issuer: " + cert.getIssuerDN());
                System.out.println("Serial Number: " + cert.getSerialNumber());
                System.out.println("Not Before: " + cert.getNotBefore());
                System.out.println("Not After: " + cert.getNotAfter());
                System.out.println("Signature Algorithm: " + cert.getSigAlgName());

                System.out.println();
            }

            System.out.println("As part of the TLS handshake, the server tendered to us these certificates.");
            if (!userSaysYes("Do you accept these certificates (y,n) ?"))
            {
                System.exit(0);
            }

            System.out.println();
            System.out.println("The untrusted server tendered to us these certificates as CA certs");
            for (X509CertificateHolder holder : ESTService.storeToArray(caCertsResponse.getStore()))
            {

                //
                // Limited the amount of information for the sake of the example.
                // The default too string prints everything and is hard to follow.
                // It is at this point developers should present users with enough information to make an informed
                // decision.
                //

                System.out.println("Subject: " + holder.getSubject());
                System.out.println("Issuer: " + holder.getIssuer());
                System.out.println("Serial Number: " + holder.getSerialNumber());
                System.out.println("Not Before: " + holder.getNotBefore());
                System.out.println("Not After: " + holder.getNotAfter());
                System.out.println("Signature Algorithm: " + holder.getSignatureAlgorithm());
                System.out.println();

            }

            if (!userSaysYes("Do you accept these certificates (y,n) ?"))
            {
                System.exit(0);
            }
        }


        System.out.println("Fetched CA Certs:\n\n");

        for (X509CertificateHolder holder : ESTService.storeToArray(caCertsResponse.getStore()))
        {
           System.out.println(ExampleUtils.toPem(holder));
        }



        System.out.println("\n TLS Certificates");


        if (printTLSCerts) {
            System.out.println();
            for (javax.security.cert.X509Certificate cert : certs)
            {
                System.out.println(ExampleUtils.toPem(new X509CertificateHolder(cert.getEncoded())));
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
        System.out.println();
        System.out.println(question + " ");
        while ((line = bin.readLine()) != null)
        {
            if (Strings.toLowerCase(line).startsWith("y"))
            {
                System.out.println();
                return true;
            }
            else if (Strings.toLowerCase(line).startsWith("n"))
            {
                break;
            }
            System.out.println();
            System.out.println(question + " ");
        }
        System.out.println();
        return false;
    }
}
