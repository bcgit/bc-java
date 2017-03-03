package org.bouncycastle.test.est.examples;


import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.security.cert.TrustAnchor;
import java.util.Set;

import javax.net.ssl.SSLSession;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.CACertsResponse;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.SSLSocketFactoryCreatorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * CaCertsExample gives examples of fetching CA certs.
 */
public class CaCertsExample
{

    public CaCertsExample(String[] args)
        throws Exception
    {

        if (args.length == 0)
        {
            printArguments();
            System.exit(1);
        }

        Security.addProvider(new BouncyCastleProvider());

        File trustAnchorFile = null;
        String serverRootUrl = null;
        boolean printTLSCerts = false;
        String tlsVersion = "TLS";
        String tlsProvider = "SunJSSE";
        String tlsProviderClass = null;
        boolean noNameVerifier = false;
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
                else if (arg.equals("--printTLS"))
                {
                    printTLSCerts = true;
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
                } else if (arg.equals("--no-name-verifier")) {
                    noNameVerifier = true;
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

        SSLSocketFactoryCreatorBuilder sfcb = null;

        //
        // Make est client builder
        //
        JcaESTServiceBuilder builder = null;
        if (trustAnchors != null && !trustAnchors.isEmpty())
        {
            sfcb = new SSLSocketFactoryCreatorBuilder(JcaJceUtils.getCertPathTrustManager(trustAnchors, null));
        }
        else
        {
            // In this case we do not have trust anchors so create a builder for a client talking to an untrusted server.
            sfcb = new SSLSocketFactoryCreatorBuilder(JcaJceUtils.getTrustAllTrustManager());
        }

        sfcb.withTLSVersion(tlsVersion);
        sfcb.withProvider(tlsProvider);


        builder = new JcaESTServiceBuilder(serverRootUrl, sfcb.build());

        if (noNameVerifier) {
            builder.withHostNameAuthorizer(null);
        }
        builder.withTimeout(timeout);

        //
        // Make a client.
        //

        ESTService estService = builder.build();

        CACertsResponse caCertsResponse = estService.getCACerts();
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
                System.out.println(cert.toString());


            }

            System.out.println("As part of the TLS handshake, the server tendered to us these certificates.");
            if (!ExampleUtils.userSaysYes("Do you accept these certificates (y,n) ?"))
            {
                System.exit(0);
            }

            System.out.println();
            System.out.println("The untrusted server tendered to us these certificates as CA certs");
            for (X509CertificateHolder holder : ESTService.storeToArray(caCertsResponse.getCertificateStore()))
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
                System.out.println(ExampleUtils.toJavaX509Certificate(holder));

            }

            if (!ExampleUtils.userSaysYes("Do you accept these certificates (y,n) ?"))
            {
                System.exit(0);
            }
        }


        System.out.println("Fetched CA Certs:\n\n");

        for (X509CertificateHolder holder : ESTService.storeToArray(caCertsResponse.getCertificateStore()))
        {
            System.out.println(ExampleUtils.toPem(holder));
        }

        if (printTLSCerts)
        {
            System.out.println("\n TLS Certificates");
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
        try
        {
            new CaCertsExample(args);

        }
        catch (Exception ex)
        {
            System.out.println("\n\n-----------------");
            System.out.println(ex.getMessage());
            System.out.println("-----------------\n\n");
            throw ex;
        }
    }

    public void printArguments()
    {
        System.out.println("-t <file>                         Trust anchor file. (PEM)");
        System.out.println("-u <url>                          Server URL");
        System.out.println("--printTLS <url>                  Print TLS certificates as PEM format");
        System.out.println("--tls <version>                   Use this TLS version when creating socket factory, Eg TLSv1.2");
        System.out.println("--tlsProvider <provider> <class>  The JSSE Provider.");
        System.out.println("--to <milliseconds>               Timeout in milliseconds.");
        System.out.println("--no-name-verifier                No hostname verifier.");
    }

}
