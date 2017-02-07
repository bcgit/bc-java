package org.bouncycastle.test.est.examples;


import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.BasicAuth;
import org.bouncycastle.est.DigestAuth;
import org.bouncycastle.est.ESTAuth;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * Enroll example exercises the enrollment of a certificate.
 * It will generate a CSR using the supplied common name.
 * As this is a PEM encoded trusted operation a trust anchor will need to be provided.
 */
public class EnrollExample
{
    public EnrollExample(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        File trustAnchorFile = null;
        String serverRootUrl = null;
        String cn = null;
        File clientKeyStoreFile = null;
        char[] clientKeyStoreFilePassword = null;
        String keyStoreType = null;
        boolean basicAuth = false;
        boolean digestAuth = false;
        String[] credentials = null;
        boolean reEnroll = false;

        try
        {
            for (int t = 0; t < args.length; t++)
            {
                String arg = args[t];
                if (arg.equals("-r"))
                {
                    reEnroll = true;
                    continue;
                }
                else if (arg.equals("-t"))
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
                else if (arg.equals("-c"))
                {
                    cn = ExampleUtils.nextArgAsString("Common Name", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("--keyStore"))
                {
                    clientKeyStoreFile = ExampleUtils.nextArgAsFile("Client Key store", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("--keyStorePass"))
                {
                    clientKeyStoreFilePassword = ExampleUtils.nextArgAsString("Keystore password", args, t).toCharArray();
                    t += 1;
                    continue;
                }
                if (arg.equals("--keyStoreType"))
                {
                    keyStoreType = ExampleUtils.nextArgAsString("Keystore type", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("--keyStoreType"))
                {
                    keyStoreType = ExampleUtils.nextArgAsString("Keystore type", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("--digestAuth"))
                {
                    credentials = ExampleUtils.nextArgAsString("Keystore type", args, t).split(":");
                    digestAuth = true;
                    t += 1;
                    continue;
                }
                else if (arg.equals("--basicAuth"))
                {
                    credentials = ExampleUtils.nextArgAsString("Keystore type", args, t).split(":");
                    basicAuth = true;
                    t += 1;
                    continue;
                }
                else
                {
                    printArgs();
                    System.exit(0);
                }
            }
        }
        catch (IllegalArgumentException ilex)
        {
            System.err.println(ilex.getMessage());
            System.exit(1);
        }

        if (args.length == 0)
        {
            System.out.println("-r                                    Re-enroll");
            System.out.println("-t <file>                             Trust anchor file");
            System.out.println("-u <url>                              EST server url.");
            System.out.println("-c <common name>                      EST server url.");
            System.out.println("--keyStore <file>                      Optional Key Store.");
            System.out.println("--keyStorePass <password>              Optional Key Store password.");
            System.out.println("--keyStoreType <JKS>                   Optional Key Store type, defaults to JKS");
            System.out.println("--digestAuth <realm:user:password>     Digest Auth credentials, if real is not");
            System.out.println("                                      specified <user:password> then the realm from the server is used.");
            System.out.println("--basicAuth <realm:user:password>      Use basic auth.");
            System.exit(0);
        }


        if (serverRootUrl == null)
        {
            System.err.println("Server url (-u) must be defined.");
            System.exit(-1);
        }

        if (cn == null)
        {
            System.err.println("Common Name (-c) must be defined.");
            System.exit(-1);
        }

        if (trustAnchorFile == null)
        {
            System.err.println("Trust Anchor (-t) must be defined.");
            System.exit(-1);
        }


        //
        // Make a CSR here
        //

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
            new X500Name("CN=" + cn),
            keyPair.getPublic());

        PKCS10CertificationRequest csr = pkcs10Builder.build(
            new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(keyPair.getPrivate()));

        JcaESTServiceBuilder est = new JcaESTServiceBuilder(serverRootUrl,
            ExampleUtils.toTrustAnchor(ExampleUtils.readPemCertificate(trustAnchorFile)));

        if (clientKeyStoreFile != null)
        {
            if (keyStoreType == null)
            {
                keyStoreType = "JKS";
            }
            KeyStore ks = KeyStore.getInstance(keyStoreType, "BC");
            ks.load(new FileInputStream(clientKeyStoreFile), clientKeyStoreFilePassword);
            est.withClientKeystore(ks, clientKeyStoreFilePassword);
        }

        ESTAuth auth = null;

        if (digestAuth)
        {
            if (credentials.length == 3)
            {
                auth = new DigestAuth(credentials[0], credentials[1], credentials[2], new SecureRandom());
            }
            else if (credentials.length == 2)
            {
                auth = new DigestAuth(null, credentials[0], credentials[1], new SecureRandom());
            }
            else
            {
                System.err.println("Not enough credential for digest auth.");
                System.exit(0);
            }
        }
        else if (basicAuth)
        {
            if (credentials.length == 3)
            {
                auth = new BasicAuth(credentials[0], credentials[1], credentials[2]);
            }
            else if (credentials.length == 2)
            {
                auth = new BasicAuth(null, credentials[0], credentials[1]);
            }
            else
            {
                System.err.println("Not enough credential for basic auth.");
                System.exit(0);
            }
        }

        ESTService estService = est.build();
        ESTService.EnrollmentResponse enrollmentResponse;

        //
        // The enrollment action can be deferred by the server.
        // In this example we will check if the response is actually completed.
        // If it is not then we must wait long enough for it to be completed.
        //
        do
        {
            enrollmentResponse = estService.simpleEnroll(reEnroll, csr, auth);
            if (!enrollmentResponse.isCompleted())
            {
                long t = enrollmentResponse.getNotBefore() - System.currentTimeMillis();
                if (t < 0)
                {
                    continue;
                }
                t += 1000;
                Thread.sleep(t);
                continue;
            }
        }
        while (!enrollmentResponse.isCompleted());


        for (X509CertificateHolder holder : ESTService.storeToArray(enrollmentResponse.getStore()))
        {

            //
            // Limited the amount of information for the sake of the example.
            // The default too string prints everything and is hard to follow.
            //

            System.out.println("Subject: " + holder.getSubject());
            System.out.println("Issuer: " + holder.getIssuer());
            System.out.println("Serial Number: " + holder.getSerialNumber());
            System.out.println("Not Before: " + holder.getNotBefore());
            System.out.println("Not After: " + holder.getNotAfter());
            System.out.println("Signature Algorithm: " + holder.getSignatureAlgorithm());
            System.out.println();

        }

    }

    public static void main(String[] args)
        throws Exception
    {
        new EnrollExample(args);
    }

    public void printArgs()
    {
        System.out.println("-ta <file>                            Trust anchor file");
        System.out.println("-url <url>                            EST server url.");
        System.out.println("-keyStore <file>                      Optional Key Store.");
        System.out.println("-keyStorePass <password>              Optional Key Store password.");
        System.out.println("-keyStoreType <JKS>                   Optional Key Store type, defaults to JKS");
        System.out.println("-digestAuth <realm:user:password>     Digest Auth credentials, if real is not");
        System.out.println("                                      specified <user:password> then the realm from the server is used.");
        System.out.println("-basicAuth <realm:user:password>      Use basic auth.");
    }
}
