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

        try
        {
            for (int t = 0; t < args.length; t++)
            {
                String arg = args[t];
                if (arg.equals("-ta"))
                {
                    trustAnchorFile = ExampleUtils.nextArgAsFile("Trust Anchor File", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("-url"))
                {
                    serverRootUrl = ExampleUtils.nextArgAsString("Server URL", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("-url"))
                {
                    cn = ExampleUtils.nextArgAsString("Common Name", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("-keyStore"))
                {
                    clientKeyStoreFile = ExampleUtils.nextArgAsFile("Client Key store", args, t);
                    t += 1;
                    continue;
                }
                else if (arg.equals("-keyStorePass"))
                {
                    clientKeyStoreFilePassword = ExampleUtils.nextArgAsString("Keystore password", args, t).toCharArray();
                    t += 1;
                    continue;
                }
                if (arg.equals("-keyStoreType"))
                {
                    keyStoreType = ExampleUtils.nextArgAsString("Keystore type", args, t);
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

        if (serverRootUrl == null)
        {
            System.err.println("Server url (-url) must be defined.");
            System.exit(-1);
        }

        if (cn == null)
        {
            System.err.println("Common Name (-cn) must be defined.");
            System.exit(-1);
        }

        if (trustAnchorFile == null)
        {
            System.err.println("Trust Anchor (-tn) must be defined.");
            System.exit(-1);
        }


        //
        // Make CSR
        //

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
            new X500Name("CN=Test"),
            keyPair.getPublic());

        PKCS10CertificationRequest csr = pkcs10Builder.build(
            new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(keyPair.getPrivate()));

        JcaESTServiceBuilder est = new JcaESTServiceBuilder(
            "https://localhost:8443/.well-known/est/",
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

        est.build();


    }


    public static void main(String[] args)
        throws Exception
    {
        new EnrollExample(args);
    }
}
