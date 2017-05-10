package org.bouncycastle.test.est;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Test;


public class TestKeyUsage
    extends SimpleTest
{
    private static int[] keyUsage = new int[]{
        KeyUsage.digitalSignature,
        KeyUsage.nonRepudiation,
        KeyUsage.keyEncipherment,
        KeyUsage.dataEncipherment,
        KeyUsage.keyAgreement,
        KeyUsage.keyCertSign,
        KeyUsage.cRLSign,
        KeyUsage.encipherOnly,
        KeyUsage.decipherOnly
    };

    public static String[] keyUsageNames = new String[]{
        "digitalSignature",
        "nonRepudiation",
        "keyEncipherment",
        "dataEncipherment",
        "keyAgreement",
        "keyCertSign",
        "cRLSign",
        "encipherOnly",
        "decipherOnly"
    };


    private static KeyPurposeId[] keyPurposeIds = new KeyPurposeId[]{
        KeyPurposeId.id_kp_serverAuth,
        KeyPurposeId.id_kp_msSGC,
        KeyPurposeId.id_kp_nsSGC,
        KeyPurposeId.id_kp_clientAuth,
    };


    private static String[] KeyPurposeIDName = new String[]{
        "id_kp_serverAuth",
        "id_kp_msSGC",
        "id_kp_nsSGC",
        "id_kp_clientAuth"
    };

    public String getName()
    {
        return "TestKeyUsage";
    }

    public void performTest()
        throws Exception
    {
        ESTTestUtils.runJUnit(TestKeyUsage.class);
    }


    public static void matrix()
        throws Exception
    {

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        //
        // Permutate key usage indexes
        //
        ArrayList<List> keyUsages = new ArrayList<List>();
        keyUsages.add(new ArrayList());
        for (int a = 0; a < keyUsage.length; a++)
        {
            ArrayList<Integer> u = new ArrayList<Integer>();
            keyUsages.add(u);
            u.add(a);
        }


        for (int a = 0; a < keyUsage.length; a++)
        {
            ArrayList<Integer> u = new ArrayList<Integer>();

            for (int b = 0; b < a; b++)
            {
                u.add(b);
            }
            if (u.size() > 1)
            {
                keyUsages.add(u);
            }
        }


        //
        // Permutate keyPurposes indexes
        //
        ArrayList<List<Integer>> keyPurposes = new ArrayList<List<Integer>>();
        keyPurposes.add(new ArrayList<Integer>());
        for (int a = 0; a < keyPurposeIds.length; a++)
        {
            ArrayList<Integer> u = new ArrayList<Integer>();
            keyPurposes.add(u);
            u.add(a);
        }

        for (int a = 0; a < keyPurposeIds.length; a++)
        {
            ArrayList<Integer> u = new ArrayList<Integer>();
            for (int b = 0; b < a; b++)
            {
                u.add(b);
            }
            if (u.size() > 1)
            {
                keyPurposes.add(u);
            }
        }

        FileWriter sw = new FileWriter("~/matrix.html");
        PrintWriter pw = new PrintWriter(sw);


        pw.println("<html><head><style>" +

            "table.hovertable {\n" +
            "\tfont-family: verdana,arial,sans-serif;\n" +
            "\tfont-size:11px;\n" +
            "\tcolor:#333333;\n" +
            "\tborder-width: 1px;\n" +
            "\tborder-color: #999999;\n" +
            "\tborder-collapse: collapse;\n" +
            "}\n" +
            "table.hovertable th {\n" +
            "\tbackground-color:#c3dde0;\n" +
            "\tborder-width: 1px;\n" +
            "\tpadding: 8px;\n" +
            "\tborder-style: solid;\n" +
            "\tborder-color: #a9c6c9;\n" +
            "}\n" +
            "table.hovertable tr {\n" +
            "\tbackground-color:#d4e3e5;\n" +
            "}\n" +
            "table.hovertable td {\n" +
            "\tborder-width: 1px;\n" +
            "\tpadding: 8px;\n" +
            "\tborder-style: solid;\n" +
            "\tborder-color: #a9c6c9;\n" +
            "}\n" +
            "</style></head><body><div><table class=\"hovertable\">");
        pw.println("<tr><th></th>");

        for (List<Integer> x : keyUsages)
        {
            if (x.isEmpty())
            {
                pw.println("<th>null</th>");
            }
            else
            {
                pw.print("<th>");
                for (Integer k : x)
                {
                    pw.print(keyUsageNames[k]);
                    pw.println(" ");
                }
                pw.println("</th>");
            }
        }
        pw.println("<tr>");


        KeyUsage usage = null;
        ASN1EncodableVector purposes = null;


        for (List<Integer> y : keyPurposes)
        {
            pw.println("<tr>");

            pw.print("<td>");

            if (y.isEmpty())
            {
                pw.print("null");
                purposes = null;
            }
            else
            {
                purposes = new ASN1EncodableVector();
                for (Integer i : y)
                {
                    if (keyPurposeIds[i] != null)
                    {
                        purposes.add(keyPurposeIds[i]);
                        pw.print(" " + KeyPurposeIDName[i]);
                    }
                }
                pw.print("</td>");
            }

            for (List<Integer> x : keyUsages)
            {

                //
                // Assemble usage.
                //
                if (x.isEmpty())
                {
                    usage = null;
                }
                else
                {
                    int k = 0;
                    for (Integer i : x)
                    {
                        k |= keyUsage[i];
                    }
                    usage = new KeyUsage(k);
                }

                X509Certificate cert = makeCertificate(originalKeyPair, purposes, usage);


                try
                {
                    JcaJceUtils.validateServerCertUsage(cert);
                    pw.print("<td>Pass</td>");
                }
                catch (Exception ex)
                {
                    assert ex instanceof CertificateException;
                    pw.print("<td>Fail</td>");
                }

            }

            pw.println("</tr>");
        }

        pw.println("</table>");
        pw.println("</div></body></html>");

        pw.flush();
        pw.close();

    }


    @Test
    public void testWith_0()
        throws Exception
    {

        //
        // With no key usage and no extended key usage.
        //

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, null);

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_1()
        throws Exception
    {

        // With digitalSignature, and no extended key usage


        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.digitalSignature));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_2()
        throws Exception
    {

        // With keyEncipherment and no extended key usage

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.keyEncipherment));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_3()
        throws Exception
    {

        // With digitalSignature and keyEncipherment and no extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }

    @Test
    public void testCertUsage_4()
        throws Exception
    {

        // With digitalSignature, keyEncipherment amd keyAgreement no extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test(expected = CertificateException.class)
    public void testCertUsage_5()
        throws Exception
    {

        // With keyAgreement no extended key usage -- must fail.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_6()
        throws Exception
    {

        // Valid key usage with serverAuth extended key usage

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_serverAuth);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_7()
        throws Exception
    {

        // Valid key usage with msSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_msSGC);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }

    @Test
    public void testCertUsage_8()
        throws Exception
    {

        // Valid key usage with nsSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_nsSGC);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }

    @Test
    public void testCertUsage_9()
        throws Exception
    {

        // Valid key usage with nsSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_serverAuth);
        purpose.add(KeyPurposeId.id_kp_msSGC);
        purpose.add(KeyPurposeId.id_kp_nsSGC);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_10()
        throws Exception
    {

        // Valid key usage with nsSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_serverAuth);
        purpose.add(KeyPurposeId.id_kp_msSGC);
        purpose.add(KeyPurposeId.id_kp_nsSGC);
        purpose.add(KeyPurposeId.id_kp_clientAuth);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test(expected = CertificateException.class)
    public void testCertUsage_11()
        throws Exception
    {

        // Valid key usage with nsSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();

        purpose.add(KeyPurposeId.id_kp_clientAuth);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }

//    @Test
//    public void testKeyEncipherment()
//        throws Exception
//    {
//        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
//            ESTServerUtils.makeRelativeToServerHome("/keyusage/KeyUsage-keyEnciph.pem")
//        ));
//
//        JcaJceUtils.validateServerCertUsage(cert);
//
//    }
//
//    @Test
//    public void testCertPath()
//        throws Exception
//    {
//
//        ESTTestUtils.ensureProvider();
//
//        Set<TrustAnchor> ts = ESTTestUtils.toTrustAnchor(ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
//            ESTServerUtils.makeRelativeToServerHome("/keyusage/bc_cacert.crt")
//        )));
//        X509TrustManager[] tm = JcaJceUtils.getCertPathTrustManager(ts, null);
//
//        tm[0].checkServerTrusted(new X509Certificate[]{ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
//            ESTServerUtils.makeRelativeToServerHome("/keyusage/KeyUsage-keyEnciph.pem")
//        ))}, "");
//
//    }


    private static X509Certificate makeCertificate(KeyPair originalKeyPair, ASN1EncodableVector purposes, KeyUsage keyUsage)
        throws Exception
    {
        X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.CN, "Bunyip Bluegum");
        builder.addRDN(BCStyle.O, "Pudding Protectors");
        builder.addRDN(BCStyle.L, "Victoria");

        X500Name name = builder.build();

        X509Certificate clientTLSCert = ESTTestUtils.createASignedCert("SHA256WITHECDSA",
            name,
            SubjectPublicKeyInfo.getInstance(originalKeyPair.getPublic().getEncoded()),
            name,
            originalKeyPair.getPrivate(),
            1, purposes, keyUsage
        );

        return clientTLSCert;
    }


}
