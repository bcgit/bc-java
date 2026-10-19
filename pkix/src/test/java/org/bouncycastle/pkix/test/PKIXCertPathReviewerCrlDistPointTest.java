package org.bouncycastle.pkix.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Properties;

/**
 * Both PKIXCertPathReviewer copies may only fetch a CRL from a certificate's CRL distribution
 * point when org.bouncycastle.x509.enableCRLDP is set, as CertPathValidator and
 * X509RevocationChecker require, and only for a certificate that verifies back to a trust anchor.
 * A local server records whether a connection arrived.
 */
public class PKIXCertPathReviewerCrlDistPointTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String FETCH_DISABLED = "CertPathReviewer.crlDistPtFetchDisabled";
    private static final String FETCH_UNTRUSTED = "CertPathReviewer.crlDistPtFetchUntrusted";
    private static final String LOAD_ERROR = "CertPathReviewer.loadCrlDistPointError";

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void tearDown()
    {
        System.getProperties().remove(Properties.X509_ENABLE_CRLDP);
    }

    public void testNoFetchByDefault()
        throws Exception
    {
        LocalServer server = new LocalServer(false);
        try
        {
            Fixture f = new Fixture(server.getUrl(), true);

            assertTrue(reviewPkix(f).contains(FETCH_DISABLED));
            assertTrue(reviewX509(f).contains(FETCH_DISABLED));
            assertEquals("connection made with CRLDP fetching disabled", 0, server.getConnectionCount());
        }
        finally
        {
            server.close();
        }
    }

    public void testNoFetchForUntrustedChain()
        throws Exception
    {
        System.setProperty(Properties.X509_ENABLE_CRLDP, "true");

        LocalServer server = new LocalServer(false);
        try
        {
            Fixture f = new Fixture(server.getUrl(), false);

            assertTrue(reviewPkix(f).contains(FETCH_UNTRUSTED));
            assertTrue(reviewX509(f).contains(FETCH_UNTRUSTED));
            assertEquals("connection made for a chain with no trust anchor", 0, server.getConnectionCount());
        }
        finally
        {
            server.close();
        }
    }

    public void testFetchWhenEnabledAndTrusted()
        throws Exception
    {
        System.setProperty(Properties.X509_ENABLE_CRLDP, "true");

        LocalServer server = new LocalServer(false);
        try
        {
            Fixture f = new Fixture(server.getUrl(), true);

            List pkixIds = reviewPkix(f);
            assertTrue(pkixIds.contains(LOAD_ERROR));
            assertFalse(pkixIds.contains(FETCH_DISABLED) || pkixIds.contains(FETCH_UNTRUSTED));

            List x509Ids = reviewX509(f);
            assertTrue(x509Ids.contains(LOAD_ERROR));
            assertFalse(x509Ids.contains(FETCH_DISABLED) || x509Ids.contains(FETCH_UNTRUSTED));

            assertEquals(2, server.getConnectionCount());
        }
        finally
        {
            server.close();
        }
    }

    public void testStalledServerTimesOut()
        throws Exception
    {
        System.setProperty(Properties.X509_ENABLE_CRLDP, "true");

        LocalServer server = new LocalServer(true);
        try
        {
            final Fixture f = new Fixture(server.getUrl(), true);
            final List[] results = new List[2];

            Thread pkix = new Thread()
            {
                public void run()
                {
                    try
                    {
                        results[0] = reviewPkix(f);
                    }
                    catch (Exception e)
                    {
                        // results[0] stays null
                    }
                }
            };
            Thread x509 = new Thread()
            {
                public void run()
                {
                    try
                    {
                        results[1] = reviewX509(f);
                    }
                    catch (Exception e)
                    {
                        // results[1] stays null
                    }
                }
            };
            pkix.setDaemon(true);
            x509.setDaemon(true);
            pkix.start();
            x509.start();
            pkix.join(60000);
            x509.join(60000);

            assertFalse("pkix reviewer still waiting on a stalled server", pkix.isAlive());
            assertFalse("x509 reviewer still waiting on a stalled server", x509.isAlive());
            assertTrue(results[0].contains(LOAD_ERROR));
            assertTrue(results[1].contains(LOAD_ERROR));
        }
        finally
        {
            server.close();
        }
    }

    private static List reviewPkix(Fixture f)
        throws Exception
    {
        org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer reviewer =
            new org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer(f.path, f.params);
        reviewer.isValidCertPath();

        List ids = new ArrayList();
        List[] notifications = reviewer.getNotifications();
        for (int i = 0; i != notifications.length; i++)
        {
            for (Iterator it = notifications[i].iterator(); it.hasNext();)
            {
                ids.add(((org.bouncycastle.pkix.util.ErrorBundle)it.next()).getId());
            }
        }
        return ids;
    }

    private static List reviewX509(Fixture f)
        throws Exception
    {
        org.bouncycastle.x509.PKIXCertPathReviewer reviewer =
            new org.bouncycastle.x509.PKIXCertPathReviewer(f.path, f.params);
        reviewer.isValidCertPath();

        List ids = new ArrayList();
        List[] notifications = reviewer.getNotifications();
        for (int i = 0; i != notifications.length; i++)
        {
            for (Iterator it = notifications[i].iterator(); it.hasNext();)
            {
                ids.add(((org.bouncycastle.i18n.ErrorBundle)it.next()).getId());
            }
        }
        return ids;
    }

    /**
     * Counts the connections it accepts, and either answers each with a 404 or holds it open
     * without a response.
     */
    private static class LocalServer
        extends Thread
    {
        private final ServerSocket serverSocket;
        private final boolean stall;
        private final List held = new ArrayList();
        private int connectionCount;

        LocalServer(boolean stall)
            throws IOException
        {
            this.serverSocket = new ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"));
            this.stall = stall;
            setDaemon(true);
            start();
        }

        String getUrl()
        {
            return "http://127.0.0.1:" + serverSocket.getLocalPort() + "/crl";
        }

        synchronized int getConnectionCount()
        {
            return connectionCount;
        }

        public void run()
        {
            try
            {
                for (;;)
                {
                    Socket s = serverSocket.accept();
                    synchronized (this)
                    {
                        connectionCount++;
                    }
                    if (stall)
                    {
                        held.add(s);
                        continue;
                    }

                    InputStream in = s.getInputStream();
                    int state = 0;
                    int b;
                    while (state < 4 && (b = in.read()) >= 0)
                    {
                        state = (b == ((state % 2 == 0) ? '\r' : '\n')) ? state + 1 : 0;
                    }
                    OutputStream out = s.getOutputStream();
                    out.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes("US-ASCII"));
                    out.flush();
                    s.close();
                }
            }
            catch (IOException e)
            {
                // server closed
            }
        }

        void close()
            throws IOException
        {
            serverSocket.close();
            for (Iterator it = held.iterator(); it.hasNext();)
            {
                ((Socket)it.next()).close();
            }
        }
    }

    private static class Fixture
    {
        final CertPath path;
        final PKIXParameters params;

        /**
         * @param trusted true for an issuer that is the trust anchor, false for an unrelated
         *                self-signed issuer that chains to nothing.
         */
        Fixture(String crlDistPoint, boolean trusted)
            throws Exception
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
            kpGen.initialize(256);
            KeyPair anchorKp = kpGen.generateKeyPair();
            KeyPair otherKp = kpGen.generateKeyPair();
            KeyPair eeKp = kpGen.generateKeyPair();

            X500Name anchorName = new X500Name("CN=CRLDP Test Anchor");
            X500Name otherName = new X500Name("CN=CRLDP Test Unrelated CA");

            X509Certificate anchorCert = caCert(anchorName, anchorKp);
            X509Certificate otherCert = caCert(otherName, otherKp);

            X500Name issuerName = trusted ? anchorName : otherName;
            PrivateKey issuerKey = trusted ? anchorKp.getPrivate() : otherKp.getPrivate();

            long now = System.currentTimeMillis();
            JcaX509v3CertificateBuilder eeBldr = new JcaX509v3CertificateBuilder(issuerName,
                BigInteger.valueOf(2), new Date(now - 3600000L), new Date(now + 3600000L),
                new X500Name("CN=CRLDP Test EE"), eeKp.getPublic());
            eeBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            eeBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            GeneralNames dpNames = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlDistPoint));
            eeBldr.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(
                new DistributionPoint[]{ new DistributionPoint(new DistributionPointName(dpNames), null, null) }));

            X509Certificate eeCert = new JcaX509CertificateConverter().setProvider(BC)
                .getCertificate(eeBldr.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(issuerKey)));

            List certList = new ArrayList();
            certList.add(eeCert);
            if (!trusted)
            {
                certList.add(otherCert);
            }
            path = CertificateFactory.getInstance("X.509", BC).generateCertPath(certList);

            params = new PKIXParameters(Collections.singleton(new TrustAnchor(anchorCert, null)));
            params.setRevocationEnabled(true);
        }

        private static X509Certificate caCert(X500Name name, KeyPair kp)
            throws Exception
        {
            long now = System.currentTimeMillis();
            PublicKey pub = kp.getPublic();
            JcaX509v3CertificateBuilder bldr = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(1),
                new Date(now - 3600000L), new Date(now + 3600000L), name, pub);
            bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            bldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            return new JcaX509CertificateConverter().setProvider(BC)
                .getCertificate(bldr.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(kp.getPrivate())));
        }
    }
}
