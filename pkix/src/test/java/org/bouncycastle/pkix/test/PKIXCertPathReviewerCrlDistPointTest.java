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
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
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
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Properties;

/**
 * Both PKIXCertPathReviewer copies may only fetch a CRL from a certificate's CRL distribution
 * point when org.bouncycastle.x509.enableCRLDP is set, as CertPathValidator and
 * X509RevocationChecker require, and only for a certificate whose issuer chain passed every check
 * back to a trust anchor - not for one issued under an end entity certificate or a revoked
 * intermediate. A CRL that is fetched has to cover the certificate as a local one must, and a
 * distribution point carrying only cRLIssuer is passed over rather than failing the review.
 * A local server records whether a connection arrived, and can serve a CRL.
 */
public class PKIXCertPathReviewerCrlDistPointTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String FETCH_DISABLED = "CertPathReviewer.crlDistPtFetchDisabled";
    private static final String FETCH_UNTRUSTED = "CertPathReviewer.crlDistPtFetchUntrusted";
    private static final String LOAD_ERROR = "CertPathReviewer.loadCrlDistPointError";
    private static final String ONLINE_VALID = "CertPathReviewer.onlineValidCRL";
    private static final String ONLINE_OUT_OF_SCOPE = "CertPathReviewer.onlineCRLOutOfScope";
    private static final String NOT_REVOKED = "CertPathReviewer.notRevoked";
    private static final String NO_VALID_CRL = "CertPathReviewer.noValidCrlFound";
    private static final String NO_CA_CERT = "CertPathReviewer.noCACert";
    private static final String CERT_REVOKED = "CertPathReviewer.certRevoked";

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        System.getProperties().remove(Properties.X509_ENABLE_CRLDP);
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
            Fixture f = new Fixture(server.getUrl(), Fixture.TRUSTED);

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
            Fixture f = new Fixture(server.getUrl(), Fixture.UNTRUSTED);

            assertTrue(reviewPkix(f).contains(FETCH_UNTRUSTED));
            assertTrue(reviewX509(f).contains(FETCH_UNTRUSTED));
            assertEquals("connection made for a chain with no trust anchor", 0, server.getConnectionCount());
        }
        finally
        {
            server.close();
        }
    }

    /**
     * The issuer verifies back to the anchor, but is an end entity certificate: the leaf's
     * signature checks out and the chain still carries an error above it.
     */
    public void testNoFetchUnderEndEntityIssuer()
        throws Exception
    {
        System.setProperty(Properties.X509_ENABLE_CRLDP, "true");

        LocalServer server = new LocalServer(false);
        try
        {
            Fixture f = new Fixture(server.getUrl(), Fixture.VIA_END_ENTITY);

            List pkixIds = reviewPkix(f);
            assertTrue(pkixIds.contains(NO_CA_CERT));
            assertTrue(pkixIds.contains(FETCH_UNTRUSTED));
            assertFalse(pkixIds.contains(LOAD_ERROR));

            List x509Ids = reviewX509(f);
            assertTrue(x509Ids.contains(NO_CA_CERT));
            assertTrue(x509Ids.contains(FETCH_UNTRUSTED));
            assertFalse(x509Ids.contains(LOAD_ERROR));

            assertEquals("connection made for a certificate issued under an end entity certificate", 0, server.getConnectionCount());
        }
        finally
        {
            server.close();
        }
    }

    /**
     * The intermediate is a proper CA under the anchor, but a CRL in the local store revokes it.
     */
    public void testNoFetchUnderRevokedIssuer()
        throws Exception
    {
        System.setProperty(Properties.X509_ENABLE_CRLDP, "true");

        LocalServer server = new LocalServer(false);
        try
        {
            Fixture f = new Fixture(server.getUrl(), Fixture.VIA_REVOKED_CA);

            List pkixIds = reviewPkix(f);
            assertTrue(pkixIds.contains(CERT_REVOKED));
            assertTrue(pkixIds.contains(FETCH_UNTRUSTED));
            assertFalse(pkixIds.contains(LOAD_ERROR));

            List x509Ids = reviewX509(f);
            assertTrue(x509Ids.contains(CERT_REVOKED));
            assertTrue(x509Ids.contains(FETCH_UNTRUSTED));
            assertFalse(x509Ids.contains(LOAD_ERROR));

            assertEquals("connection made for a certificate issued under a revoked CA", 0, server.getConnectionCount());
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
            Fixture f = new Fixture(server.getUrl(), Fixture.TRUSTED);

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

    /**
     * A fetched CRL has to cover the certificate under the RFC 5280 sec. 6.3.3 rules the local
     * store path already applies: one whose issuing distribution point names the certificate's
     * distribution point is used, one naming another distribution point is passed over and the
     * review ends with no valid CRL found rather than with the certificate not revoked.
     */
    public void testFetchedCrlMustCoverCertificate()
        throws Exception
    {
        System.setProperty(Properties.X509_ENABLE_CRLDP, "true");

        LocalServer server = new LocalServer(false);
        try
        {
            Fixture f = new Fixture(server.getUrl(), Fixture.TRUSTED);

            server.setBody(f.crl(server.getUrl()).getEncoded());

            List pkixIds = reviewPkix(f);
            assertTrue(pkixIds.contains(ONLINE_VALID));
            assertTrue(pkixIds.contains(NOT_REVOKED));
            assertFalse(pkixIds.contains(NO_VALID_CRL));

            List x509Ids = reviewX509(f);
            assertTrue(x509Ids.contains(ONLINE_VALID));
            assertTrue(x509Ids.contains(NOT_REVOKED));
            assertFalse(x509Ids.contains(NO_VALID_CRL));

            server.setBody(f.crl("http://127.0.0.1:1/other-partition").getEncoded());

            pkixIds = reviewPkix(f);
            assertTrue(pkixIds.contains(ONLINE_OUT_OF_SCOPE));
            assertTrue(pkixIds.contains(NO_VALID_CRL));
            assertFalse(pkixIds.contains(ONLINE_VALID) || pkixIds.contains(NOT_REVOKED));

            x509Ids = reviewX509(f);
            assertTrue(x509Ids.contains(ONLINE_OUT_OF_SCOPE));
            assertTrue(x509Ids.contains(NO_VALID_CRL));
            assertFalse(x509Ids.contains(ONLINE_VALID) || x509Ids.contains(NOT_REVOKED));

            assertEquals(4, server.getConnectionCount());
        }
        finally
        {
            server.close();
        }
    }

    /**
     * RFC 5280 sec. 4.2.1.13 lets a DistributionPoint carry cRLIssuer and no distributionPoint;
     * the review has to complete rather than throw.
     */
    public void testCrlIssuerOnlyDistributionPoint()
        throws Exception
    {
        Fixture f = new Fixture(null, Fixture.CRL_ISSUER_ONLY);

        List pkixIds = reviewPkix(f);
        assertTrue(pkixIds.contains(NO_VALID_CRL));
        assertFalse(pkixIds.contains(FETCH_DISABLED));

        List x509Ids = reviewX509(f);
        assertTrue(x509Ids.contains(NO_VALID_CRL));
        assertFalse(x509Ids.contains(FETCH_DISABLED));
    }

    public void testStalledServerTimesOut()
        throws Exception
    {
        System.setProperty(Properties.X509_ENABLE_CRLDP, "true");

        LocalServer server = new LocalServer(true);
        try
        {
            final Fixture f = new Fixture(server.getUrl(), Fixture.TRUSTED);
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

    /**
     * @return the ids of every notification and error the review produced, for all certificates.
     */
    private static List reviewPkix(Fixture f)
        throws Exception
    {
        org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer reviewer =
            new org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer(f.path, f.params);
        reviewer.isValidCertPath();

        List ids = new ArrayList();
        List[][] bundles = new List[][]{ reviewer.getNotifications(), reviewer.getErrors() };
        for (int b = 0; b != bundles.length; b++)
        {
            for (int i = 0; i != bundles[b].length; i++)
            {
                for (Iterator it = bundles[b][i].iterator(); it.hasNext();)
                {
                    ids.add(((org.bouncycastle.pkix.util.ErrorBundle)it.next()).getId());
                }
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
        List[][] bundles = new List[][]{ reviewer.getNotifications(), reviewer.getErrors() };
        for (int b = 0; b != bundles.length; b++)
        {
            for (int i = 0; i != bundles[b].length; i++)
            {
                for (Iterator it = bundles[b][i].iterator(); it.hasNext();)
                {
                    ids.add(((org.bouncycastle.i18n.ErrorBundle)it.next()).getId());
                }
            }
        }
        return ids;
    }

    /**
     * Counts the connections it accepts, and either answers each with the body it was given (a
     * 404 when it has none) or holds it open without a response.
     */
    private static class LocalServer
        extends Thread
    {
        private final ServerSocket serverSocket;
        private final boolean stall;
        private final List held = Collections.synchronizedList(new ArrayList());
        private int connectionCount;
        private byte[] body;

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

        synchronized void setBody(byte[] body)
        {
            this.body = body;
        }

        private synchronized byte[] getBody()
        {
            return body;
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
                    byte[] content = getBody();
                    if (content == null)
                    {
                        out.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes("US-ASCII"));
                    }
                    else
                    {
                        out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: "
                            + content.length + "\r\nConnection: close\r\n\r\n").getBytes("US-ASCII"));
                        out.write(content);
                    }
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
            synchronized (held)
            {
                for (Iterator it = held.iterator(); it.hasNext();)
                {
                    ((Socket)it.next()).close();
                }
            }
        }
    }

    private static class Fixture
    {
        /** anchor issues the leaf. */
        static final int TRUSTED = 0;
        /** an unrelated self-signed CA issues the leaf; the path carries it and chains to nothing. */
        static final int UNTRUSTED = 1;
        /** anchor issues an end entity certificate, which issues the leaf. */
        static final int VIA_END_ENTITY = 2;
        /** anchor issues a CA certificate it has revoked in a CRL on the local store, which issues the leaf. */
        static final int VIA_REVOKED_CA = 3;
        /** anchor issues the leaf, whose single distribution point carries only cRLIssuer. */
        static final int CRL_ISSUER_ONLY = 4;

        final CertPath path;
        final PKIXParameters params;

        private final X500Name anchorName;
        private final KeyPair anchorKp;
        private final X509Certificate anchorCert;
        private final String crlDistPoint;

        Fixture(String crlDistPoint, int mode)
            throws Exception
        {
            this.crlDistPoint = crlDistPoint;

            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
            kpGen.initialize(256);
            anchorKp = kpGen.generateKeyPair();
            KeyPair otherKp = kpGen.generateKeyPair();
            KeyPair midKp = kpGen.generateKeyPair();
            KeyPair eeKp = kpGen.generateKeyPair();

            anchorName = new X500Name("CN=CRLDP Test Anchor");
            X500Name otherName = new X500Name("CN=CRLDP Test Unrelated CA");
            X500Name midName = new X500Name("CN=CRLDP Test Intermediate");

            anchorCert = caCert(anchorName, anchorKp);
            X509Certificate otherCert = caCert(otherName, otherKp);

            X500Name issuerName;
            PrivateKey issuerKey;
            X509Certificate midCert = null;
            X509CRL localCrl = null;
            switch (mode)
            {
            case UNTRUSTED:
                issuerName = otherName;
                issuerKey = otherKp.getPrivate();
                midCert = otherCert;
                break;
            case VIA_END_ENTITY:
                midCert = endEntityCert(anchorName, anchorKp.getPrivate(), midName, midKp.getPublic(), null, BigInteger.valueOf(3));
                issuerName = midName;
                issuerKey = midKp.getPrivate();
                break;
            case VIA_REVOKED_CA:
                midCert = caCert(anchorName, anchorKp.getPrivate(), midName, midKp.getPublic(), BigInteger.valueOf(3));
                issuerName = midName;
                issuerKey = midKp.getPrivate();
                localCrl = crl(null, midCert.getSerialNumber());
                break;
            default:
                issuerName = anchorName;
                issuerKey = anchorKp.getPrivate();
            }

            DistributionPoint dp;
            if (mode == CRL_ISSUER_ONLY)
            {
                dp = new DistributionPoint(null, null, new GeneralNames(new GeneralName(GeneralName.directoryName, anchorName)));
            }
            else
            {
                GeneralNames dpNames = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlDistPoint));
                dp = new DistributionPoint(new DistributionPointName(dpNames), null, null);
            }
            X509Certificate eeCert = endEntityCert(issuerName, issuerKey, new X500Name("CN=CRLDP Test EE"), eeKp.getPublic(), dp, BigInteger.valueOf(2));

            List certList = new ArrayList();
            certList.add(eeCert);
            if (midCert != null)
            {
                certList.add(midCert);
            }
            path = CertificateFactory.getInstance("X.509", BC).generateCertPath(certList);

            params = new PKIXParameters(Collections.singleton(new TrustAnchor(anchorCert, null)));
            params.setRevocationEnabled(true);
            if (localCrl != null)
            {
                params.addCertStore(CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(Collections.singleton(localCrl)), BC));
            }
        }

        /**
         * An in-date CRL from the anchor with no entries, carrying an issuing distribution point
         * naming the passed in URL when there is one.
         */
        X509CRL crl(String issuingDistPointUrl)
            throws Exception
        {
            return crl(issuingDistPointUrl, null);
        }

        private X509CRL crl(String issuingDistPointUrl, BigInteger revokedSerial)
            throws Exception
        {
            long now = System.currentTimeMillis();
            JcaX509v2CRLBuilder bldr = new JcaX509v2CRLBuilder(anchorCert, new Date(now - 60000L));
            bldr.setNextUpdate(new Date(now + 3600000L));
            if (issuingDistPointUrl != null)
            {
                GeneralNames idpNames = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, issuingDistPointUrl));
                bldr.addExtension(Extension.issuingDistributionPoint, true,
                    new IssuingDistributionPoint(new DistributionPointName(idpNames), false, false));
            }
            if (revokedSerial != null)
            {
                bldr.addCRLEntry(revokedSerial, new Date(now - 60000L), CRLReason.keyCompromise);
            }

            return new JcaX509CRLConverter().setProvider(BC)
                .getCRL(bldr.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(anchorKp.getPrivate())));
        }

        private static X509Certificate caCert(X500Name name, KeyPair kp)
            throws Exception
        {
            return caCert(name, kp.getPrivate(), name, kp.getPublic(), BigInteger.valueOf(1));
        }

        private static X509Certificate caCert(X500Name issuerName, PrivateKey issuerKey, X500Name name, PublicKey pub, BigInteger serial)
            throws Exception
        {
            long now = System.currentTimeMillis();
            JcaX509v3CertificateBuilder bldr = new JcaX509v3CertificateBuilder(issuerName, serial,
                new Date(now - 3600000L), new Date(now + 3600000L), name, pub);
            bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            bldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            return new JcaX509CertificateConverter().setProvider(BC)
                .getCertificate(bldr.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(issuerKey)));
        }

        private static X509Certificate endEntityCert(X500Name issuerName, PrivateKey issuerKey, X500Name name, PublicKey pub,
            DistributionPoint dp, BigInteger serial)
            throws Exception
        {
            long now = System.currentTimeMillis();
            JcaX509v3CertificateBuilder bldr = new JcaX509v3CertificateBuilder(issuerName, serial,
                new Date(now - 3600000L), new Date(now + 3600000L), name, pub);
            bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            bldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            if (dp != null)
            {
                bldr.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{ dp }));
            }

            return new JcaX509CertificateConverter().setProvider(BC)
                .getCertificate(bldr.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(issuerKey)));
        }
    }
}
