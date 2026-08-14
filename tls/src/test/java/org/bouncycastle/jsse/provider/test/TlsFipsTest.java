package org.bouncycastle.jsse.provider.test;

import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.SSLContext;

import junit.framework.TestCase;

/**
 * A test to confirm what the BCJSSE provider actually enables in FIPS mode: the protocol
 * preference, the GCM cipher suites (available when the JcaTlsCrypto supplies a FIPS GCM nonce
 * generator factory), and the ML-KEM based named groups.
 * <p/>
 * Note this is the complement of {@link FipsCipherSuitesTestSuite} /
 * {@link FipsCipherSuitesEngineTestSuite}: those check that nothing <em>outside</em> the FIPS set is
 * exposed, this one checks the FIPS-approved algorithms are in fact there.
 */
public class TlsFipsTest
    extends TestCase
{
    protected void setUp()
    {
        FipsTestUtils.setupFipsSuite();
    }

    protected void tearDown()
    {
        FipsTestUtils.teardownFipsSuite();
    }

    public void testTLS13()
        throws Exception
    {
        Provider tlsProv = ProviderUtils.getProviderBCJSSE();

        SSLContext clientContext = SSLContext.getInstance("TLS", tlsProv);

        clientContext.init(null, null, null);

        try
        {
            String[] protocols = clientContext.getSupportedSSLParameters().getProtocols();

            assertTrue(protocols[0].equals("TLSv1.3"));
        }
        catch (NoSuchMethodError e)
        {
            // ignore on this jvm, we'll fail elsewhere!
        }
    }

    public void testFipsModeGCM()
        throws Exception
    {
        Set<String> gcm = new HashSet<String>();
        {
            gcm.add("TLS_AES_128_GCM_SHA256");
            gcm.add("TLS_AES_256_GCM_SHA384");

            if (FipsTestUtils.enableGCMCiphersIn12)
            {
                gcm.add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
                gcm.add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
                gcm.add("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
                gcm.add("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
                gcm.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
                gcm.add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
                gcm.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
                gcm.add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");

                if (FipsTestUtils.provAllowRSAKeyExchange)
                {
                    gcm.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
                    gcm.add("TLS_RSA_WITH_AES_256_GCM_SHA384");
                }
            }
        }

        Provider tlsProv = ProviderUtils.getProviderBCJSSE();

        SSLContext sslContext = SSLContext.getInstance("TLS", tlsProv);

        sslContext.init(null, null, SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

        String[] cipherSuites = sslContext.getServerSocketFactory().getSupportedCipherSuites();

        for (int i = 0; i != cipherSuites.length; i++)
        {
            gcm.remove(cipherSuites[i]);
        }

        assertTrue("GCM cipher suites missing in FIPS mode: " + gcm, gcm.isEmpty());
    }

    /**
     * Confirms that the ML-KEM/hybrid named groups classified as FIPS-approved in
     * FipsUtils.isFipsNamedGroup can each complete a TLS 1.3 handshake through the FIPS-mode
     * BCJSSE provider. Both ends are restricted to the group under test: the pure ML-KEM groups
     * are not offered by default (see NamedGroupsTest), so this is what asks whether they work
     * when a caller does select them.
     */
    public void testFipsModeMLKEMGroups()
        throws Exception
    {
        String[] namedGroups = new String[]{
            "SecP256r1MLKEM768",
            "SecP384r1MLKEM1024",
            "X25519MLKEM768",
            "MLKEM512",
            "MLKEM768",
            "MLKEM1024",
        };

        Provider tlsProv = ProviderUtils.getProviderBCJSSE();

        KeyStore[] credential = NamedGroupTestUtil.createRSACredential();
        KeyStore ks = credential[0], ts = credential[1];

        for (int i = 0; i != namedGroups.length; i++)
        {
            NamedGroupTestUtil.runNamedGroupTest(namedGroups[i],
                NamedGroupTestUtil.createClientContext(tlsProv, ts),
                NamedGroupTestUtil.createServerContext(tlsProv, ks));
        }
    }
}
