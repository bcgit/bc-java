package org.bouncycastle.test.est;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.est.AttrOrOID;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;
import org.junit.Test;


public class TestGetCSRAttrs
    extends SimpleTest
{

    public String getName()
    {
        return "TestGetCSRAttrs";
    }

    private ESTServerUtils.ServerInstance startDefaultServer()
        throws Exception
    {

        final ESTServerUtils.EstServerConfig config = new ESTServerUtils.EstServerConfig();
        config.serverCertPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.serverKeyPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.realm = "estreal";
        config.verbose = true;
        config.tcpPort = 8443;
        config.estTRUSTEDCerts = ESTServerUtils.makeRelativeToServerHome("trustedcerts.crt").getCanonicalPath();
        config.estCACERTSResp = ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt").getCanonicalPath();

        //
        // Mock up some Attributes, this not a real attribute.!
        //
        config.estCSRAttr = Base64.toBase64String(new CsrAttrs(new AttrOrOID(new ASN1ObjectIdentifier("1.2.3.4"))).getEncoded());

        return ESTServerUtils.startServer(config);

    }


    public void performTest()
        throws Exception
    {
        ESTTestUtils.runJUnit(TestGetCSRAttrs.class);
    }


    /**
     * Test the fetching of CSRAttributes.
     * This test confirms it is possible to fetch attributes and that we get an attribute back.
     * Variation on authentication is verified in other tests.
     *
     * @throws Exception
     */
    @Test
    public void testFetchCSRAttributes()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try
        {
            serverInstance = startDefaultServer();

            ESTService est = new JcaESTServiceBuilder(
                "https://localhost:8443/.well-known/est/",
                ESTTestUtils.toTrustAnchor(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    ))
            ).build();

            ESTService.CSRRequestResponse csrRequestResponse = est.getCSRAttributes();
            Assert.assertEquals( 1,csrRequestResponse.getAttributesResponse().getRequirements().size());
            Assert.assertTrue("Must have: ",
                csrRequestResponse.getAttributesResponse().hasRequirement(new ASN1ObjectIdentifier("1.2.3.4")));
        }
        finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }

    }


    public static void main(String[] args)
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        runTest(new TestGetCSRAttrs());
    }
}
