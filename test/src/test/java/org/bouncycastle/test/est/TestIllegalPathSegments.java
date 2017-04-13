package org.bouncycastle.test.est;


import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.JsseESTServiceBuilder;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Test;

public class TestIllegalPathSegments
    extends SimpleTest
{
    public String getName()
    {
        return "TestIllegalPathSegments";
    }

    public void performTest()
        throws Exception
    {
        ESTTestUtils.runJUnit(TestIllegalPathSegments.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPathSegment_4800()
        throws Exception
    {
        JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
            "//127.0.0.1:23456", JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            )), null));
        builder.withLabel("cacerts");
        ESTService est = builder.build();
    }


    @Test(expected = IllegalArgumentException.class)
    public void testPathSegment_4801()
        throws Exception
    {
        JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
            "127.0.0.1:23456", JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            )), null));

        builder.withLabel("csrattrs");
        ESTService est = builder.build();
    }


    @Test(expected = IllegalArgumentException.class)
    public void testPathSegment_4802()
        throws Exception
    {
        JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
            "127.0.0.1:23456", JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            )), null));
        builder.withLabel("simpleenroll");
        ESTService est = builder.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPathSegment_4803()
        throws Exception
    {
        JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
            "127.0.0.1:23456", JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            )), null));
        builder.withLabel("simplereenroll");
        ESTService est = builder.build();
    }


    @Test(expected = IllegalArgumentException.class)
    public void testPathSegment_4805()
        throws Exception
    {
        JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
            "127.0.0.1:23456", JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            )), null));

            builder.withLabel("invalid<>^");

        ESTService est = builder.build();
    }

    @Test
    public void testAllowsNumbers()
        throws Exception
    {
        JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
            "127.0.0.1:23456", JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            )), null));

        builder.withLabel("FAC51");

        builder.withLabel("Fac73");
        builder.build();
    }




}
