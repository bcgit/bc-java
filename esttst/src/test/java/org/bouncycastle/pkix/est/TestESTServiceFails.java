package org.bouncycastle.pkix.est;


import junit.framework.TestCase;
import org.bouncycastle.est.BasicAuth;
import org.bouncycastle.est.ESTServiceBuilder;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Test;

import java.security.cert.TrustAnchor;
import java.util.Collections;


/**
 * Test illegal state exceptions are thrown when expected.
 */
public class TestESTServiceFails extends SimpleTest
{


    public String getName()
    {
        return "ESTServiceFails";
    }

    public void performTest() throws Exception
    {
        ESTTestUtils.runJUnit(TestESTServiceFails.class);
    }

    @Test(expected = IllegalStateException.class)
    public void testEmptyTrustAnchors() throws Exception
    {
        ESTServiceBuilder b = new JcaESTServiceBuilder("", Collections.<TrustAnchor>emptySet());
    }

    @Test(expected = IllegalStateException.class)
    public void testNullTrustAnchors() throws Exception
    {
        ESTServiceBuilder b = new JcaESTServiceBuilder("", Collections.<TrustAnchor>emptySet());
    }

    @Test
    public void testEnforceTrusting() throws Exception
    {
        ESTServiceBuilder b = new JcaESTServiceBuilder("");
        try
        {
            b.build().getCSRAttributes();
        } catch (Exception ex)
        {
            TestCase.assertEquals("Must be illegal state exception", IllegalStateException.class, ex.getClass());
        }

        try
        {
            b.build().simpleEnroll(null);
        } catch (Exception ex)
        {
            TestCase.assertEquals("Must be illegal state exception", IllegalStateException.class, ex.getClass());
        }


        try
        {
            b.build().simpleEnroll(false, null, null);
        } catch (Exception ex)
        {
            TestCase.assertEquals("Must be illegal state exception", IllegalStateException.class, ex.getClass());
        }

    }


}
