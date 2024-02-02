package org.bouncycastle.mozilla.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mozilla.jcajce.JcaSignedPublicKeyAndChallenge;
import org.bouncycastle.test.GeneralTest;

public class MozillaGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        MozillaGeneralTest test = new MozillaGeneralTest();
        test.setUp();
        test.testSpkac();
    }

    public void testSpkac()
        throws Exception
    {
        byte[] req = SPKACTest.spkac;
        JcaSignedPublicKeyAndChallenge spkac = new JcaSignedPublicKeyAndChallenge(req);
        spkac.setProvider(new BouncyCastleProvider());
        assertEquals("", spkac.getChallenge());
        assertNotNull(spkac.getEncoded());
    }
}
