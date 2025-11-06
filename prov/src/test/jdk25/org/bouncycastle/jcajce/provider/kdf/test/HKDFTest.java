package org.bouncycastle.jcajce.provider.kdf.test;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jcajce.provider.kdf.hkdf.HKDFParameterSpec;

import javax.crypto.KDF;

import java.security.Security;

import static org.bouncycastle.util.Arrays.areEqual;

public class HKDFTest
        extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKDF()
            throws Exception
    {

        setUp();
        KDF kdfHkdf = KDF.getInstance("HKDF-SHA256", "BC");

        byte[] ikm = Hex.decode("c702e7d0a9e064b09ba55245fb733cf3");
        byte[] salt = Strings.toByteArray("The Cryptographic Message Syntax");
        byte[] info = Hex.decode("301b0609608648016503040106300e040c5c79058ba2f43447639d29e2");
        byte[] okm = Hex.decode("2124ffb29fac4e0fbbc7d5d87492bff3");
        byte[] genOkm;
        HKDFParameterSpec hkdfParams = new HKDFParameterSpec(ikm, salt, info);

        genOkm = kdfHkdf.deriveData(hkdfParams);

        if (!areEqual(genOkm, okm))
        {
            fail("HKDF failed generator test");
        }

        //TODO: make test for derived keys
//        kdfHkdf.deriveKey("AES", hkdfParams);

        //TODO: do we want users to initialize the digest?
        //KDF kdf = KDF.getInstance("HKDF", "BC");
        //kdf.init(new KDFParameter(new SHA1Digest()));
        //kdf.deriveData(hkdfParams);
    }
}
