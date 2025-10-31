package org.bouncycastle.jcajce.provider.symmetric.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.symmetric.PBEPBKDF2;
import org.bouncycastle.jcajce.provider.symmetric.hkdf.HKDFParameterSpec;
import org.bouncycastle.jcajce.provider.symmetric.pbepbkdf2.PBEPBKDF2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KDF;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayInputStream;
import java.security.Security;

import static org.bouncycastle.util.Arrays.areEqual;

public class PBEPBKDF2Test
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
        KDF kdf = KDF.getInstance("PBKDF2WITH8BIT", "BC");
        //
        // RFC 3211 tests
        //
        char[] password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        byte[]  salt = Hex.decode("1234567878563412");

        PBEPBKDF2ParameterSpec spec = new PBEPBKDF2ParameterSpec(password, salt, 5, 64);

//        if (!areEqual((kdf.deriveKey("AES", spec).getEncoded()), Hex.decode("d1daa78615f287e6")))
        if (!areEqual(kdf.deriveData(spec), Hex.decode("d1daa78615f287e6")))
        {
            fail("64 test failed");
        }

        password = "All n-entities must communicate with other n-entities via n-1 entiteeheehees".toCharArray();
        spec = new PBEPBKDF2ParameterSpec(password, salt, 500, 192);


        if (!areEqual((kdf.deriveData(spec)), Hex.decode("6a8970bf68c92caea84a8df28510858607126380cc47ab2d")))
        {
            fail("192 test failed");
        }

        spec = new PBEPBKDF2ParameterSpec(password, salt, 60000, 192);
        if (!areEqual((kdf.deriveData(spec)), Hex.decode("29aaef810c12ecd2236bbcfb55407f9852b5573dc1c095bb")))
        {
            fail("192 (60000) test failed");
        }
    }
}
