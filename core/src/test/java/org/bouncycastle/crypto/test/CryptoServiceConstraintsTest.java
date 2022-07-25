package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.util.Collections;

import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint;
import org.bouncycastle.crypto.constraints.LegacyBitsOfSecurityConstraint;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class CryptoServiceConstraintsTest
    extends SimpleTest
{
    public String getName()
    {
        return "CryptoServiceConstraintsTest";
    }

    public void performTest()
        throws Exception
    {
        test112bits();
        test128bits();
        testLegacy128bits();
        test1024bitDSA();
    }

    private void test112bits()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(112));

        try
        {
            new RC4Engine();
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 20", e.getMessage());
        }

        // try with exception for RC4/ARC4
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(112, Collections.singleton("ARC4")));

        new RC4Engine();

        try
        {
            new DESEngine();
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 56", e.getMessage());
        }

        new DESedeEngine();

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void test128bits()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new DESedeEngine();
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 112", e.getMessage());
        }

        // add exception for DESede
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128, Collections.singleton("DESede")));

        new DESedeEngine();

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testLegacy128bits()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128));

        DESedeEngine eng = new DESedeEngine();
        KeyParameter dKey = new KeyParameter(Hex.decode("01020304050607080102030405060708"));

        try
        {
            eng.init(true, dKey);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 112", e.getMessage());
        }

        eng.init(false, dKey);     // this should work as we are decrypting

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void test1024bitDSA()
    {
        BigInteger p = new BigInteger(
            "17801190547854226652823756245015999014523215636912067427327445031"
            + "444286578873702077061269525212346307956715678477846644997065077092072"
            + "785705000966838814403412974522117181850604723115003930107995935806739"
            + "534871706631980226201971496652413506094591370759495651467285569060679"
            + "4135837542707371727429551343320695239");
        BigInteger q = new BigInteger("864205495604807476120572616017955259175325408501");
        BigInteger g = new BigInteger(
            "17406820753240209518581198012352343653860449079456135097849583104"
            + "059995348845582314785159740894095072530779709491575949236830057425243"
            + "876103708447346718014887611810308304375498519098347260155049469132948"
            + "808339549231385000036164648264460849230407872181895999905649609776936"
            + "8017749273708962006689187956744210730");
        BigInteger x = new BigInteger("774290984479563168206130828532207106685994961942");
        BigInteger y = new BigInteger(
            "11413953692062257086993806233172330674938775529337393031977771373"
            + "129746946910914240113023221721777732136818444139744393157698465044933"
            + "013442758757568273862367115354816009554808091206304096963365266649829"
            + "966917085474283297375073085459703201287235180005340124397005934806133"
            + "1526243448471205166130497310892424132");

        DSAPublicKeyParameters pk = new DSAPublicKeyParameters(y, new DSAParameters(p, q, g));
        DSAPrivateKeyParameters sk = new DSAPrivateKeyParameters(x, new DSAParameters(p, q, g));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128));
        
        DSASigner signer = new DSASigner();

        try
        {
            signer.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 80", e.getMessage());
        }

        // legacy usage allowed for verification.
        signer.init(false, pk);
        
        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    public static void main(
         String[] args)
     {
         runTest(new CryptoServiceConstraintsTest());
     }
}
