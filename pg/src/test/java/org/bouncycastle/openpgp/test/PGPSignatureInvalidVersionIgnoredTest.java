package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class PGPSignatureInvalidVersionIgnoredTest
        extends SimpleTest
{

    // Signing Key ID
    private static final long KEY_ID = new BigInteger("FBFCC82A015E7330", 16).longValue();

    // Signature List consisting of Version 4 Signature and Version 23 (invalid version) Signature
    private static final String SIG4SIG23 = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "wsE7BAABCgBvBYJgyf2fCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
            "cy5zZXF1b2lhLXBncC5vcmdURSYEGurWv1IDN4trcpgfrHMZeGRdhG5jlQazr8tJ\n" +
            "QRYhBNGmbhojsYLJmA94jPv8yCoBXnMwAADAYwv+NeSzVRrR/CGLMna43b0xCrOz\n" +
            "tEYVp3hLzjCYWP1F5d7OdrpQWB3jzgMhjkH5ZnSm369A6D6eEoo05uP7lUNoex7s\n" +
            "Bcksq4QF2t9y0YHwjhciVyPUw0rgzOIDpJ6jb/HqEgWB+EYz5qU3RFAk4tz+ghpw\n" +
            "93x+EAI7QBnw+PRjgmJiXQvcq78W+h8aysAQCv/dNJc9W8gfCpwDY2VKTc0BW9VI\n" +
            "R4KbeI2Rgx378JYjzJNP9ORgDTacBdQh3LiqJ8B4x7OeVGouGbWEVG6x+htQ9YMH\n" +
            "uOY1CmcNzoMSRyk50JOeM0Xcge/9PLuQM+b4OQ3ZRN/BhUEg4P/VclXzkWeDKCvP\n" +
            "cGEUrdFnyU1Lk2mYh1HTKS3gurTP9bdAyS9sdjXj9kv2fRM5N46rBRAffjwfW/LT\n" +
            "VedvgRZ3RMCLrwPo90ID/xVU8PC9VmBR+WrqOijdsgnh7n940NR5hSyeWVeMwNFl\n" +
            "Js043gKSIc5yNLS16mE/YzgosnUpIUsDlSR6D8M/wsE7FwABCgBvBYJgyf2fCRD7\n" +
            "/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdU\n" +
            "RSYEGurWv1IDN4trcpgfrHMZeGRdhG5jlQazr8tJQRYhBNGmbhojsYLJmA94jPv8\n" +
            "yCoBXnMwAADAYwv+NeSzVRrR/CGLMna43b0xCrOztEYVp3hLzjCYWP1F5d7OdrpQ\n" +
            "WB3jzgMhjkH5ZnSm369A6D6eEoo05uP7lUNoex7sBcksq4QF2t9y0YHwjhciVyPU\n" +
            "w0rgzOIDpJ6jb/HqEgWB+EYz5qU3RFAk4tz+ghpw93x+EAI7QBnw+PRjgmJiXQvc\n" +
            "q78W+h8aysAQCv/dNJc9W8gfCpwDY2VKTc0BW9VIR4KbeI2Rgx378JYjzJNP9ORg\n" +
            "DTacBdQh3LiqJ8B4x7OeVGouGbWEVG6x+htQ9YMHuOY1CmcNzoMSRyk50JOeM0Xc\n" +
            "ge/9PLuQM+b4OQ3ZRN/BhUEg4P/VclXzkWeDKCvPcGEUrdFnyU1Lk2mYh1HTKS3g\n" +
            "urTP9bdAyS9sdjXj9kv2fRM5N46rBRAffjwfW/LTVedvgRZ3RMCLrwPo90ID/xVU\n" +
            "8PC9VmBR+WrqOijdsgnh7n940NR5hSyeWVeMwNFlJs043gKSIc5yNLS16mE/Yzgo\n" +
            "snUpIUsDlSR6D8M/\n" +
            "=Ptch\n" +
            "-----END PGP SIGNATURE-----";

    // Signature List consisting of Version 23 (invalid version) Signature and Version 4 Signature
    private static final String SIG23SIG4 = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "wsE7FwABCgBvBYJgyf2fCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
            "cy5zZXF1b2lhLXBncC5vcmdURSYEGurWv1IDN4trcpgfrHMZeGRdhG5jlQazr8tJ\n" +
            "QRYhBNGmbhojsYLJmA94jPv8yCoBXnMwAADAYwv+NeSzVRrR/CGLMna43b0xCrOz\n" +
            "tEYVp3hLzjCYWP1F5d7OdrpQWB3jzgMhjkH5ZnSm369A6D6eEoo05uP7lUNoex7s\n" +
            "Bcksq4QF2t9y0YHwjhciVyPUw0rgzOIDpJ6jb/HqEgWB+EYz5qU3RFAk4tz+ghpw\n" +
            "93x+EAI7QBnw+PRjgmJiXQvcq78W+h8aysAQCv/dNJc9W8gfCpwDY2VKTc0BW9VI\n" +
            "R4KbeI2Rgx378JYjzJNP9ORgDTacBdQh3LiqJ8B4x7OeVGouGbWEVG6x+htQ9YMH\n" +
            "uOY1CmcNzoMSRyk50JOeM0Xcge/9PLuQM+b4OQ3ZRN/BhUEg4P/VclXzkWeDKCvP\n" +
            "cGEUrdFnyU1Lk2mYh1HTKS3gurTP9bdAyS9sdjXj9kv2fRM5N46rBRAffjwfW/LT\n" +
            "VedvgRZ3RMCLrwPo90ID/xVU8PC9VmBR+WrqOijdsgnh7n940NR5hSyeWVeMwNFl\n" +
            "Js043gKSIc5yNLS16mE/YzgosnUpIUsDlSR6D8M/wsE7BAABCgBvBYJgyf2fCRD7\n" +
            "/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdU\n" +
            "RSYEGurWv1IDN4trcpgfrHMZeGRdhG5jlQazr8tJQRYhBNGmbhojsYLJmA94jPv8\n" +
            "yCoBXnMwAADAYwv+NeSzVRrR/CGLMna43b0xCrOztEYVp3hLzjCYWP1F5d7OdrpQ\n" +
            "WB3jzgMhjkH5ZnSm369A6D6eEoo05uP7lUNoex7sBcksq4QF2t9y0YHwjhciVyPU\n" +
            "w0rgzOIDpJ6jb/HqEgWB+EYz5qU3RFAk4tz+ghpw93x+EAI7QBnw+PRjgmJiXQvc\n" +
            "q78W+h8aysAQCv/dNJc9W8gfCpwDY2VKTc0BW9VIR4KbeI2Rgx378JYjzJNP9ORg\n" +
            "DTacBdQh3LiqJ8B4x7OeVGouGbWEVG6x+htQ9YMHuOY1CmcNzoMSRyk50JOeM0Xc\n" +
            "ge/9PLuQM+b4OQ3ZRN/BhUEg4P/VclXzkWeDKCvPcGEUrdFnyU1Lk2mYh1HTKS3g\n" +
            "urTP9bdAyS9sdjXj9kv2fRM5N46rBRAffjwfW/LTVedvgRZ3RMCLrwPo90ID/xVU\n" +
            "8PC9VmBR+WrqOijdsgnh7n940NR5hSyeWVeMwNFlJs043gKSIc5yNLS16mE/Yzgo\n" +
            "snUpIUsDlSR6D8M/\n" +
            "=o4rJ\n" +
            "-----END PGP SIGNATURE-----";

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPSignatureInvalidVersionIgnoredTest());
    }
    
    public String getName()
    {
        return "PGPSignatureInvalidVersionIgnoredTest";
    }

    public void performTest() throws Exception
    {
        assertInvalidSignatureVersionIsIgnored(SIG4SIG23);
        assertInvalidSignatureVersionIsIgnored(SIG23SIG4);
    }

    private void assertInvalidSignatureVersionIsIgnored(String SIG)
            throws IOException
    {
        ArmoredInputStream armorIn = new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(SIG)));
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        PGPSignatureList signatures = (PGPSignatureList) objectFactory.nextObject();
        isEquals(1, signatures.size());
        PGPSignature signature = signatures.get(0);
        isEquals(KEY_ID, signature.getKeyID());
    }
}
