package org.bouncycastle.crypto.test;

import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class BigSkippingCipherTest
    extends TestCase
{
    public void testAESCTR()
        throws Exception
    {
        CipherParameters externalCounterParams = new ParametersWithIV(new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")), Hex.decode("00000000000000000000000000000000"));
        CipherParameters internalCounterParams = new ParametersWithIV(new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")), Hex.decode("00000000000000000000"));
        SICBlockCipher linearEngine = new SICBlockCipher(new AESEngine());
        SICBlockCipher skippingEngine = new SICBlockCipher(new AESEngine());
        Random random = new Random();

        linearEngine.init(true, externalCounterParams);
        skippingEngine.init(false, internalCounterParams);

        testCipher(random, linearEngine, skippingEngine);

        byte[] in = Base64.decode("pzVbCyj5JntIYN2Kvzf64/po+gTu/jvnZwU33F7UsfxpWRUDEGIQbArxqCQzEkGAwa4omXJ28WJveJNUQbQ5cBxS2aTt3sV0mrP+cneJ3OZkzo5Lhz0vuXs7Mav9uUzQFrU0DuMyGr1QJnKO0BUal0gLJ0v6YAo2SObDS5A4CTrsAgo0C2UXQmnuGzyYlhm4VoSNotD8auqyQXUrT8c2B/tLIcjyyl8ug1BabL2gAxN7oKbpvW5j2z3IZNZh+AKR4OR47RfjtYglOfgGQB1L5yiL9reuWEsRjbZmcEFfLmAAK0gtcP+0KDXV/DS4NxRx0sC7NkBzSC3uq2RbQOdjygFZ5qrmvwQZgLqlXs2cGiNzqx5CRjAvl83aAWAAerR5T2sHadRckW01oE2ivQixpgdPCGFHLeXoPMlkZ/r1cECYFAGPjMGSG2qnQZ/ZJbStEAZye/11r/dyoUgP+XTc6FDCCQHSdmyQljPHDQm7ioMTTkCf15YWv0kSuKOd4nBlLrGjSl9dsJsVU9TDRCqNExmk+lN3f0p8vr8TVNnir+OtEabOXzjOv6i3PHQZP27ML3Hy9TU1MHx1Q0bLdgi6yIw8lmzzBzok8j5VrCpNf2HmBqtRm1WDeTO9R62OWyaMT/dCT7AzEzP8ClBSq57p69OrlEDoaLXrYvNS3hEw1Lo=");
        byte[] exp = Base64.decode("JD0KPwMaKvqYZnDgI0rFTCbexg+RRj3UbEPtsf5IDeM3lb5OJ5EMLHXrfknu//XNLE6dV/Jaoz3LuylkfRlMg2/Vvgo6KwXNV3VsUgkEmTpy74NAd9DCh+1EgJYCNbHkT/haaKpPWLqHEIp1/LVKZZgRXc+C4kH02GzqwYkjUZCSrE8GBpiILlHhN+2A14Ltmxe7XZrlnOQx62sBoh+QR2ZCSAhQjMayhnkrIC1qpM8S4vcZbAYOGuVRcmBhGZdvQg+YXUKrx3FS6XS+xF3yMld5iVx2aEzjkmXuDoULLzrppD/5Ed0I2CCFZigBZ3ZFsOGIZw1yTBXLRVroM/xksYaGgQs9arKB3rEBpUV4yUMuYokqz9A4k7jg/6loTFU8SntBzXptrPuKPbEMT/FvJqEsI3yKCndYiRAkTRmHWhNmdjLH9Pw32VYlpbjYzQjPP6Iy055VujucBofsP3/ENK32XNs1I6PzcVrjjRJaBy3dbAB0e7/P7cqnUvKu+dSR7N92VnuDtCaS5ksVMWJOlfLhqLq8umz8+3aIsTj20bfNGzf4aeqkUzv+AezQedVY3gmYBgwv/1ZR3Y9bUATE4ieIwK+gkZBgtANOs2abY+8+of5sQhyfYiWpUrSb+L/7MjaFgBz+b69bD5xl0kes/ySVGBqaqG4jcOr01qGfaLw=");
        byte[] buf = new byte[512];

        skippingEngine.seekTo(1L << 38);

        skippingEngine.processBytes(in, 0, in.length, buf, 0);

        if (!Arrays.areEqual(buf, exp))
        {
            fail("long seek failed");
        }

        skippingEngine.skip(-(1L << 38) - 512);

        if (skippingEngine.getPosition() != 0)
        {
            fail("zero position came back as: " + skippingEngine.getPosition());
        }

        random.nextBytes(buf);

        byte[] linOut = new byte[512];
        byte[] skipOut = new byte[512];

        linearEngine.init(true, internalCounterParams);

        linearEngine.processBytes(buf, 0, buf.length, linOut, 0);
        skippingEngine.processBytes(buf, 0, buf.length, skipOut, 0);

        if (!Arrays.areEqual(linOut, skipOut))
        {
            fail("long output mismatch");
        }
    }

    public void testSalsa20()
        throws Exception
    {
        CipherParameters params = new ParametersWithIV(new KeyParameter(Hex.decode("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D")), Hex.decode("0D74DB42A91077DE"));
        Salsa20Engine linearEngine = new Salsa20Engine();
        Salsa20Engine skippingEngine = new Salsa20Engine();
        Random random = new Random();

        linearEngine.init(true, params);
        skippingEngine.init(false, params);

        testCipher(random, linearEngine, skippingEngine);

        byte[] in = Base64.decode("pzVbCyj5JntIYN2Kvzf64/po+gTu/jvnZwU33F7UsfxpWRUDEGIQbArxqCQzEkGAwa4omXJ28WJveJNUQbQ5cBxS2aTt3sV0mrP+cneJ3OZkzo5Lhz0vuXs7Mav9uUzQFrU0DuMyGr1QJnKO0BUal0gLJ0v6YAo2SObDS5A4CTrsAgo0C2UXQmnuGzyYlhm4VoSNotD8auqyQXUrT8c2B/tLIcjyyl8ug1BabL2gAxN7oKbpvW5j2z3IZNZh+AKR4OR47RfjtYglOfgGQB1L5yiL9reuWEsRjbZmcEFfLmAAK0gtcP+0KDXV/DS4NxRx0sC7NkBzSC3uq2RbQOdjygFZ5qrmvwQZgLqlXs2cGiNzqx5CRjAvl83aAWAAerR5T2sHadRckW01oE2ivQixpgdPCGFHLeXoPMlkZ/r1cECYFAGPjMGSG2qnQZ/ZJbStEAZye/11r/dyoUgP+XTc6FDCCQHSdmyQljPHDQm7ioMTTkCf15YWv0kSuKOd4nBlLrGjSl9dsJsVU9TDRCqNExmk+lN3f0p8vr8TVNnir+OtEabOXzjOv6i3PHQZP27ML3Hy9TU1MHx1Q0bLdgi6yIw8lmzzBzok8j5VrCpNf2HmBqtRm1WDeTO9R62OWyaMT/dCT7AzEzP8ClBSq57p69OrlEDoaLXrYvNS3hEw1Lo=");
        byte[] exp = Base64.decode("e0bdyXVHsxzA9pZ/htVVPAsAgief6pEyLmdayG09N3GkBZFulTze/He524ETzTGtV7c1yGypTwjwVr+rNWmZs9YeXtYljySAQUbv1il5spmn7+iiwN6H21Keg6r4ciwzR7jhm7Wc0A1GGkh8OLmb2ZAh/fNDXHyL8mbEmLYh5C9n+DCTruTEjtS5TwueaRsUSNkexUgemqOVHxeOD0nZcVARr2AzMW6btNrQycol3+WTvLmbCeAZwcZnfPvZeU3r2UF73o8lP0vOUrOi095H2WZkJIVrAiV/+i4Sb76XXRgFlvWP6RbX9mYApIBhs69+yxp8lmVI0AABAwwV7PNXo+1UK6kzNi5spa32MRDMogP+wDHMyu8nHzLpIv9OTx0CmkZ0XO4Lla3d3UsPGq8g50a6gfrSOa9JHYFjfMzqIY/6SdZxr39Z8jVYiCfWGYplMTSDvfj3whk2J0DnSSdf6k6JstCjIXeMagKjwpcf9r0kq1Q9mAGhdJLqkM2LYHz3CP6GiWbGy5477GKnrhFDOeG1PtLv4YaTLrrjnNngIeeMK0tgkwBhsobVCD1hSs26I9/V+rdFhFb3/a/ob37cfnPmflbC0oOpSKoY6tZEaDp9u2ulNCpLYV6zrn3k9soP4q+sfsmXKMuWU2+rJGvBOEPh9Jo8Z+u7r+1PG+8VgAs=");
        byte[] buf = new byte[512];

        skippingEngine.seekTo(1L << 38);

        skippingEngine.processBytes(in, 0, in.length, buf, 0);

        if (!Arrays.areEqual(buf, exp))
        {
            fail("long seek failed");
        }

        skippingEngine.skip(-(1L << 38) - 512);

        if (skippingEngine.getPosition() != 0)
        {
            fail("zero position came back as: " + skippingEngine.getPosition());
        }

        random.nextBytes(buf);

        byte[] linOut = new byte[512];
        byte[] skipOut = new byte[512];

        linearEngine.init(true, params);

        linearEngine.processBytes(buf, 0, buf.length, linOut, 0);
        skippingEngine.processBytes(buf, 0, buf.length, skipOut, 0);

        if (!Arrays.areEqual(linOut, skipOut))
        {
            fail("long output mismatch");
        }
    }

    public void testChaCha()
        throws Exception
    {
        CipherParameters params = new ParametersWithIV(new KeyParameter(Hex.decode("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D")), Hex.decode("0D74DB42A91077DE"));
        ChaChaEngine linearEngine = new ChaChaEngine();
        ChaChaEngine skippingEngine = new ChaChaEngine();
        Random random = new Random();

        linearEngine.init(true, params);
        skippingEngine.init(false, params);

        testCipher(random, linearEngine, skippingEngine);

        byte[] in = Base64.decode("pzVbCyj5JntIYN2Kvzf64/po+gTu/jvnZwU33F7UsfxpWRUDEGIQbArxqCQzEkGAwa4omXJ28WJveJNUQbQ5cBxS2aTt3sV0mrP+cneJ3OZkzo5Lhz0vuXs7Mav9uUzQFrU0DuMyGr1QJnKO0BUal0gLJ0v6YAo2SObDS5A4CTrsAgo0C2UXQmnuGzyYlhm4VoSNotD8auqyQXUrT8c2B/tLIcjyyl8ug1BabL2gAxN7oKbpvW5j2z3IZNZh+AKR4OR47RfjtYglOfgGQB1L5yiL9reuWEsRjbZmcEFfLmAAK0gtcP+0KDXV/DS4NxRx0sC7NkBzSC3uq2RbQOdjygFZ5qrmvwQZgLqlXs2cGiNzqx5CRjAvl83aAWAAerR5T2sHadRckW01oE2ivQixpgdPCGFHLeXoPMlkZ/r1cECYFAGPjMGSG2qnQZ/ZJbStEAZye/11r/dyoUgP+XTc6FDCCQHSdmyQljPHDQm7ioMTTkCf15YWv0kSuKOd4nBlLrGjSl9dsJsVU9TDRCqNExmk+lN3f0p8vr8TVNnir+OtEabOXzjOv6i3PHQZP27ML3Hy9TU1MHx1Q0bLdgi6yIw8lmzzBzok8j5VrCpNf2HmBqtRm1WDeTO9R62OWyaMT/dCT7AzEzP8ClBSq57p69OrlEDoaLXrYvNS3hEw1Lo=");
        byte[] exp = Base64.decode("FACFDKSYxFYEOknCBPdfy5elbrDu8FzOImwpczlIk1HWlcbBPHXwHEnVaKrGtmthC7gA1DQJSeobO83KW3YZVkT8fcGnMFbeee6ISs9R4KqekE+Fs8uNWYlqsgT5xrErOC/cmz4B5envQx7EZK5h+fJupYO3vHqVk5/Q6c/v8ndDeBKSDTKA6eyybOwFVIjwJKPfuliu4mJGHphUIsp/OgRPs+VhlMrWXMVwsGzGHy9xZvTz6Xv6GJvrIoONMHh24YGOSt+83cFTepU7ur8anyDaoWzMz/n04eopnQd9TlREwYOZWdF0ZAJ0VZQYEixopmH+mlEZ/Nyw6IDswvyX3Zf/7lyDsM8bv2kz1gXvmQgUMqr6wXrOuJtxaH8aUvLVswCeNZEGFl17FHgwdD2MRzkmhfPRFlTgicd02D/ateBs5B0ORu5CKu3p/RGjU4YE68ONPNEkwkBRm5uGzdezTJmUzdJAEtoIxv1XfE1tytP7U+BpWdP5LY5NlEUo6sNR4O2nlSQJkAOzhoz821hnn1IL6r9DLDHIW40IhStDqc5Hy/8rEZgnnFhIE6pAD1PAGV5oJk/Z/V64bFvGkpD7xuhN5U2Eic7UheB8D227JtQQWTc8GhynlOWbmkYm/koKw+ieraN5IWE/KD2HFqJhxasB9lb3lMGh3zfgBKck5Lo=");
        byte[] buf = new byte[512];

        skippingEngine.seekTo(1L << 38);

        skippingEngine.processBytes(in, 0, in.length, buf, 0);

        if (!Arrays.areEqual(buf, exp))
        {
            fail("long seek failed");
        }

        skippingEngine.skip(-(1L << 38) - 512);

        if (skippingEngine.getPosition() != 0)
        {
            fail("zero position came back as: " + skippingEngine.getPosition());
        }

        random.nextBytes(buf);

        byte[] linOut = new byte[512];
        byte[] skipOut = new byte[512];

        linearEngine.init(true, params);

        linearEngine.processBytes(buf, 0, buf.length, linOut, 0);
        skippingEngine.processBytes(buf, 0, buf.length, skipOut, 0);

        if (!Arrays.areEqual(linOut, skipOut))
        {
            fail("long output mismatch");
        }
    }

    public void testCipher(Random random, SkippingStreamCipher linearEngine, SkippingStreamCipher skippingEngine)
        throws Exception
    {
        byte[] startDataBuf = new byte[1 << 16];
        byte[] startEncBuf = new byte[1 << 16];
        byte[] startSeekBuf = new byte[1 << 16];

        random.nextBytes(startDataBuf);

        linearEngine.processBytes(startDataBuf, 0, startDataBuf.length, startEncBuf, 0);

        byte[] incBuf = new byte[1 << 12];
        byte[] linearOutBuf = new byte[1 << 12];
        byte[] seekOutBuf = new byte[1 << 12];

        for (long i = 0; i != 1L << 20; i++)
        {
            random.nextBytes(incBuf);

            linearEngine.processBytes(incBuf, 0, incBuf.length, linearOutBuf, 0);

            skippingEngine.seekTo(startDataBuf.length + i * incBuf.length);

            if (skippingEngine.getPosition() != startDataBuf.length + i * incBuf.length)
            {
                fail(i + "th position came back as: " + skippingEngine.getPosition());
            }

            skippingEngine.processBytes(incBuf, 0, incBuf.length, seekOutBuf, 0);

            if (!Arrays.areEqual(linearOutBuf, seekOutBuf))
            {
                fail("output mismatch");
            }

            if (skippingEngine.getPosition() != startDataBuf.length + (i + 1) * incBuf.length)
            {
                fail(i + "th + 1 position came back as: " + skippingEngine.getPosition());
            }

            skippingEngine.skip(-skippingEngine.getPosition());

            if (skippingEngine.getPosition() != 0)
            {
                fail("zero position came back as: " + skippingEngine.getPosition());
            }

            skippingEngine.processBytes(startEncBuf, 0, startEncBuf.length, startSeekBuf, 0);

            if (!Arrays.areEqual(startDataBuf, startSeekBuf))
            {
                fail("output mismatch");
            }
        }
    }
}
