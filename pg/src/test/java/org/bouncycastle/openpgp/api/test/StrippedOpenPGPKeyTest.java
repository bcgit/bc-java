package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPKeyReader;

import java.io.IOException;

public class StrippedOpenPGPKeyTest
        extends APITest
{

    @Override
    protected void performTestWith(OpenPGPApi api)
            throws PGPException, IOException
    {
        // Adapted test case from https://github.com/bcgit/bc-java/issues/2173
        // Credit for test vectors to @agrahn
        OpenPGPKeyReader reader = api.readKeyOrCertificate();
        OpenPGPKey strippedKey = reader.parseKey(
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" +
                        "lDsEaNz9VhYJKwYBBAHaRw8BAQdANvkQp6G9vVPUtxHplmw44lclTAm2vSqREnfi\n" +
                        "bsqmDDP/AGUAR05VAbQfQm9iIFVzZXIgPGJvYi51c2VyQGV4YW1wbGUub3JnPoiT\n" +
                        "BBMWCgA7FiEE81kLNGDerGMA7okHMcFP0Qqg/SwFAmjc/VYCGwEFCwkIBwICIgIG\n" +
                        "FQoJCAsCBBYCAwECHgcCF4AACgkQMcFP0Qqg/Szv3AEA5Q0S6UrHI6YC9IqCV86Z\n" +
                        "xF7zegeUJiTGfbIMmp+7qk4BAIJBZyfpsutfdnLBmXMQmPPvdlfNZ0H781sm4vq4\n" +
                        "1KkFnIsEaNz9pRIKKwYBBAGXVQEFAQEHQLilfhrcbzI6XI7a+HbOfqNj/9cwZk8s\n" +
                        "O4H/4IMhY7ZZAwEIB/4HAwIpPDPOpRpcw//ZZTsMuT5ZRDGnSA+3i34NWnhv50ex\n" +
                        "yf51MgrvY+E3NaE9ObFfvEJILF8kub206yaQRbHWPrj7fU1C+DKJ9AbDcXZmzu/U\n" +
                        "iHgEGBYKACAWIQTzWQs0YN6sYwDuiQcxwU/RCqD9LAUCaNz9pQIbDAAKCRAxwU/R\n" +
                        "CqD9LCNSAP9v7GminBOFV8XkMsL4T+0P0woGjTZxUrYKKVR98NhXswEAhDfkQh0n\n" +
                        "IyhOyHwzLuoGJ31M7a1rtB44tcJNtnP6XQQ=\n" +
                        "=jquc\n" +
                        "-----END PGP PRIVATE KEY BLOCK-----\n");

        OpenPGPKey.OpenPGPSecretKey secKey = strippedKey.getPrimarySecretKey();

        boolean isCorrect = secKey.isPassphraseCorrect(("12345678").toCharArray());
        isFalse("Expected false when checking passphrase of stripped secret key", isCorrect);
    }

    @Override
    public String getName()
    {
        return "StrippedOpenPGPKeyTest";
    }

    public static void main(String[] args)
    {
        runTest(new StrippedOpenPGPKeyTest());
    }
}
