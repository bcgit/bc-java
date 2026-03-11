package org.bouncycastle.jsse.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.PKCS12StoreParameter;

import junit.framework.TestCase;

public class PKCS12Test
    extends TestCase
{
    private final static String PASSWORD = "hello world";

    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    ///////////////////////////////////////////////////////////////////////////
    // This simply tests whether we can obtain our revised PKCS12KeyStoreSpi
    ///////////////////////////////////////////////////////////////////////////
    public void pbmac1()
        throws Exception
    {
        KeyStore.getInstance("PKCS12-PBMAC1", ProviderUtils.PROVIDER_NAME_BCJSSE);
    }

    ///////////////////////////////////////////////////////////////////////////
    // This test will read in a PKCS12 object with the default MAC, we then
    // convert the MAC to PBMAC1 format.
    ///////////////////////////////////////////////////////////////////////////
    public void convertDefaultMacToPBMAC1()
        throws Exception
    {
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12-PBMAC1", ProviderUtils.PROVIDER_NAME_BCJSSE);
        ByteArrayInputStream inStream = new ByteArrayInputStream(PKCS12TestData._non_PBMAC1_PKCS12);
        pkcs12.load(inStream, PASSWORD.toCharArray());

        PKCS12StoreParameter.PBMAC1WithPBKDF2Builder pbmacBuilder = PKCS12StoreParameter.pbmac1WithPBKDF2Builder();
        byte[] mSalt = new byte[20];
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        random.nextBytes(mSalt);
        pbmacBuilder.setSalt(mSalt);
        AlgorithmIdentifier macAlgorithm = pbmacBuilder.build();

        ByteArrayOutputStream outStream = new ByteArrayOutputStream ();
        PKCS12StoreParameter.Builder builder = PKCS12StoreParameter.builder(outStream, PASSWORD.toCharArray());
        builder.setMacAlgorithm(macAlgorithm);
        PKCS12StoreParameter storeParam = builder.build();
        pkcs12.store(storeParam);
        outStream.toByteArray();
    }

    public void testRunAll() throws Exception
    {
        pbmac1();
        convertDefaultMacToPBMAC1();
    }
}
