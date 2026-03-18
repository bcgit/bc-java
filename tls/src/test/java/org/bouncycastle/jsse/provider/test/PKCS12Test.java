package org.bouncycastle.jsse.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;

import java.io.*;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.Iterator;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.PKCS12StoreParameter;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Test;


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
    @Test
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

    public void importPBMAC1KeyStore()
        throws Exception
    {
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12-PBMAC1", ProviderUtils.PROVIDER_NAME_BCJSSE);
        ByteArrayInputStream inStream = new ByteArrayInputStream(PKCS12TestData._importPBMAC1);
        pkcs12.load(inStream, PASSWORD.toCharArray());
        Enumeration<String> en = pkcs12.aliases();
        int counter = 0;
        String[] aliases = new String[10];
        while (en.hasMoreElements())
        {
            aliases[counter] =  en.nextElement();
            counter += 1;
        }
        assertEquals(1,counter);
        assertEquals("PBMAC1_csharp_test",aliases[0]);
    }


    public void testRunAll() throws Exception
    {
        //System.out.println("running all PCS12 Tests for TLS");
        pbmac1();
        convertDefaultMacToPBMAC1();
        importPBMAC1KeyStore();
    }
}
