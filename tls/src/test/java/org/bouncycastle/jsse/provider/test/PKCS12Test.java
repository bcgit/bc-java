package org.bouncycastle.jsse.provider.test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Provider;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;

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

public class PKCS12Test
    extends TestCase
{
    //private static final String _BC = BouncyCastleProvider.PROVIDER_NAME;
    private final static char[] _password = "hello world".toCharArray();
    private static byte[] _currentPKCS12Object = null;

    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

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
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12-PBM", ProviderUtils.PROVIDER_NAME_BCJSSE);
    }

    ///////////////////////////////////////////////////////////////////////////
    // This test will read in a PKCS12 object with the default MAC, we then
    // convert the MAC to PBMAC1 format.
    ///////////////////////////////////////////////////////////////////////////
    public void convertDefaultMacToPBMAC1()
        throws Exception
    {
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12-PBM", ProviderUtils.PROVIDER_NAME_BCJSSE);
        ByteArrayInputStream inStream = new ByteArrayInputStream(PKCS12TestData._non_PBMAC1_PKCS12);
        pkcs12.load(inStream, _password);

        PKCS12StoreParameter.PBMAC1WithPBKDF2Builder pbmacBuilder = PKCS12StoreParameter.pbmac1WithPBKDF2Builder();
        byte[] mSalt = new byte[20];
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        random.nextBytes(mSalt);
        pbmacBuilder.setSalt(mSalt);
        AlgorithmIdentifier macAlgorithm = pbmacBuilder.build();

        ByteArrayOutputStream outStream = new ByteArrayOutputStream ();
        PKCS12StoreParameter.Builder builder = PKCS12StoreParameter.builder(outStream, _password);
        builder.setMacAlgorithm(macAlgorithm);
        PKCS12StoreParameter storeParam = builder.build();
        pkcs12.store(storeParam);
        _currentPKCS12Object = outStream.toByteArray();
    }

    public void testRunAll() throws Exception
    {
        pbmac1();
        convertDefaultMacToPBMAC1();
    }

}
