package org.bouncycastle.pkcs.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SecretBag;
import org.bouncycastle.pkcs.PKCS12SecretBagBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.util.Strings;

public class PKCS12UtilTest
    extends TestCase
{
    private static final char[] passwd = "secret".toCharArray();

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testConvertToDefiniteLength_PBE_RoundTrips()
        throws Exception
    {
        byte[] pfxBytes = buildPfx(new BcPKCS12MacCalculatorBuilder()).getEncoded();

        byte[] derBytes = org.bouncycastle.pkcs.util.PKCS12Util
            .convertToDefiniteLength(pfxBytes, passwd, "BC");

        PKCS12PfxPdu pfx = new PKCS12PfxPdu(derBytes);
        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(
            new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"), passwd));
    }

    public void testConvertToDefiniteLength_PBMAC1_RoundTrips()
        throws Exception
    {
        BcPKCS12PBMac1CalculatorBuilder mac1Builder = new BcPKCS12PBMac1CalculatorBuilder(new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(Strings.toByteArray("saltsalt"), 1024, 256,
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256))),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512)));

        byte[] pfxBytes = buildPfx(mac1Builder).getEncoded();

        byte[] derBytes = org.bouncycastle.pkcs.util.PKCS12Util
            .convertToDefiniteLength(pfxBytes, passwd, "BC");

        PKCS12PfxPdu pfx = new PKCS12PfxPdu(derBytes);
        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(
            new JcePKCS12MacCalculatorBuilderProvider().setProvider("BC"), passwd));
    }

    public void testConvertToDefiniteLength_Idempotent()
        throws Exception
    {
        byte[] pfxBytes = buildPfx(new BcPKCS12MacCalculatorBuilder()).getEncoded();

        byte[] once = org.bouncycastle.pkcs.util.PKCS12Util
            .convertToDefiniteLength(pfxBytes, passwd, "BC");
        byte[] twice = org.bouncycastle.pkcs.util.PKCS12Util
            .convertToDefiniteLength(once, passwd, "BC");

        assertTrue(java.util.Arrays.equals(once, twice));
    }

    public void testDeprecatedClass_StillRejectsPBMAC1()
        throws Exception
    {
        BcPKCS12PBMac1CalculatorBuilder mac1Builder = new BcPKCS12PBMac1CalculatorBuilder(new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(Strings.toByteArray("saltsalt"), 1024, 256,
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256))),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512)));

        byte[] pfxBytes = buildPfx(mac1Builder).getEncoded();

        try
        {
            org.bouncycastle.jce.PKCS12Util.convertToDefiniteLength(pfxBytes, passwd, "BC");
            fail("deprecated PKCS12Util accepted PBMAC1");
        }
        catch (java.io.IOException e)
        {
            // expected: deprecated class wraps UnsupportedOperationException as
            // "error constructing MAC: ..."
            assertTrue("unexpected cause: " + e.getCause(),
                e.getCause() instanceof UnsupportedOperationException);
        }
    }

    private static PKCS12PfxPdu buildPfx(
        org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder macBuilder)
        throws Exception
    {
        PKCS12SecretBag secret = new PKCS12SecretBagBuilder(
            CMSAlgorithm.AES256_CBC, new DEROctetString(new byte[]{1, 2, 3, 4}))
            .build();
        PKCS12SafeBag bag = new PKCS12SafeBagBuilder(secret).build();

        PKCS12PfxPduBuilder builder = new PKCS12PfxPduBuilder();
        builder.addData(bag);

        return builder.build(macBuilder, passwd);
    }
}
