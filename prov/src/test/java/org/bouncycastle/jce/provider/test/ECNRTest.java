package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class ECNRTest
    extends SimpleTest
{
    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom random = new FixedSecureRandom(
        new FixedSecureRandom.Source[] { new FixedSecureRandom.Data(k1), new FixedSecureRandom.Data(k2) });

    /**
     * X9.62 - 1998,<br>
     * J.3.2, Page 155, ECDSA over the field Fp<br>
     * an example with 239 bit prime
     */
    private void testECNR239bitPrime()
        throws Exception
    {
        BigInteger r = new BigInteger("308636143175167811492623515537541734843573549327605293463169625072911693");
        BigInteger s = new BigInteger("852401710738814635664888632022555967400445256405412579597015412971797143");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));
        
        SecureRandom k = new TestRandomBigInteger(kData);

        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec spec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
            new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
            spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
            spec);

        Signature           sgr = Signature.getInstance("SHA1withECNR", "BC");
        KeyFactory          f = KeyFactory.getInstance("ECDSA", "BC");

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };
        
        checkSignature(239, priKey, pubKey, sgr, k, message, r, s);
    }
    
    // -------------------------------------------------------------------------
    
    /**
     * X9.62 - 1998,<br>
     * Page 104-105, ECDSA over the field Fp<br>
     * an example with 192 bit prime
     */
    private void testECNR192bitPrime()
        throws Exception
    {
        BigInteger r  = new BigInteger("2474388605162950674935076940284692598330235697454145648371");
        BigInteger s  = new BigInteger("2997192822503471356158280167065034437828486078932532073836");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("dcc5d1f1020906df2782360d36b2de7a17ece37d503784af", 16));
        
        SecureRandom k = new TestRandomBigInteger(kData);

        X9ECParameters x9 = ECNamedCurveTable.getByName("prime192v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec spec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
            spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            curve.decodePoint(Hex.decode("0262B12D60690CDCF330BABAB6E69763B471F994DD702D16A5")), // Q
            spec);

        Signature           sgr = Signature.getInstance("SHA1withECNR", "BC");
        KeyFactory          f = KeyFactory.getInstance("ECDSA", "BC");

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };
        
        checkSignature(192, priKey, pubKey, sgr, k, message, r, s);
    }
    
    // -------------------------------------------------------------------------
    
    /**
     * SEC 2: Recommended Elliptic Curve Domain Parameters - September 2000,<br>
     * Page 17-19, Recommended 521-bit Elliptic Curve Domain Parameters over Fp<br>
     * an ECC example with a 521 bit prime and a 512 bit hash
     */
    private void testECNR521bitPrime()
        throws Exception
    {
        BigInteger r  = new BigInteger("1820641608112320695747745915744708800944302281118541146383656165330049339564439316345159057453301092391897040509935100825960342573871340486684575368150970954");
        BigInteger s  = new BigInteger("6358277176448326821136601602749690343031826490505780896013143436153111780706227024847359990383467115737705919410755190867632280059161174165591324242446800763");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("cdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16));
        
        SecureRandom k = new TestRandomBigInteger(kData);

        X9ECParameters x9 = ECNamedCurveTable.getByName("secp521r1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec spec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
            new BigInteger("5769183828869504557786041598510887460263120754767955773309066354712783118202294874205844512909370791582896372147797293913785865682804434049019366394746072023"), // d
            spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            curve.decodePoint(Hex.decode("02006BFDD2C9278B63C92D6624F151C9D7A822CC75BD983B17D25D74C26740380022D3D8FAF304781E416175EADF4ED6E2B47142D2454A7AC7801DD803CF44A4D1F0AC")), // Q
            spec);

        Signature           sgr = Signature.getInstance("SHA512withECNR", "BC");
        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };
        
        checkSignature(521, priKey, pubKey, sgr, k, message, r, s);
    }

    private void checkSignature(
        int size,
        ECPrivateKeySpec priKey, 
        ECPublicKeySpec pubKey, 
        Signature sgr,
        SecureRandom k, 
        byte[] message, 
        BigInteger r, 
        BigInteger s)
        throws Exception
    {
        KeyFactory          f = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey          sKey = f.generatePrivate(priKey);
        PublicKey           vKey = f.generatePublic(pubKey);

        sgr.initSign(sKey, k);

        sgr.update(message);

        byte[]  sigBytes = sgr.sign();

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail(size + " bit EC verification failed");
        }

        BigInteger[]  sig = derDecode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail(size + "bit"
                + ": r component wrong." + Strings.lineSeparator()
                + " expecting: " + r + Strings.lineSeparator()
                + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail(size + "bit"
                + ": s component wrong." + Strings.lineSeparator()
                + " expecting: " + s + Strings.lineSeparator()
                + " got      : " + sig[1]);
        }
    }

    protected BigInteger[] derDecode(
        byte[]  encoding)
        throws IOException
    {
        ByteArrayInputStream    bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream         aIn = new ASN1InputStream(bIn);
        ASN1Sequence            s = (ASN1Sequence)aIn.readObject();

        BigInteger[]            sig = new BigInteger[2];

        sig[0] = ((ASN1Integer)s.getObjectAt(0)).getValue();
        sig[1] = ((ASN1Integer)s.getObjectAt(1)).getValue();

        return sig;
    }

    public String getName()
    {
        return "ECNR";
    }

    public void performTest()
        throws Exception
    {
        testECNR192bitPrime();
        testECNR239bitPrime();
        testECNR521bitPrime();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ECNRTest());
    }
}
