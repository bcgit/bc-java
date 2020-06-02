package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class ECEncodingTest
    extends SimpleTest
{
    public String getName()
    {
        return "ECEncodingTest";
    }

    /** J.4.7 An Example with m = 304 */
    private int m = 304;
    
    /** f = 010000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000807 */
    private int k1 = 1;
    private int    k2 = 2;
    private int    k3 = 11;
    private byte hexa[] = {(byte)0xFD, 0x0D, 0x69, 0x31, 0x49, (byte)0xA1, 0x18, (byte)0xF6, 0x51
        , (byte)0xE6, (byte)0xDC, (byte)0xE6, (byte)0x80, 0x20, (byte)0x85, 0x37, 0x7E, 0x5F, (byte)0x88, 0x2D, 0x1B, 0x51
        , 0x0B, 0x44, 0x16, 0x00, 0x74, (byte)0xC1, 0x28, (byte)0x80, 0x78, 0x36, 0x5A, 0x03
        , (byte)0x96, (byte)0xC8, (byte)0xE6, (byte)0x81};
    private byte hexb[] = {(byte)0xBD, (byte)0xDB, (byte)0x97, (byte)0xE5, (byte)0x55
        , (byte)0xA5, (byte)0x0A, (byte)0x90, (byte)0x8E, (byte)0x43, (byte)0xB0
        , (byte)0x1C, (byte)0x79, (byte)0x8E, (byte)0xA5, (byte)0xDA, (byte)0xA6
        , (byte)0x78, (byte)0x8F, (byte)0x1E, (byte)0xA2, (byte)0x79
        , (byte)0x4E, (byte)0xFC, (byte)0xF5, (byte)0x71, (byte)0x66, (byte)0xB8
        , (byte)0xC1, (byte)0x40, (byte)0x39, (byte)0x60, (byte)0x1E
        , (byte)0x55, (byte)0x82, (byte)0x73, (byte)0x40, (byte)0xBE};
    private BigInteger a = new BigInteger(1, hexa);
    private BigInteger b = new BigInteger(1, hexb);
    
    /** Base point G (with point compression) */
    private byte enc[] =    
    {0x02, 0x19, 0x7B, 0x07, (byte)0x84, 0x5E, (byte)0x9B, (byte)0xE2, (byte)0xD9, 0x6A, (byte)0xDB, 0x0F
            , 0x5F, 0x3C, 0x7F, 0x2C, (byte)0xFF, (byte)0xBD, 0x7A, 0x3E, (byte)0xB8, (byte)0xB6, (byte)0xFE, 
            (byte)0xC3, 0x5C, 0x7F, (byte)0xD6, 0x7F, 0x26, (byte)0xDD, (byte)0xF6
            , 0x28, 0x5A, 0x64, 0x4F, 0x74, 0x0A, 0x26, 0x14};
    
    private void testPointCompression() 
        throws Exception
    {
        ECCurve curve = new ECCurve.F2m(m, k1, k2, k3, a, b);
        curve.decodePoint(enc);
        
        int ks[] = new int[3];
        ks[0] = k3;
        ks[1] = k2;
        ks[2] = k1;
    }

    private void testPointCompressionProperty()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair kp = kpGen.generateKeyPair();

        byte[] enc1 = kp.getPublic().getEncoded();

        System.setProperty("org.bouncycastle.ec.enable_pc", "true");

        byte[] enc2 = kp.getPublic().getEncoded();

        isTrue(enc2.length == enc1.length - 32);

        System.setProperty("org.bouncycastle.ec.enable_pc", "false");

        byte[] enc3 = kp.getPublic().getEncoded();

        isTrue(areEqual(enc1, enc3));
    }
    
    public void performTest()
        throws Exception
    {
        byte[] ecParams = Hex.decode("3081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101");
        testParams(ecParams, true);
        
        testParams(ecParams, false);
        
        ecParams = Hex.decode("3081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C56E6C7E4F11A7B4B961A4DCB5BD282EB22E42E9BCBE3E7B361F18012041C4BE3E7B361F18012F2353D22975E02D8D05D2C6F3342DD8F57D4C76F0439048D127A0C27E0DE207ED3B7FB98F83C8BD5A2A57C827F4B97874DEB2C1BAEB0C006958CE61BB1FC81F5389E288CB3E86E2ED91FB47B08FCCA021D00D7C134AA264366862A18302575D11A5F7AABFBA3D897FF5CA727AF53020101");
        testParams(ecParams, true);
        
        testParams(ecParams, false);
        
        ecParams = Hex.decode("30820142020101303c06072a8648ce3d0101023100fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff3066043100fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc043100b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef046104aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f023100ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973020101");
        testParams(ecParams, true);
        
        testParams(ecParams, false);
        
        testPointCompression();
        testPointCompressionProperty();
    }
    
    private void testParams(byte[] ecParameterEncoded, boolean compress)
        throws Exception
    {
        String keyStorePass = "myPass";
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(
                ecParameterEncoded));
        X9ECParameters params = X9ECParameters.getInstance(in
                .readObject());
        KeyPair kp = null;
        boolean success = false;
        while (!success)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA");
            kpg.initialize(new ECParameterSpec(params.getCurve(),
                    params.getG(), params.getN(), params.getH(), params
                            .getSeed()));
            kp = kpg.generateKeyPair();
            // The very old Problem... we need a certificate chain to
            // save a private key...
            ECPublicKey pubKey = (ECPublicKey)kp.getPublic();
            if (!compress)
            {
                ((ECPointEncoder)pubKey).setPointFormat("UNCOMPRESSED");
            }
            byte[] x = pubKey.getQ().getAffineXCoord().toBigInteger().toByteArray();
            byte[] y = pubKey.getQ().getAffineYCoord().toBigInteger().toByteArray();
            if (x.length == y.length)
            {
                success = true;
            }
        }

        // The very old Problem... we need a certificate chain to
        // save a private key...

        Certificate[] chain = new Certificate[] { generateSelfSignedSoftECCert(
                kp, compress) };

        KeyStore keyStore = KeyStore.getInstance("BKS");
        keyStore.load(null, keyStorePass.toCharArray());

        keyStore.setCertificateEntry("ECCert", chain[0]);

        ECPrivateKey privateECKey = (ECPrivateKey)kp.getPrivate();
        keyStore.setKeyEntry("ECPrivKey", privateECKey, keyStorePass
                .toCharArray(), chain);

        // Test ec sign / verify
        ECPublicKey pub = (ECPublicKey)kp.getPublic();
        String oldPrivateKey = new String(Hex.encode(privateECKey.getEncoded()));
        String oldPublicKey = new String(Hex.encode(pub.getEncoded()));
        ECPrivateKey newKey = (ECPrivateKey)keyStore.getKey("ECPrivKey",
                keyStorePass.toCharArray());
        ECPublicKey newPubKey = (ECPublicKey)keyStore.getCertificate(
                "ECCert").getPublicKey();
        if (!compress)
        {
            ((ECPointEncoder)newKey).setPointFormat("UNCOMPRESSED");
            ((ECPointEncoder)newPubKey).setPointFormat("UNCOMPRESSED");
        }

        String newPrivateKey = new String(Hex.encode(newKey.getEncoded()));
        String newPublicKey = new String(Hex.encode(newPubKey.getEncoded()));

        if (!oldPrivateKey.equals(newPrivateKey))
        {
            fail("failed private key comparison");
        }

        if (!oldPublicKey.equals(newPublicKey))
        {
            fail("failed public key comparison");
        }
    }

    /**
     * Create a self signed cert for our software emulation
     * 
     * @param kp
     *            is the keypair for our certificate
     * @return a self signed cert for our software emulation
     * @throws InvalidKeyException
     *             on error
     * @throws SignatureException
     *             on error
     */
    private X509Certificate generateSelfSignedSoftECCert(KeyPair kp,
            boolean compress) throws Exception
    {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        ECPrivateKey privECKey = (ECPrivateKey)kp.getPrivate();
        ECPublicKey pubECKey = (ECPublicKey)kp.getPublic();
        if (!compress)
        {
            ((ECPointEncoder)privECKey).setPointFormat("UNCOMPRESSED");
            ((ECPointEncoder)pubECKey).setPointFormat("UNCOMPRESSED");
        }
        certGen.setSignatureAlgorithm("ECDSAwithSHA1");
        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal("CN=Software emul (EC Cert)"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000000));
        certGen.setSubjectDN(new X509Principal("CN=Software emul (EC Cert)"));
        certGen.setPublicKey((PublicKey)pubECKey);

        return certGen.generate((PrivateKey)privECKey);
    }
    
    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ECEncodingTest());
    }
}
