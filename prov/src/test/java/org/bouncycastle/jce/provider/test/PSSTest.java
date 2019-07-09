package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomData;

public class PSSTest
    extends SimpleTest
{
    private class FixedRandom
        extends SecureRandom
    {
        byte[]  vals;

        FixedRandom(
            byte[]  vals)
        {
            this.vals = vals;
        }

        public void nextBytes(
            byte[]  bytes)
        {
            System.arraycopy(vals, 0, bytes, 0, vals.length);
        }
    }

    private boolean arrayEquals(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }


    private RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
        new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16),
        new BigInteger("010001",16));

    private RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16),
        new BigInteger("010001",16),
        new BigInteger("33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",16),
        new BigInteger("e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443",16),
        new BigInteger("b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd",16),
        new BigInteger("28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979",16),
        new BigInteger("1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729",16),
        new BigInteger("27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d",16));

    // PSSExample1.1

    private byte[] msg1a = Hex.decode("cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0");

    private byte[] slt1a = Hex.decode("dee959c7e06411361420ff80185ed57f3e6776af");

    private byte[] sig1a = Hex.decode("9074308fb598e9701b2294388e52f971faac2b60a5145af185df5287b5ed2887e57ce7fd44dc8634e407c8e0e4360bc226f3ec227f9d9e54638e8d31f5051215df6ebb9c2f9579aa77598a38f914b5b9c1bd83c4e2f9f382a0d0aa3542ffee65984a601bc69eb28deb27dca12c82c2d4c3f66cd500f1ff2b994d8a4e30cbb33c");

    private byte[] sig1b = Hex.decode("96ea348db4db2947aee807bd687411a880913706f21b383a1002b97e43656e5450a9d1812efbedd1ed159f8307986adf48bada66a8efd14bd9e2f6f6f458e73b50c8ce6e3079011c5b4bd1600a2601a66198a1582574a43f13e0966c6c2337e6ca0886cd9e1b1037aeadef1382117d22b35e7e4403f90531c8cfccdf223f98e4");

    private byte[] sig1c = Hex.decode("9e64cc1062c537b142480bc5af407b55904ead970e20e0f8f6664279c96c6da6b03522160f224a85cc413dfe6bd00621485b665abac6d90ff38c9af06f4ddd6c7c81540439e5795601a1343d9feb465712ff8a5f5150391522fb5a9b8e2225a555f4efaa5e5c0ed7a19b27074c2d9f6dbbd0c893ba02c4a35b115d337bccd7a2");
    
    public void performTest() throws Exception
    {
        KeyFactory fact = KeyFactory.getInstance("RSA", "BC");

        PrivateKey  privKey = fact.generatePrivate(privKeySpec);
        PublicKey   pubKey = fact.generatePublic(pubKeySpec);

        Signature s = Signature.getInstance("SHA1withRSA/PSS", "BC");

        s.initSign(privKey, new FixedRandom(slt1a));
        s.update(msg1a);
        byte[] sig = s.sign();

        if (!arrayEquals(sig1a, sig))
        {
           fail("PSS Sign test expected " + new String(Hex.encode(sig1a)) + " got " + new String(Hex.encode(sig)));
        }

        s = Signature.getInstance("SHA1withRSAandMGF1", "BC");
        
        s.initVerify(pubKey);
        s.update(msg1a);
        if (!s.verify(sig1a))
        {
            fail("SHA1 signature verification failed");
        }

        s = Signature.getInstance("SHA1withRSAandMGF1", "BC");
        
        s.setParameter(PSSParameterSpec.DEFAULT);
        
        s.initVerify(pubKey);
        s.update(msg1a);
        if (!s.verify(sig1a))
        {
            fail("SHA1 signature verification with default parameters failed");
        }
        
        AlgorithmParameters pss = s.getParameters();
        if (!arrayEquals(pss.getEncoded(), new byte[] { 0x30, 0x00 }))
        {
            fail("failed default encoding test.");
        }
        
        s = Signature.getInstance("SHA256withRSA/PSS", "BC");

        s.initSign(privKey, new FixedRandom(slt1a));
        s.update(msg1a);
        sig = s.sign();

        pss = s.getParameters();
        
        if (!arrayEquals(sig1b, sig))
        {
            fail("PSS Sign test expected " + new String(Hex.encode(sig1b)) + " got " + new String(Hex.encode(sig)));
        }

        AlgorithmParameters pParams = AlgorithmParameters.getInstance("PSS", "BC");

        pParams.init(pss.getEncoded());

        PSSParameterSpec spec = (PSSParameterSpec)pParams.getParameterSpec(PSSParameterSpec.class);

        isTrue("Digest mismatch", "SHA-256".equals(spec.getDigestAlgorithm()));
        isTrue("MGF alg mismatch", PSSParameterSpec.DEFAULT.getMGFAlgorithm().equals(spec.getMGFAlgorithm()));
        isTrue("MGF Digest mismatch", "SHA-256".equals(((MGF1ParameterSpec)spec.getMGFParameters()).getDigestAlgorithm()));

        s = Signature.getInstance("SHA256withRSAandMGF1", "BC");
        
        s.setParameter(pss.getParameterSpec(PSSParameterSpec.class));
        
        s.initVerify(pubKey);
        s.update(msg1a);
        if (!s.verify(sig1b))
        {
            fail("SHA256 signature verification failed");
        }

        // set parameter after sig intialisation
        s = Signature.getInstance("RSAPSS", "BC");

        s.initVerify(pubKey);

        s.setParameter(pss.getParameterSpec(PSSParameterSpec.class));

        s.update(msg1a);
        if (!s.verify(sig1b))
        {
            fail("SHA256 signature verification failed");
        }

        s = Signature.getInstance("RSASSA-PSS", "BC");

        s.initSign(privKey);

        s.setParameter(pss.getParameterSpec(PSSParameterSpec.class));

        s.update(msg1a);

        sig = s.sign();

        s.initVerify(pubKey);

        s.update(msg1a);

        if (!s.verify(sig))
        {
            fail("SHA256 signature verification failed (setParameter)");
        }

        s = Signature.getInstance("RSASSA-PSS", "BC");

        s.initSign(privKey);

        s.setParameter(pss.getParameterSpec(PSSParameterSpec.class));

        s.update(msg1a);

        try
        {
            s.setParameter(pss.getParameterSpec(PSSParameterSpec.class));
            fail("no exception - setParameter byte[]");
        }
        catch (ProviderException e)
        {
            isEquals("cannot call setParameter in the middle of update", e.getMessage());
        }

        s.initSign(privKey);
        
        s.update(msg1a[0]);

        try
        {
            s.setParameter(pss.getParameterSpec(PSSParameterSpec.class));
            fail("no exception - setParameter byte");
        }
        catch (ProviderException e)
        {
            isEquals("cannot call setParameter in the middle of update", e.getMessage());
        }

        //
        // 512 test -with zero salt length
        //
        s = Signature.getInstance("SHA512withRSAandMGF1", "BC");
        
        s.setParameter(new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 0, 1));
        s.initSign(privKey);

        s.update(msg1a);
        sig = s.sign();

        pss = s.getParameters();
        
        if (!arrayEquals(sig1c, sig))
        {
            fail("PSS Sign test expected " + new String(Hex.encode(sig1c)) + " got " + new String(Hex.encode(sig)));
        }

        pParams = AlgorithmParameters.getInstance("PSS", "BC");

        pParams.init(pss.getEncoded());

        spec = (PSSParameterSpec)pParams.getParameterSpec(PSSParameterSpec.class);

        isTrue("Digest mismatch", "SHA-512".equals(spec.getDigestAlgorithm()));
        isTrue("MGF alg mismatch", PSSParameterSpec.DEFAULT.getMGFAlgorithm().equals(spec.getMGFAlgorithm()));
        isTrue("MGF Digest mismatch", "SHA-512".equals(((MGF1ParameterSpec)spec.getMGFParameters()).getDigestAlgorithm()));

        s = Signature.getInstance("SHA512withRSAandMGF1", "BC");
        
        s.setParameter(pss.getParameterSpec(PSSParameterSpec.class));
        
        s.initVerify(pubKey);
        s.update(msg1a);
        if (!s.verify(sig1c))
        {
            fail("SHA512 signature verification failed");
        }


        s = Signature.getInstance(PKCSObjectIdentifiers.id_RSASSA_PSS.getId(), "BC");

        s.setParameter(pss.getParameterSpec(PSSParameterSpec.class));

        s.initVerify(pubKey);
        s.update(msg1a);
        if (!s.verify(sig1c))
        {
            fail("SHA512 signature verification failed");
        }

        SecureRandom random = new SecureRandom();

        // Note: PSS minimum key size determined by hash/salt lengths
        PrivateKey priv2048Key = fact.generatePrivate(RSATest.priv2048KeySpec);
        PublicKey pub2048Key = fact.generatePublic(RSATest.pub2048KeySpec);

        rawModeTest("SHA1withRSA/PSS", X509ObjectIdentifiers.id_SHA1, priv2048Key, pub2048Key, random);
        rawModeTest("SHA224withRSA/PSS", NISTObjectIdentifiers.id_sha224, priv2048Key, pub2048Key, random);
        rawModeTest("SHA256withRSA/PSS", NISTObjectIdentifiers.id_sha256, priv2048Key, pub2048Key, random);
        rawModeTest("SHA384withRSA/PSS", NISTObjectIdentifiers.id_sha384, priv2048Key, pub2048Key, random);
        rawModeTest("SHA512withRSA/PSS", NISTObjectIdentifiers.id_sha512, priv2048Key, pub2048Key, random);
    }

    private void rawModeTest(String sigName, ASN1ObjectIdentifier digestOID,
            PrivateKey privKey, PublicKey pubKey, SecureRandom random) throws Exception
    {
        byte[] sampleMessage = new byte[1000 + random.nextInt(100)];
        random.nextBytes(sampleMessage);

        Signature normalSig = Signature.getInstance(sigName, "BC");

        PSSParameterSpec spec = (PSSParameterSpec)normalSig.getParameters().getParameterSpec(PSSParameterSpec.class);

        // Make sure we generate the same 'random' salt for both normal and raw signers
        int saltLen = spec.getSaltLength();
        byte[] fixedRandomBytes = new byte[saltLen];
        random.nextBytes(fixedRandomBytes);

        normalSig.initSign(privKey, new TestRandomData(fixedRandomBytes));
        normalSig.update(sampleMessage);
        byte[] normalResult = normalSig.sign();

        MessageDigest digest = MessageDigest.getInstance(digestOID.getId(), "BC");
        byte[] hash = digest.digest(sampleMessage);

        Signature rawSig = Signature.getInstance("RAWRSASSA-PSS", "BC");

        // Need to init the params explicitly to avoid having a 'raw' variety of every PSS algorithm
        rawSig.setParameter(spec);

        rawSig.initSign(privKey, new TestRandomData(fixedRandomBytes));
        rawSig.update(hash);
        byte[] rawResult = rawSig.sign();

        if (!Arrays.areEqual(normalResult, rawResult))
        {
            fail("raw mode signature differs from normal one");
        }

        rawSig.initVerify(pubKey);
        rawSig.update(hash);

        if (!rawSig.verify(rawResult))
        {
            fail("raw mode signature verification failed");
        }
    }

    public String getName()
    {
        return "PSSTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PSSTest());
    }
}
