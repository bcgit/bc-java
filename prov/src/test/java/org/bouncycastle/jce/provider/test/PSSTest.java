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
import java.security.spec.AlgorithmParameterSpec;
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
    private static class FixedRandom
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

    private byte[] sig1d = Hex.decode("944a75909b6f3bd29b44364def2c814ec85e1171efd57e04471c26a20ffaf5162c7a820ab3023263574b338d43945ed15a1c7f81e262b96922defb5c7d15c14ed555b8c8ede00211f774ffa8b189e4a650cf5b4efa1f5e75401f3b45b5cf83853b7ad6e0fb2d9d055047178db48e32b36e3134fc7b54919f59051c2c1b33f139");

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

        s = Signature.getInstance("SHAKE128withRSAPSS", "BC");
        
        s.initVerify(pubKey);
        s.update(msg1a);
        if (!s.verify(sig1d))
        {
            fail("SHAKE128 signature verification failed");
        }

        isTrue(s.getParameters() != null);
        
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

        testShake128Pss();
        testShake256Pss();
        testShake128Sha256Pss();
        testShake256Sha512Pss();
    }

    /**
     *           {
     *             "tcId": 2,
     *             "message": "0DEEA95988D7C12DAFD3EE46716F9AE13D05432479D9E3A1AA68D8204BA00C05BE3B8D508BCACC9E52E4FC8FB0FA6F6B809629444D97279B3F352354751411AB629F40E0DB1B78674991BCA17522D6CDBC4E345D4B6FA4FF1C696C0331162F0E8571B287C82CB9B5F475B3F1974304AB38556AA523971D1426090D95D06CDDFD",
     *             "signature": "3A21B77F2D9534486FADBB7308F44A9CAD45AC731E51E4656998B8DAEC08431E045B40E375AEC9D07228364A98328991B23EA4D5C69596738EBA1B3990C1296AD9746643D2053AC34178198AF7BBD674E1E550372CFCB417804D13CC013B9D5C07CE1B882E90CD5F0CF353FA53896E6B069C552461A7F0316197EF10231FD400F6524CB17861C254DA367EE3F6B7FB8E0AEFA04F98AD4375FD171868B4F747079FF401698F7DC3C40438F0369694595293B32F37ADD42D44D7D65B8B218C139D576B9EF71CE916C23498857A9121F72B1618D322A64F8789663325A6E7FF6A3E6AEB224BA9F03B2FF801854551A57E497416450250AA75B1842CDC0770D4A1C0"
     *           },
     *
     */
    private void testShake128Pss()
        throws Exception
    {
        byte[] msg = Hex.decode("0DEEA95988D7C12DAFD3EE46716F9AE13D05432479D9E3A1AA68D8204BA00C05BE3B8D508BCACC9E52E4FC8FB0FA6F6B809629444D97279B3F352354751411AB629F40E0DB1B78674991BCA17522D6CDBC4E345D4B6FA4FF1C696C0331162F0E8571B287C82CB9B5F475B3F1974304AB38556AA523971D1426090D95D06CDDFD");
        byte[] sig = Hex.decode("3A21B77F2D9534486FADBB7308F44A9CAD45AC731E51E4656998B8DAEC08431E045B40E375AEC9D07228364A98328991B23EA4D5C69596738EBA1B3990C1296AD9746643D2053AC34178198AF7BBD674E1E550372CFCB417804D13CC013B9D5C07CE1B882E90CD5F0CF353FA53896E6B069C552461A7F0316197EF10231FD400F6524CB17861C254DA367EE3F6B7FB8E0AEFA04F98AD4375FD171868B4F747079FF401698F7DC3C40438F0369694595293B32F37ADD42D44D7D65B8B218C139D576B9EF71CE916C23498857A9121F72B1618D322A64F8789663325A6E7FF6A3E6AEB224BA9F03B2FF801854551A57E497416450250AA75B1842CDC0770D4A1C0");

        KeyFactory kFact = KeyFactory.getInstance("RSA", "BC");

        PublicKey pubKey = kFact.generatePublic(new RSAPublicKeySpec(new BigInteger("A1B7BA64A30ADE94FEC333ECC856B6B5E75812F7D5845D5F8741E9A125E4276A690AE1D4E5236C9A14BE053777C5623EBAC72EE53B4839C1BAD43C8F49964F28BA4B891055883064E42D97096E3714455C6E7862DF860C13C6E9739B09A53B506E8883CFA0B176D2C9FE2BC9421338113398FFEDED3D4EFC7771A803C34A4083F1D9E3F91F6D9AC36380C030BEA05BEA2D42CCFE88EBD9578AB8C9FDCEF7DE7E283A64480492768DEFE9C8EA030AFBB5E098259C75426EDD279F75898F500A75271DE0CCE02C8A02FD013750E74D8F0F7B97B492687DB92D74D9A34710AFFE87D497D286ED526EE58BA267FF836873A14224E8FF825C3D42A8E5F763B35466A9", 16),
                new BigInteger("15A08B61A3", 16)));

        Signature s = Signature.getInstance("SHA1withRSAandSHAKE128");

        s.initVerify(pubKey);

        s.update(msg);

        isTrue("shake128 failed", s.verify(sig));
    }

    private void testShake256Pss()
        throws Exception
    {
        byte[] msg = Hex.decode("D21584E5561FB875EF6EDE807D1297DC8E6C12C43CEEF259F3A685EA25C1CD1E6C0DFEBDD1274D32198320F13118A446CBC18E4F80CFDBD0D3550CA451D1F80F6010992259639D1CBC929318BFC5AFFF4AD7BB1ED02D2E052F57206E4409C5AD9BDFB7E118EF1D87DF5F7DAED40A28F3C450AE167F94EE17F1B11176EA7C7C39");
        byte[] sig = Hex.decode("02B324058D0C4F3E4664682E1F51ECA6FD80C8CDFC655A78CEBA725E42608AFD9D65381D9A87C2C7A93695858D277492977785E24E7ED8E35062AF1FA3194A379B9BF02A9A212DCBFFBDADA4FBD1BDD720F83427E8342CB6D7D267A216EA3D0F01F5F2D719E149F4EC840759403056152D457AFD30FD9A21A892E39BCD8BB3973F1662A01A662F06BAC117695943A2D54F1E947915B26EAB339545A80CB5806AA4F6E4503022A02C2FBB33FB97B0ED78334FB222069B09756FFF184602B10B6FCB4B1FA87DC60B200D8B8B7D0A9C289116A673901AA17C7DDDE4F495D3D6D32BD57769E23E9A0785AE63CAF8721D29485E8756A20ADD1CEDFAAEFF498340EF12");

        KeyFactory kFact = KeyFactory.getInstance("RSA", "BC");

        PublicKey pubKey = kFact.generatePublic(new RSAPublicKeySpec(new BigInteger("A316949326DEF5067D6BCB0B18BBD6D01CB4603F724B250CD3981AD34A9A466B7113CC34A45DF958FEF4D9BAAE41C7FD25E49BDFB1828A970D70BA8B14107705D614C486DF9B3F25CE9BC1FD8135FF21102F9C979DC381D5B7F7DB0391874763E1EB6A9CCF87AF507329E3D853A54855B5F8FAF280E84BA2A30950CB5C62963DE4BD3D9E4F10D73DD7F24E825AAD4E72D9215C4B091A221069E1BFD6749683F9CC72773C63F7E84F0FF8241D786D40C57A4D540700070640CDD9A8EEFCD74B1B6DB8243905A2EDD2BCE993E0B766091075B660467F7BAEE88B139971C32473B9C067E2427E2C496E937D22062AB9AD86AE3494301E1D2AA60500D7E7202793E7", 16),
                new BigInteger("036F67356FA8E7", 16)));

        Signature s = Signature.getInstance("SHA1withRSAandSHAKE256");

        s.initVerify(pubKey);

        s.update(msg);

        isTrue("shake256 failed", s.verify(sig));
    }

    private void testShake128Sha256Pss()
        throws Exception
    {
        byte[] msg = Hex.decode("D13EAA2287EA0FAC2947E0291FCF6E24D3F3C4905140278C688B7E82ECEE7AA60517DA2BA20E51C4A42A71E1AE3CA8C476BB2F5FCC9D08AB6A4C30D9AFB4D79B298F65C894E5E00353912E59EC91D998642E36C38AA3366ADF6E108311A456D2845D7387D50CF3AD7FB9030308E8197BCF417D06865BF99C173BD487925FBC56");
        byte[] sig = Hex.decode("8C90B0194B171DCB46121DB1599DDD1E817380421E918CCF6388695468E7BCB592B219C4347885B47F8E826ACA270BB1B7604AD667BE0818D3559910ABE4645918B4F308F5EFB8D588AC3C879C7A3F32DC098EBC658EBD8B24637BEB4224FA47C9BF30B37777EE9AECC1341F8691B3F4233EAB55813D172C9419ED076E85700C1F201C407BCC0733B673FADA681FC1F19448C9129A7C9B9F2B6C71F946B04013FE838D536CCCD5AC6AB140AB54262852D9C503E7C192CBAD817679DC4A932AC89EB886AB2145AF97C73C84E48AAE4AF0BE55EEB7496A6E36CE4FF9CAE8028E53434FBA050D25F036E511ABE7B1071B4749F09567E34AE28C09EBB384FFD68F72");

        KeyFactory kFact = KeyFactory.getInstance("RSA", "BC");

        PublicKey pubKey = kFact.generatePublic(new RSAPublicKeySpec(new BigInteger("F94653A345BE69567282DCE95E4B2B8145C04FFB4E8FD7D338AEDA1C9097E77BA851D3B3911AD274645E386222F6BDC699583B9D0CCDD38606D4D0879A997464124AC5F51D92BAEDCEAB19CAC81758123147B24D576BA8505DD8878F47F430B30A0291E99EBC26AF935E8A81D7036110A9ED6A82B90D37E4C9BE0597D79BA1EF184286B772F5B2DEE0607C29E0A4F24AE91EEC814CD1EAD83451C603F5F9C590C02015B5B5C8745DE3FC40BAAFE7813E4537DEFEA5A1CC636EA886887B4727CBBFB5EB12380F66D8626399B82E29534ACB7F6E17CC11FCB52426F8E91C9313C6A9620692C203480AAC4DA7F20F4379F1AA19DC7628A0C10A452B509DDA096161", 16),
                new BigInteger("06E594CE87", 16)));

        Signature s = Signature.getInstance("SHA256withRSAandSHAKE128");

        s.initVerify(pubKey);

        s.update(msg);

        isTrue("sha256 shake128 failed", s.verify(sig));
    }

    private void testShake256Sha512Pss()
        throws Exception
    {
        byte[] msg = Hex.decode("AB57832D76FAFAFE00D69F379120EC82FFC726DB5A86BD14F4B5C791C2BFE6292AE10B5FB0C374E8649432530F4C617A0E39B964F5A6FEB6B634F1EAE25E923329AE84F39BFBBCB92B1B82593D7448E6A0AAF054F210D8AED4A65A6D7DA004E7ED6FC758330125FF8EAC74CD55D25D11A16F8BE7457FA3F106B7F5C0FA4A66A0");
        byte[] sig = Hex.decode("C1B4FE2788A49039973A0CC154B0C951DC30D8B97CE830EE60960C779704B4590A3EC5643BB5B6E9019AA57F6638D10652EE0F1A3372F87ED93BA151144ADFBA4059C03C958DC800DA4F16D4A25933770B0EBFE20B429D37F72A2591174457061F19F9F6E60DDE26AA2D8C2231F990A05568D27DB02C5A5DA7A5C63D1F8C6D94B78AE061C31A2CF4585A7309A28FECA318F12994580257E2137361F69B7E32F23B537FAF9E2D5BB7B2F1D96730457E9E232212A99399800BCFC856E6D611E3F8C7B7D19D2441979607D81EC24893E8E70FF3B459B63CDE2EFE29D6DA5DB2BEE657E2131BFD5E52E33D683FD5DE7A701FE3D282D798C52FF3B4F97DF3296875B9");

        KeyFactory kFact = KeyFactory.getInstance("RSA", "BC");

        PublicKey pubKey = kFact.generatePublic(new RSAPublicKeySpec(new BigInteger("CFECB239C97FAE3AEBD1108E9BA175E782E24A77D5F1BE459CAA4A18711B45FC1867012CE39AB4FB5B836BF4E100D951F4A0E3943D2C7B6DD6AB4D754D44BAD185E023A36951E93843D7421234C2F711A8524A0A4D005F592C5D4EA11DC16984E1BBA765167378A5DAEC9F3957339870D65999D374E3FA04932D96A55CB0DD3405D42B5012169179E840CFDE8884DAC1950030ED667316C3E226F1F1F6B229761E7CE1A4717A279A4C29D1D079FC812108F36D8CC557E9A879918864544FF3D2E047B22DE3474B267841A1630AE59B077A1BFD96D1F16750497EC7882A21E0CCA4EFD836C287A771007DC333E80D3FC88BE44585FDC8D1B69F47A590C890B265", 16),
                new BigInteger("01CE5BA4E1", 16)));

        Signature s = Signature.getInstance("SHA512withRSAandSHAKE256");

        s.setParameter(new PSSParameterSpec("SHA-512", "SHAKE256", null, 0, 1));

        s.initVerify(pubKey);

        s.update(msg);

        isTrue("1 sha512 shake256 failed", s.verify(sig));

        AlgorithmParameters p = s.getParameters();

        isTrue(Arrays.areEqual(Hex.decode("3025a00f300d06096086480165030402030500a10d300b060960864801650304020ca203020100"), p.getEncoded()));

        s = Signature.getInstance("SHA512withRSAandSHAKE256");

        s.setParameter(p.getParameterSpec(AlgorithmParameterSpec.class));

        s.initVerify(pubKey);

        s.update(msg);

        isTrue("2 sha512 shake256 failed", s.verify(sig));

        AlgorithmParameters ap = AlgorithmParameters.getInstance("PSS", "BC");

        ap.init(p.getEncoded());

        s = Signature.getInstance("SHA512withRSAandSHAKE256");

        s.setParameter(ap.getParameterSpec(AlgorithmParameterSpec.class));

        s.initVerify(pubKey);

        s.update(msg);

        isTrue("2 sha512 shake256 failed", s.verify(sig));
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
