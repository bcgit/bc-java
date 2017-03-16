package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SigTest
    extends SimpleTest
{
    /**
     * signature with a "forged signature" (sig block not at end of plain text)
     */
    private void testBadSig(PrivateKey priv, PublicKey pub) throws Exception
    {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1", "BC");
        Cipher signer = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        
        signer.init(Cipher.ENCRYPT_MODE, priv);
        
        byte[] block = new byte[signer.getBlockSize()];
        
        sha1.update((byte)0);
        
        byte[] sigHeader = Hex.decode("3021300906052b0e03021a05000414");
        System.arraycopy(sigHeader, 0, block, 0, sigHeader.length);
        
        byte[] dig = sha1.digest();

        System.arraycopy(dig, 0, block, sigHeader.length, dig.length);

        System.arraycopy(sigHeader, 0, block, 
                        sigHeader.length + dig.length, sigHeader.length);
        
        byte[] sig = signer.doFinal(block);
        
        Signature verifier = Signature.getInstance("SHA1WithRSA", "BC");
        
        verifier.initVerify(pub);
        
        verifier.update((byte)0);
        
        if (verifier.verify(sig))
        {
            fail("bad signature passed");
        }
    }

    public void performTest()
        throws Exception
    {   
        Signature           sig = Signature.getInstance("SHA1WithRSAEncryption", "BC");
        KeyPairGenerator    fact;
        KeyPair             keyPair;
        byte[]              data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

        fact = KeyPairGenerator.getInstance("RSA", "BC");

        fact.initialize(768, new SecureRandom());

        keyPair = fact.generateKeyPair();

        PrivateKey  signingKey = keyPair.getPrivate();
        PublicKey   verifyKey = keyPair.getPublic();
        
        testBadSig(signingKey, verifyKey);

        sig.initSign(signingKey);

        sig.update(data);

        byte[]  sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail("SHA1 verification failed");
        }

        sig = Signature.getInstance("MD2WithRSAEncryption", "BC");

        sig.initSign(signingKey);

        sig.update(data);

        sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail("MD2 verification failed");
        }

        sig = Signature.getInstance("MD5WithRSAEncryption", "BC");

        sig.initSign(signingKey);

        sig.update(data);

        sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail("MD5 verification failed");
        }

        sig = Signature.getInstance("RIPEMD160WithRSAEncryption", "BC");

        sig.initSign(signingKey);

        sig.update(data);

        sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail("RIPEMD160 verification failed");
        }

        //
        // RIPEMD-128
        //
        sig = Signature.getInstance("RIPEMD128WithRSAEncryption", "BC");

        sig.initSign(signingKey);

        sig.update(data);

        sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail("RIPEMD128 verification failed");
        }

        //
        // RIPEMD256
        //
        sig = Signature.getInstance("RIPEMD256WithRSAEncryption", "BC");

        sig.initSign(signingKey);

        sig.update(data);

        sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail("RIPEMD256 verification failed");
        }

        //
        // ISO Sigs.
        //
        sig = Signature.getInstance("MD5WithRSA/ISO9796-2", "BC");

        sig.initSign(signingKey);

        sig.update(data);

        sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail("MD5/ISO verification failed");
        }

        sig = Signature.getInstance("SHA1WithRSA/ISO9796-2", "BC");

        sig.initSign(signingKey);

        sig.update(data);

        sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail("SHA1/ISO verification failed");
        }

        tryRsaPkcs15Sig("SHA224WithRSA", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha224WithRSAEncryption, NISTObjectIdentifiers.id_sha224);
        tryRsaPkcs15Sig("SHA256WithRSA", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha256WithRSAEncryption, NISTObjectIdentifiers.id_sha256);
        tryRsaPkcs15Sig("SHA384WithRSA", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha384WithRSAEncryption, NISTObjectIdentifiers.id_sha384);
        tryRsaPkcs15Sig("SHA512WithRSA", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha512WithRSAEncryption, NISTObjectIdentifiers.id_sha512);
        tryRsaPkcs15Sig("SHA512(224)WithRSA", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha512_224WithRSAEncryption, NISTObjectIdentifiers.id_sha512_224);
        tryRsaPkcs15Sig("SHA512(256)WithRSA", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha512_256WithRSAEncryption, NISTObjectIdentifiers.id_sha512_256);
        tryRsaPkcs15Sig("SHA224WithRSAEncryption", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha224WithRSAEncryption, NISTObjectIdentifiers.id_sha224);
        tryRsaPkcs15Sig("SHA256WithRSAEncryption", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha256WithRSAEncryption, NISTObjectIdentifiers.id_sha256);
        tryRsaPkcs15Sig("SHA384WithRSAEncryption", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha384WithRSAEncryption, NISTObjectIdentifiers.id_sha384);
        tryRsaPkcs15Sig("SHA512WithRSAEncryption", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha512WithRSAEncryption, NISTObjectIdentifiers.id_sha512);
        tryRsaPkcs15Sig("SHA512(224)WithRSAEncryption", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha512_224WithRSAEncryption, NISTObjectIdentifiers.id_sha512_224);
        tryRsaPkcs15Sig("SHA512(256)WithRSAEncryption", data, signingKey, verifyKey, PKCSObjectIdentifiers.sha512_256WithRSAEncryption, NISTObjectIdentifiers.id_sha512_256);

        tryRsaPkcs15Sig("SHA3-224WithRSA", data, signingKey, verifyKey, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        tryRsaPkcs15Sig("SHA3-256WithRSA", data, signingKey, verifyKey, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        tryRsaPkcs15Sig("SHA3-384WithRSA", data, signingKey, verifyKey, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        tryRsaPkcs15Sig("SHA3-512WithRSA", data, signingKey, verifyKey, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);
        tryRsaPkcs15Sig("SHA3-224WithRSAEncryption", data, signingKey, verifyKey, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        tryRsaPkcs15Sig("SHA3-256WithRSAEncryption", data, signingKey, verifyKey, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        tryRsaPkcs15Sig("SHA3-384WithRSAEncryption", data, signingKey, verifyKey, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        tryRsaPkcs15Sig("SHA3-512WithRSAEncryption", data, signingKey, verifyKey, NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);

        trySig("SHA1WithRSAAndMGF1", data, signingKey, verifyKey);
        trySig("SHA224WithRSAAndMGF1", data, signingKey, verifyKey);
        trySig("SHA256WithRSAAndMGF1", data, signingKey, verifyKey);
        //trySig("SHA384WithRSAAndMGF1", data, signingKey, verifyKey);
       //trySig("SHA512WithRSAAndMGF1", data, signingKey, verifyKey);
        trySig("SHA512(224)WithRSAAndMGF1", data, signingKey, verifyKey);
        trySig("SHA512(256)WithRSAAndMGF1", data, signingKey, verifyKey);

        trySig("SHA3-224WithRSAAndMGF1", data, signingKey, verifyKey);
        trySig("SHA3-256WithRSAAndMGF1", data, signingKey, verifyKey);
//        trySig("SHA3-384WithRSAAndMGF1", data, signingKey, verifyKey);
//        trySig("SHA3-512WithRSAAndMGF1", data, signingKey, verifyKey);

        trySig("SHA1WithRSA/ISO9796-2", data, signingKey, verifyKey);
        trySig("SHA224WithRSA/ISO9796-2", data, signingKey, verifyKey);
        trySig("SHA256withRSA/ISO9796-2", data, signingKey, verifyKey);
        trySig("SHA384WithRSA/ISO9796-2", data, signingKey, verifyKey);
        trySig("SHA512WithRSA/ISO9796-2", data, signingKey, verifyKey);
        trySig("SHA512(224)WithRSA/ISO9796-2", data, signingKey, verifyKey);
        trySig("SHA512(256)WithRSA/ISO9796-2", data, signingKey, verifyKey);
        trySig("WhirlpoolWithRSA/ISO9796-2", data, signingKey, verifyKey);
        trySig("RIPEMD160WithRSA/ISO9796-2", data, signingKey, verifyKey);

        trySig("RIPEMD128WithRSA/X9.31", data, signingKey, verifyKey);
        trySig("RIPEMD160WithRSA/X9.31", data, signingKey, verifyKey);
        trySig("SHA1WithRSA/X9.31", data, signingKey, verifyKey);
        trySig("SHA224WithRSA/X9.31", data, signingKey, verifyKey);
        trySig("SHA256withRSA/X9.31", data, signingKey, verifyKey);
        trySig("SHA384WithRSA/X9.31", data, signingKey, verifyKey);
        trySig("SHA512WithRSA/X9.31", data, signingKey, verifyKey);
        trySig("SHA512(224)WithRSA/X9.31", data, signingKey, verifyKey);
        trySig("SHA512(256)WithRSA/X9.31", data, signingKey, verifyKey);
        trySig("WhirlpoolWithRSA/X9.31", data, signingKey, verifyKey);

        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");

        BigInteger mod = new BigInteger("f6b18dfb2eb944d8df7e8b8077f8857ffa7a4192ea10cdd87edf7839872d50029ed86fc17c8b90bef725517b7f2f6403559957d0d4220ed8283ebde769d9f7024b84654d7b398d64b582520e6b7a7e07c1aea5eedbfac0474ac239a5ceb6e5e7", 16);

        RSAPublicKey vKey = (RSAPublicKey)keyFact.generatePublic(new RSAPublicKeySpec(mod, new BigInteger("10001", 16)));
        RSAPrivateKey sKey = (RSAPrivateKey)keyFact.generatePrivate(new RSAPrivateKeySpec(mod, new BigInteger("6af2b6d6fa7e9f76560e0a747b8e66720129175c95d50b289c784d2ac38bc5701d653fade64cab47dee572d9d35dbc414be785166afe59a4dd3e7b5a19e756ed83c56319ece6a3a8a4e8d982526361bb133d49a27c4299a5d717189ebd9159a1", 16)));

        trySig("SHA1WithRSA/X9.31", data, sKey, vKey);

        shouldPassSignatureX931Test1();
        shouldPassSignatureX931Test2();
        shouldPassSignatureX931Test3();

        //
        // standard vector test - B.1.3 RIPEMD160, implicit.
        //
        mod = new BigInteger("ffffffff78f6c55506c59785e871211ee120b0b5dd644aa796d82413a47b24573f1be5745b5cd9950f6b389b52350d4e01e90009669a8720bf265a2865994190a661dea3c7828e2e7ca1b19651adc2d5", 16);
        BigInteger  pub = new BigInteger("03", 16);
        BigInteger  pri = new BigInteger("2aaaaaaa942920e38120ee965168302fd0301d73a4e60c7143ceb0adf0bf30b9352f50e8b9e4ceedd65343b2179005b2f099915e4b0c37e41314bb0821ad8330d23cba7f589e0f129b04c46b67dfce9d", 16);

        KeyFactory  f = KeyFactory.getInstance("RSA", "BC");

        PrivateKey  privKey = f.generatePrivate(new RSAPrivateKeySpec(mod, pri));
        PublicKey   pubKey = f.generatePublic(new RSAPublicKeySpec(mod, pub));
        byte[]      testSig = Hex.decode("5cf9a01854dbacaec83aae8efc563d74538192e95466babacd361d7c86000fe42dcb4581e48e4feb862d04698da9203b1803b262105104d510b365ee9c660857ba1c001aa57abfd1c8de92e47c275cae");

        data = Hex.decode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

        sig = Signature.getInstance("RIPEMD160WithRSA/ISO9796-2", "BC");

        sig.initSign(privKey);

        sig.update(data);

        sigBytes = sig.sign();

        if (!Arrays.areEqual(testSig, sigBytes))
        {
            fail("SigTest: failed ISO9796-2 generation Test");
        }

        sig.initVerify(pubKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail("RIPEMD160/ISO verification failed");
        }
    }

    private void trySig(String algorithm, byte[] data, PrivateKey signingKey, PublicKey verifyKey)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
    {
        Signature sig;
        byte[] sigBytes;
        sig = Signature.getInstance(algorithm, "BC");

        sig.initSign(signingKey);

        sig.update(data);

        sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail(algorithm + " verification failed");
        }
    }

    private void tryRsaPkcs15Sig(String algorithm, byte[] data, PrivateKey signingKey, PublicKey verifyKey, ASN1ObjectIdentifier sigOid, ASN1ObjectIdentifier hashOid)
        throws Exception
    {
        Signature sig;
        byte[] sigBytes;
        sig = Signature.getInstance(algorithm, "BC");

        sig.initSign(signingKey);

        sig.update(data);

        sigBytes = sig.sign();

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail(algorithm + " verification failed");
        }

        Cipher c = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");

        c.init(Cipher.DECRYPT_MODE, verifyKey);

        DigestInfo digInfo = DigestInfo.getInstance(c.doFinal(sigBytes));

        isTrue("digest alg not match", digInfo.getAlgorithmId().getAlgorithm().equals(hashOid));

        sig = Signature.getInstance(sigOid.getId(), "BC");

        sig.initSign(signingKey);

        sig.update(data);

        isTrue("sig not matched", Arrays.areEqual(sigBytes, sig.sign()));

        sig.initVerify(verifyKey);

        sig.update(data);

        if (!sig.verify(sigBytes))
        {
            fail(algorithm + " oid verification failed");
        }
    }

    private void shouldPassSignatureX931Test1()
        throws Exception
    {
        BigInteger n = new BigInteger("c9be1b28f8caccca65d86cc3c9bbcc13eccc059df3b80bd2292b811eff3aa0dd75e1e85c333b8e3fa9bed53bb20f5359ff4e6900c5e9a388e3a4772a583a79e2299c76582c2b27694b65e9ba22e66bfb817f8b70b22206d7d8ae488c86dbb7137c26d5eff9b33c90e6cee640630313b7a715802e15142fef498c404a8de19674974785f0f852e2d470fe85a2e54ffca9f5851f672b71df691785a5cdabe8f14aa628942147de7593b2cf962414a5b59c632c4e14f1768c0ab2e9250824beea60a3529f11bf5e070ce90a47686eb0be1086fb21f0827f55295b4a48307db0b048c05a4aec3f488c576ca6f1879d354224c7e84cbcd8e76dd217a3de54dba73c35", 16);
        BigInteger e = new BigInteger("e75b1b", 16);
        byte[] msg = Hex.decode("5bb0d1c0ef9b5c7af2477fe08d45523d3842a4b2db943f7033126c2a7829bacb3d2cfc6497ec91688189e81b7f8742488224ba320ce983ce9480722f2cc5bc42611f00bb6311884f660ccc244788378673532edb05284fd92e83f6f6dab406209032e6af9a33c998677933e32d6fb95fd27408940d7728f9c9c40267ca1d20ce");
        byte[] sig = Hex.decode("0fe8bb8e3109a1eb7489ef35bf4c1a0780071da789c8bd226a4170538eafefdd30b732d628f0e87a0b9450051feae9754d4fb61f57862d10f0bacc4f660d13281d0cd1141c006ade5186ff7d961a4c6cd0a4b352fc1295c5afd088f80ac1f8e192ef116a010a442655fe8ff5eeacea15807906fb0f0dfa86e680d4c005872357f7ece9aa4e20b15d5f709b30f08648ecaa34f2fbf54eb6b414fa2ff6f87561f70163235e69ccb4ac82a2e46d3be214cc2ef5263b569b2d8fd839b21a9e102665105ea762bda25bb446cfd831487a6b846100dee113ae95ae64f4af22c428c87bab809541c962bb3a56d4c86588e0af4ebc7fcc66dadced311051356d3ea745f7");

        RSAPublicKeySpec rsaPublic = new RSAPublicKeySpec(n, e);
        Signature signer = Signature.getInstance("SHA1withRSA/X9.31", "BC");

        signer.initVerify(KeyFactory.getInstance("RSA", "BC").generatePublic(rsaPublic));

        signer.update(msg, 0, msg.length);

        if (!signer.verify(sig))
        {
            fail("RSA X931 verify test 1 failed.");
        }
    }

    private void shouldPassSignatureX931Test2()
        throws Exception
    {
        BigInteger n = new BigInteger("b746ba6c3c0be64bbe33aa55b2929b0af4e86d773d44bfe5914db9287788c4663984b61a418d2eecca30d752ff6b620a07ec72eeb2b422d2429da352407b99982800b9dd7697be6a7b1baa98ca5f4fc2fe33400f20b9dba337ac25c987804165d4a6e0ee4d18eabd6de5abdfe578cae6713ff91d16c80a5bb20217fe614d9509e75a43e1825327b9da8f0a9f6eeaa1c04b69fb4bacc073569fff4ab491becbe6d0441d437fc3fa823239c4a0f75321666b68dd3f66e2dd394089a15bcc288a68a4eb0a48e17d639743b9dea0a91cc35820544732aff253f8ca9967c609dc01c2f8cd0313a7a91cfa94ff74289a1d2b6f19d1811f4b9a65f4cce9e5759b4cc64f", 16);
        BigInteger e = new BigInteger("dcbbdb", 16);
        byte[] msg = Hex.decode("a5d3c8a060f897bbbc20ae0955052f37fbc70986b6e11c65075c9f457142bfa93856897c69020aa81a91b5e4f39e05cdeecc63395ab849c8262ca8bc5c96870aecb8edb0aba0024a9bdb71e06de6100344e5c318bc979ef32b8a49a8278ba99d4861bce42ebbc5c8c666aaa6cac39aff8779f2cae367620f9edd4cb1d80b6c8c");
        byte[] sig = Hex.decode("39fbbd1804c689a533b0043f84da0f06081038c0fbf31e443e46a05e58f50de5198bbca40522afefaba3aed7082a6cb93b1da39f1f5a42246bf64930781948d300549bef0f8d554ecfca60a1b1ecba95a7014ee4545ad4f0c4e3a31942c6738b4ccd6244b6a21267dadf0826a5f713f13b1f5a9ab8501d957a26d4948278ac67851071a315674bdab173bfef2c2690c8373da6bf3d69f30c0e5da8883de872f59521b40793854085641adf98d13db991c5d0a8aaa0222934fa33332e90ef0b954e195cb267d6ffb36c96e14d1ec7b915a87598b4461a3146566354dc2ae748c84ee0cd46543b53ebff8cdf47725b280a1f799fb6ebb4a31ad2bdd5178250f83a");

        RSAPublicKeySpec rsaPublic = new RSAPublicKeySpec(n, e);
        Signature signer = Signature.getInstance("SHA224withRSA/X9.31", "BC");

        signer.initVerify(KeyFactory.getInstance("RSA", "BC").generatePublic(rsaPublic));

        signer.update(msg, 0, msg.length);

        if (!signer.verify(sig))
        {
            fail("RSA X931 verify test 2 failed.");
        }
    }

    private void shouldPassSignatureX931Test3()
        throws Exception
    {
        BigInteger n = new BigInteger("dcb5686a3d2063a3f9cf7b9b32d2d3765b4c449b09b4960245a9111cd3b0cbd3260496885b8e1fa5db33b03efcc759d9c1afe29d93c6faebc7e0efada334b5b9a29655e2da2c8f11103d8203be311feab7ae88e9f1b2ec7d8fc655d77202b1681dd9717ec0f525b35584987e19539635a1ed23ca482a00149c609a23dc1645fd", 16);
        BigInteger e = new BigInteger("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dc9f7", 16);
        BigInteger d = new BigInteger("189d6345099098992e0c9ca5f281e1338092342fa0acc85cc2a111f30f9bd2fb4753cd1a48ef0ddca9bf1af33ec76fb2e23a9fb4896c26f2235b516f7c05ef7ae81e70f4b491a5fedba9b935e9c76d761a813ce7776ff8a1e5efe1166ff2eca26aa900da88c908d51af9de26977fe39719cc781df32216fa41b838f0c63803c3", 16);

        RSAPublicKeySpec rsaPublic = new RSAPublicKeySpec(n, e);
        RSAPrivateKeySpec rsaPriv = new RSAPrivateKeySpec(n, d);

        PrivateKey privateKey = KeyFactory.getInstance("RSA", "BC").generatePrivate(rsaPriv);
        PublicKey publicKey = KeyFactory.getInstance("RSA", "BC").generatePublic(rsaPublic);


        byte[] msg = Hex.decode("911475c6e210ef4ac65b6fe8d2bfe5e01b959771b137c4ef69b88716e0d2ff9ebc1fad0f358c1dd7d50cc99a7b893ac9a6207076f08d8467d9e48c69c683bfe64a44dabaa3f7c243880f6ab7229bf7bb587822314fc5de5131983bfb2eef8b4bc1eac36f353724b567cd1ae8cddd64ddb7057549d5c81ad5fa3b5e751f00abf5");
        byte[] sig = Hex.decode("02c50ec0ac8a7f38ef5630c396964d6a6daaa7e3083ab5b57fa2a2632f3b70e2e85c8456cd774d45d7e44fcb063f0f04fff9f1e3adfda11272535a92cb59320b190b5ee4261f23d6ceaa925df3a7bfa42e26bf61ea9645d9d64b3c90a820802768a6e209c9f83705375a3867afccc037e8242a98fa4c3db6b2d9877754d47289");

        doGenVerify("SHA1withRSA/X9.31", privateKey, publicKey, msg, sig);

        msg = Hex.decode("911475c6e210ef4ac65b6fe8d2bfe5e01b959771b137c4ef69b88716e0d2ff9ebc1fad0f358c1dd7d50cc99a7b893ac9a6207076f08d8467d9e48c69c683bfe64a44dabaa3f7c243880f6ab7229bf7bb587822314fc5de5131983bfb2eef8b4bc1eac36f353724b567cd1ae8cddd64ddb7057549d5c81ad5fa3b5e751f00abf5");
        sig = Hex.decode("2e2e279850ce21e34228a8e810d3ba835c51932e03c5e8886e99036f25a9a43aa5e33168274b7bfc1745ce8fc7ff3335f0927920f09fe9d4a6fac5e546eaf5aedc7e11ba75d33ae1487857b017930e69ec63a10971ca062c0e24f5b08226e59446d02a7827ceecbbcf6ecf0ffa7b3dff3e1a76b5f7432f804a4aa858e18877a5");

        doGenVerify("SHA224withRSA/X9.31", privateKey, publicKey, msg, sig);

        msg = Hex.decode("911475c6e210ef4ac65b6fe8d2bfe5e01b959771b137c4ef69b88716e0d2ff9ebc1fad0f358c1dd7d50cc99a7b893ac9a6207076f08d8467d9e48c69c683bfe64a44dabaa3f7c243880f6ab7229bf7bb587822314fc5de5131983bfb2eef8b4bc1eac36f353724b567cd1ae8cddd64ddb7057549d5c81ad5fa3b5e751f00abf5");
        sig = Hex.decode("4f917837c2aedfb13e8c039cb076e399de39c2a964e418ad541745ff8062ca967d2ce6d51190732d3db089e48e31e95746f306314468c7d2248ace2cfbf4d67c59629a6e61813d52c1a84ea9d21a73b0afa7e871217f2ebeffeaa1268278edfcb7f2f98d1d32ef835123906e8d5f896d1af6877e304a39b03cf014ddaf850911");

        doGenVerify("SHA256withRSA/X9.31", privateKey, publicKey, msg, sig);

        msg = Hex.decode("7d1f36e728dd03b07825c5dcdf6ea933136e1eb819dd8a8aa27c3b0c9b56a0440045b981f1b9cc4107b55a51e81a5136192883cc1442572d9bf1bed44b2c690374d73a612889f8e8929246fe893dd6e26552da4a12dfbb4b63380e78a83dc44e82dba0d0f6d6ef6ec1c5732beb5ea0ff9ff30b7a3a3d1faba2591140d91017ee");
        sig = Hex.decode("1210a59883326234d363155876818f43bdbe7ba758c44104ad771984636e13ecfbad97beb138a836b2d94dafd910ecb5b6ba7de6125a15f683af96220b3370e92ea2e1fb22fcd5e83def31728d9196b59308eb4498dadeddad66e26152b456e613ecc5fc8a7ed33f0608ea1ef886949f3741ab8c41ee453de877e5acea33a557");

        doGenVerify("SHA384withRSA/X9.31", privateKey, publicKey, msg, sig);

        msg = Hex.decode("911475c6e210ef4ac65b6fe8d2bfe5e01b959771b137c4ef69b88716e0d2ff9ebc1fad0f358c1dd7d50cc99a7b893ac9a6207076f08d8467d9e48c69c683bfe64a44dabaa3f7c243880f6ab7229bf7bb587822314fc5de5131983bfb2eef8b4bc1eac36f353724b567cd1ae8cddd64ddb7057549d5c81ad5fa3b5e751f00abf5");
        sig = Hex.decode("154bbde6991b6c8c137a62595619e0038e6787703568a213cff95dac33bc871f7a45f8a3471b823451d1262f7a8932f11d5f93cadbc63daf840e0bbd7d317b57d385be706b58670afac7f055f67d8834f574863b1e295b2a85905bb9926f3114be2be59ad7782321578a451b91587bda7cd6a5051c0fd934af28d5d479463642");

        doGenVerify("SHA512withRSA/X9.31", privateKey, publicKey, msg, sig);
    }

    private void doGenVerify(String algorithm, PrivateKey privateKey, PublicKey publicKey, byte[] msg, byte[] sig)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
    {
        Signature signer = Signature.getInstance(algorithm, "BC");

        signer.initSign(privateKey);

        signer.update(msg, 0, msg.length);

        byte[] s = signer.sign();

        if (!Arrays.areEqual(sig, s))
        {
           fail(algorithm + " sig test 3 failed.");
        }

        signer.initVerify(publicKey);

        signer.update(msg, 0, msg.length);

        if (!signer.verify(sig))
        {
            fail(algorithm + " verify test 3 failed.");
        }
    }

    public String getName()
    {
        return "SigTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SigTest());
    }
}
