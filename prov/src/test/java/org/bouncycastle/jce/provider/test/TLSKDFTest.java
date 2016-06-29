package org.bouncycastle.jce.provider.test;

import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.jcajce.spec.TLSKeyMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class TLSKDFTest
    extends SimpleTest
{
    public String getName()
    {
        return "TLSKDF";
    }

    private void testTls10()
        throws Exception
    {
        byte[] pre_master_secret = Hex.decode("bded7fa5c1699c010be23dd06ada3a48349f21e5f86263d512c0c5cc379f0e780ec55d9844b2f1db02a96453513568d0");
        byte[] serverHello_random = Hex.decode("135e4d557fdf3aa6406d82975d5c606a9734c9334b42136e96990fbd5358cdb2");
        byte[] clientHello_random = Hex.decode("e5acaf549cd25c22d964c0d930fa4b5261d2507fad84c33715b7b9a864020693");
        byte[] server_random = Hex.decode("67267e650eb32444119d222a368c191af3082888dc35afe8368e638c828874be");
        byte[] client_random = Hex.decode("d58a7b1cd4fedaa232159df652ce188f9d997e061b9bf48e83b62990440931f6");
        byte[] master_secret = Hex.decode("2f6962dfbc744c4b2138bb6b3d33054c5ecc14f24851d9896395a44ab3964efc2090c5bf51a0891209f46c1e1e998f62");
        byte[] key_block = Hex.decode("3088825988e77fce68d19f756e18e43eb7fe672433504feaf99b3c503d9091b164f166db301d70c9fc0870b4a94563907bee1a61fb786cb717576890bcc51cb9ead97e01d0a2fea99c953377b195205ff07b369589178796edc963fd80fdbe518a2fc1c35c18ae8d");

        SecretKeyFactory kFact = SecretKeyFactory.getInstance("TLS10KDF", "BC");

        SecretKey keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(pre_master_secret, TLSKeyMaterialSpec.MASTER_SECRET, master_secret.length, clientHello_random, serverHello_random));

        isTrue("name mismatch (10): " + keyMaterial.getAlgorithm(), keyMaterial.getAlgorithm().equals("TLS10KDF"));

        isTrue("key block error (pre)", Arrays.areEqual(master_secret, keyMaterial.getEncoded()));

        keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(master_secret, TLSKeyMaterialSpec.KEY_EXPANSION, key_block.length, server_random, client_random));

        isTrue("key block error", Arrays.areEqual(key_block, keyMaterial.getEncoded()));
    }

    private void testTls11()
        throws Exception
    {
        byte[] pre_master_secret = Hex.decode("bded7fa5c1699c010be23dd06ada3a48349f21e5f86263d512c0c5cc379f0e780ec55d9844b2f1db02a96453513568d0");
        byte[] serverHello_random = Hex.decode("135e4d557fdf3aa6406d82975d5c606a9734c9334b42136e96990fbd5358cdb2");
        byte[] clientHello_random = Hex.decode("e5acaf549cd25c22d964c0d930fa4b5261d2507fad84c33715b7b9a864020693");
        byte[] server_random = Hex.decode("67267e650eb32444119d222a368c191af3082888dc35afe8368e638c828874be");
        byte[] client_random = Hex.decode("d58a7b1cd4fedaa232159df652ce188f9d997e061b9bf48e83b62990440931f6");
        byte[] master_secret = Hex.decode("2f6962dfbc744c4b2138bb6b3d33054c5ecc14f24851d9896395a44ab3964efc2090c5bf51a0891209f46c1e1e998f62");
        byte[] key_block = Hex.decode("3088825988e77fce68d19f756e18e43eb7fe672433504feaf99b3c503d9091b164f166db301d70c9fc0870b4a94563907bee1a61fb786cb717576890bcc51cb9ead97e01d0a2fea99c953377b195205ff07b369589178796edc963fd80fdbe518a2fc1c35c18ae8d");

        SecretKeyFactory kFact = SecretKeyFactory.getInstance("TLS11KDF", "BC");

        SecretKey keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(pre_master_secret, TLSKeyMaterialSpec.MASTER_SECRET, master_secret.length, clientHello_random, serverHello_random));

        isTrue("name mismatch (11): " + keyMaterial.getAlgorithm(), keyMaterial.getAlgorithm().equals("TLS11KDF"));

        isTrue("key block error (pre)", Arrays.areEqual(master_secret, keyMaterial.getEncoded()));

        keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(master_secret, TLSKeyMaterialSpec.KEY_EXPANSION, key_block.length, server_random, client_random));

        isTrue("key block error", Arrays.areEqual(key_block, keyMaterial.getEncoded()));
    }

    private void testTls12Sha256()
        throws Exception
    {
        byte[] pre_master_secret = Hex.decode("f8938ecc9edebc5030c0c6a441e213cd24e6f770a50dda07876f8d55da062bcadb386b411fd4fe4313a604fce6c17fbc");
        byte[] serverHello_random = Hex.decode("f6c9575ed7ddd73e1f7d16eca115415812a43c2b747daaaae043abfb50053fce");
        byte[] clientHello_random = Hex.decode("36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c");
        byte[] server_random = Hex.decode("ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868");
        byte[] client_random = Hex.decode("62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616");
        byte[] master_secret = Hex.decode("202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf");
        byte[] key_block = Hex.decode("d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928");

        SecretKeyFactory kFact = SecretKeyFactory.getInstance("TLS12withSHA256KDF", "BC");

        SecretKey keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(pre_master_secret, TLSKeyMaterialSpec.MASTER_SECRET, master_secret.length, clientHello_random, serverHello_random));

        isTrue("name mismatch (12-256)", keyMaterial.getAlgorithm().equals("TLS12withSHA256KDF"));

        isTrue("key block error (pre)", Arrays.areEqual(master_secret, keyMaterial.getEncoded()));

        keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(master_secret, TLSKeyMaterialSpec.KEY_EXPANSION, key_block.length, server_random, client_random));

        isTrue("key block error", Arrays.areEqual(key_block, keyMaterial.getEncoded()));
    }

    private void testTls12Sha384()
        throws Exception
    {
        byte[] pre_master_secret = Hex.decode("a5e2642633f5b8c81ad3fe0c2fe3a8e5ef806b06121dd10df4bb0fe857bfdcf522558e05d2682c9a80c741a3aab1716f");
        byte[] serverHello_random = Hex.decode("cb6e0b3eb02976b6466dfa9651c2919414f1648fd3a7838d02153e5bd39535b6");
        byte[] clientHello_random = Hex.decode("abe4bf5527429ac8eb13574d2709e8012bd1a113c6d3b1d3aa2c3840518778ac");
        byte[] server_random = Hex.decode("1b1c8568344a65c30828e7483c0e353e2c68641c9551efae6927d9cd627a107c");
        byte[] client_random = Hex.decode("954b5fe1849c2ede177438261f099a2fcd884d001b9fe1de754364b1f6a6dd8e");
        byte[] master_secret = Hex.decode("b4d49bfa87747fe815457bc3da15073d6ac73389e703079a3503c09e14bd559a5b3c7c601c7365f6ea8c68d3d9596827");
        byte[] key_block = Hex.decode("10fd89ef689c7ef033387b8a8f3e5e8e7c11f680f6bdd71fbac3246a73e98d45d03185dde686e6b2369e4503e9dc5a6d2cee3e2bf2fa3f41d3de57dff3e197c8a9d5f74cc2d277119d894f8584b07a0a5822f0bd68b3433ec6adaf5c9406c5f3ddbb71bbe17ce98f3d4d5893d3179ef369f57aad908e2bf710639100c3ce7e0c");

        SecretKeyFactory kFact = SecretKeyFactory.getInstance("TLS12withSHA384KDF", "BC");

        SecretKey keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(pre_master_secret, TLSKeyMaterialSpec.MASTER_SECRET, master_secret.length, clientHello_random, serverHello_random));

        isTrue("name mismatch (12-384)", keyMaterial.getAlgorithm().equals("TLS12withSHA384KDF"));

        isTrue("key block error (pre)", Arrays.areEqual(master_secret, keyMaterial.getEncoded()));

        keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(master_secret, TLSKeyMaterialSpec.KEY_EXPANSION, key_block.length, server_random, client_random));

        isTrue("key block error", Arrays.areEqual(key_block, keyMaterial.getEncoded()));
    }

    private void testTls12Sha512()
        throws Exception
    {
        byte[] pre_master_secret = Hex.decode("dfef39af25c12663a91ee5d27042b9644a16ef55b81055d1bd7dcb0b8f06eb001708cdefcf82591defca1a6f1ac693ab");
        byte[] serverHello_random = Hex.decode("e2339a6c681eb30808883971b1ce5b9b1ece0f3d011a96a7fff1f5f9d80ffd4b");
        byte[] clientHello_random = Hex.decode("78bc5298dfe9cf8ed336c2e2f0f6b46e2456f39f35f1143cd21eaa16277025b2");
        byte[] server_random = Hex.decode("11cfbd3b45e5e917c4edbabc27b9feac833bbbacabd079465b2759fab3063330");
        byte[] client_random = Hex.decode("b5c41ac5ebd55d136d916547fee741bc1b509f766d50b29d7378b0cebace3c8a");
        byte[] master_secret = Hex.decode("a70c5fe8d34b645a20ce98969bd30858e729c77c8a5f05d3e289219d6b5752b75b75e1ca00d3329658d7f188ed1ab7e0");
        byte[] key_block = Hex.decode("a56650076e6bdaad7e1ea42d68a0f5ffead9b6b5232ba538767e4cc6a3ae9abcae897b068645496cd620f865ce0879081a98901fb98b112ce1f00165e7d6b3288eb4d4ed9811fdbbc24e290b8e448c71da72498449ea67cfdafd66adc31a89d83cc44cf01c749fb531494ff8cb9a677762a7220e32b7f251fde09841bf97110e");

        SecretKeyFactory kFact = SecretKeyFactory.getInstance("TLS12withSHA512KDF", "BC");

        SecretKey keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(pre_master_secret, TLSKeyMaterialSpec.MASTER_SECRET, master_secret.length, clientHello_random, serverHello_random));

        isTrue("name mismatch (12-512)", keyMaterial.getAlgorithm().equals("TLS12withSHA512KDF"));

        isTrue("key block error (pre)", Arrays.areEqual(master_secret, keyMaterial.getEncoded()));

        keyMaterial = kFact.generateSecret(new TLSKeyMaterialSpec(master_secret, TLSKeyMaterialSpec.KEY_EXPANSION, key_block.length, server_random, client_random));

        isTrue("key block error", Arrays.areEqual(key_block, keyMaterial.getEncoded()));
    }

    public void performTest()
        throws Exception
    {
        testTls10();
        testTls11();
        testTls12Sha256();
        testTls12Sha384();
        testTls12Sha512();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new TLSKDFTest());
    }
}
