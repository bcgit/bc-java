package org.bouncycastle.tls.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.ExporterLabel;
import org.bouncycastle.tls.PRFAlgorithm;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class PRFTest
    extends TestCase
{
    public void testLwTLS11()
    {
        byte[] pre_master_secret = Hex.decode("86051948e4d9a0cd273b6cd3a76557fc695e2ad9517cda97081ed009588a20ab48d0b128de8f917da74e711879460b60");
        byte[] serverHello_random = Hex.decode("55f1f273d4cdd4abb97f6856ed10f83a799dc42403c3f60c4e504419db4fd727");
        byte[] clientHello_random = Hex.decode("0b71e1f7232e675112510cf654a5e6280b3bd8ff078b67ec55276bfaddb92075");
        byte[] server_random = Hex.decode("a62615ee7fee41993588b2542735f90910c5a0f9c5dcb64898fdf3e90dc72a5f");
        byte[] client_random = Hex.decode("7798a130b732d7789e59a5fc14ad331ae91199f7d122e7fd4a594036b0694873");
        byte[] master_secret = Hex.decode("37841ef801f8cbdb49b6a164025de3e0ea8169604ffe80bd98b45cdd34105251cedac7223045ff4c7b67c8a12bf3141c");
        byte[] key_block = Hex.decode("c520e2409fa54facd3da01910f50a28f2f50986beb56b0c7b4cee9122e8f7428b7f7b8277bda931c71d35fdc2ea92127a5a143f63fe145275af5bcdab26113deffbb87a67f965b3964ea1ca29df1841c1708e6f42aacd87c12c4471913f61bb994fe3790b735dd11");

        byte[] msSeed = Arrays.concatenate(clientHello_random, serverHello_random);

        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
        TlsSecret masterSecret = new BcTlsSecret(crypto, pre_master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_legacy, ExporterLabel.master_secret, msSeed, master_secret.length);

        assertTrue("master secret wrong", Arrays.areEqual(master_secret, masterSecret.extract()));

        byte[] keSeed = Arrays.concatenate(server_random, client_random);

        TlsSecret keyExpansion = new BcTlsSecret(crypto, master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_legacy, ExporterLabel.key_expansion, keSeed, key_block.length);

        assertTrue("key expansion error", Arrays.areEqual(key_block, keyExpansion.extract()));
    }

    public void testLwTLS12_SHA256PRF()
    {
        byte[] pre_master_secret = Hex.decode("f8938ecc9edebc5030c0c6a441e213cd24e6f770a50dda07876f8d55da062bcadb386b411fd4fe4313a604fce6c17fbc");
        byte[] serverHello_random = Hex.decode("f6c9575ed7ddd73e1f7d16eca115415812a43c2b747daaaae043abfb50053fce");
        byte[] clientHello_random = Hex.decode("36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c");
        byte[] server_random = Hex.decode("ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868");
        byte[] client_random = Hex.decode("62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616");
        byte[] master_secret = Hex.decode("202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf");
        byte[] key_block = Hex.decode("d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928");

        byte[] msSeed = Arrays.concatenate(clientHello_random, serverHello_random);

        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
        TlsSecret masterSecret = new BcTlsSecret(crypto, pre_master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_sha256, ExporterLabel.master_secret, msSeed, master_secret.length);

        assertTrue("master secret wrong", Arrays.areEqual(master_secret, masterSecret.extract()));

        byte[] keSeed = Arrays.concatenate(server_random, client_random);

        TlsSecret keyExpansion = new BcTlsSecret(crypto, master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_sha256, ExporterLabel.key_expansion, keSeed, key_block.length);

        assertTrue("key expansion error", Arrays.areEqual(key_block, keyExpansion.extract()));
    }

    public void testLwTLS12_SHA384PRF()
    {
        byte[] pre_master_secret = Hex.decode("a5e2642633f5b8c81ad3fe0c2fe3a8e5ef806b06121dd10df4bb0fe857bfdcf522558e05d2682c9a80c741a3aab1716f");
        byte[] serverHello_random = Hex.decode("cb6e0b3eb02976b6466dfa9651c2919414f1648fd3a7838d02153e5bd39535b6");
        byte[] clientHello_random = Hex.decode("abe4bf5527429ac8eb13574d2709e8012bd1a113c6d3b1d3aa2c3840518778ac");
        byte[] server_random = Hex.decode("1b1c8568344a65c30828e7483c0e353e2c68641c9551efae6927d9cd627a107c");
        byte[] client_random = Hex.decode("954b5fe1849c2ede177438261f099a2fcd884d001b9fe1de754364b1f6a6dd8e");
        byte[] master_secret = Hex.decode("b4d49bfa87747fe815457bc3da15073d6ac73389e703079a3503c09e14bd559a5b3c7c601c7365f6ea8c68d3d9596827");
        byte[] key_block = Hex.decode("10fd89ef689c7ef033387b8a8f3e5e8e7c11f680f6bdd71fbac3246a73e98d45d03185dde686e6b2369e4503e9dc5a6d2cee3e2bf2fa3f41d3de57dff3e197c8a9d5f74cc2d277119d894f8584b07a0a5822f0bd68b3433ec6adaf5c9406c5f3ddbb71bbe17ce98f3d4d5893d3179ef369f57aad908e2bf710639100c3ce7e0c");

        byte[] msSeed = Arrays.concatenate(clientHello_random, serverHello_random);

        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
        TlsSecret masterSecret = new BcTlsSecret(crypto, pre_master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_sha384, ExporterLabel.master_secret, msSeed, master_secret.length);

        assertTrue("master secret wrong", Arrays.areEqual(master_secret, masterSecret.extract()));

        byte[] keSeed = Arrays.concatenate(server_random, client_random);

        TlsSecret keyExpansion = new BcTlsSecret(crypto, master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_sha384, ExporterLabel.key_expansion, keSeed, key_block.length);

        assertTrue("key expansion error", Arrays.areEqual(key_block, keyExpansion.extract()));
    }

    public void testTLS11()
    {
        byte[] pre_master_secret = Hex.decode("86051948e4d9a0cd273b6cd3a76557fc695e2ad9517cda97081ed009588a20ab48d0b128de8f917da74e711879460b60");
        byte[] serverHello_random = Hex.decode("55f1f273d4cdd4abb97f6856ed10f83a799dc42403c3f60c4e504419db4fd727");
        byte[] clientHello_random = Hex.decode("0b71e1f7232e675112510cf654a5e6280b3bd8ff078b67ec55276bfaddb92075");
        byte[] server_random = Hex.decode("a62615ee7fee41993588b2542735f90910c5a0f9c5dcb64898fdf3e90dc72a5f");
        byte[] client_random = Hex.decode("7798a130b732d7789e59a5fc14ad331ae91199f7d122e7fd4a594036b0694873");
        byte[] master_secret = Hex.decode("37841ef801f8cbdb49b6a164025de3e0ea8169604ffe80bd98b45cdd34105251cedac7223045ff4c7b67c8a12bf3141c");
        byte[] key_block = Hex.decode("c520e2409fa54facd3da01910f50a28f2f50986beb56b0c7b4cee9122e8f7428b7f7b8277bda931c71d35fdc2ea92127a5a143f63fe145275af5bcdab26113deffbb87a67f965b3964ea1ca29df1841c1708e6f42aacd87c12c4471913f61bb994fe3790b735dd11");

        byte[] msSeed = Arrays.concatenate(clientHello_random, serverHello_random);

        JcaTlsCrypto crypto = (JcaTlsCrypto)new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(new SecureRandom());

        TlsSecret masterSecret = new JceTlsSecret(crypto, pre_master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_legacy, ExporterLabel.master_secret, msSeed, master_secret.length);

        assertTrue("master secret wrong", Arrays.areEqual(master_secret, masterSecret.extract()));

        byte[] keSeed = Arrays.concatenate(server_random, client_random);

        TlsSecret keyExpansion = new JceTlsSecret(crypto, master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_legacy, ExporterLabel.key_expansion, keSeed, key_block.length);

        assertTrue("key expansion error", Arrays.areEqual(key_block, keyExpansion.extract()));
    }

    public void testTLS12_SHA256PRF()
    {
        byte[] pre_master_secret = Hex.decode("f8938ecc9edebc5030c0c6a441e213cd24e6f770a50dda07876f8d55da062bcadb386b411fd4fe4313a604fce6c17fbc");
        byte[] serverHello_random = Hex.decode("f6c9575ed7ddd73e1f7d16eca115415812a43c2b747daaaae043abfb50053fce");
        byte[] clientHello_random = Hex.decode("36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c");
        byte[] server_random = Hex.decode("ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868");
        byte[] client_random = Hex.decode("62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616");
        byte[] master_secret = Hex.decode("202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf");
        byte[] key_block = Hex.decode("d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928");

        byte[] msSeed = Arrays.concatenate(clientHello_random, serverHello_random);

        JcaTlsCrypto crypto = (JcaTlsCrypto)new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(new SecureRandom());

        TlsSecret masterSecret = new JceTlsSecret(crypto, pre_master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_sha256, ExporterLabel.master_secret, msSeed, master_secret.length);

        assertTrue("master secret wrong", Arrays.areEqual(master_secret, masterSecret.extract()));

        byte[] keSeed = Arrays.concatenate(server_random, client_random);

        TlsSecret keyExpansion = new JceTlsSecret(crypto, master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_sha256, ExporterLabel.key_expansion, keSeed, key_block.length);
       
        assertTrue("key expansion error", Arrays.areEqual(key_block, keyExpansion.extract()));
    }

    public void testTLS12_SHA384PRF()
    {
        byte[] pre_master_secret = Hex.decode("a5e2642633f5b8c81ad3fe0c2fe3a8e5ef806b06121dd10df4bb0fe857bfdcf522558e05d2682c9a80c741a3aab1716f");
        byte[] serverHello_random = Hex.decode("cb6e0b3eb02976b6466dfa9651c2919414f1648fd3a7838d02153e5bd39535b6");
        byte[] clientHello_random = Hex.decode("abe4bf5527429ac8eb13574d2709e8012bd1a113c6d3b1d3aa2c3840518778ac");
        byte[] server_random = Hex.decode("1b1c8568344a65c30828e7483c0e353e2c68641c9551efae6927d9cd627a107c");
        byte[] client_random = Hex.decode("954b5fe1849c2ede177438261f099a2fcd884d001b9fe1de754364b1f6a6dd8e");
        byte[] master_secret = Hex.decode("b4d49bfa87747fe815457bc3da15073d6ac73389e703079a3503c09e14bd559a5b3c7c601c7365f6ea8c68d3d9596827");
        byte[] key_block = Hex.decode("10fd89ef689c7ef033387b8a8f3e5e8e7c11f680f6bdd71fbac3246a73e98d45d03185dde686e6b2369e4503e9dc5a6d2cee3e2bf2fa3f41d3de57dff3e197c8a9d5f74cc2d277119d894f8584b07a0a5822f0bd68b3433ec6adaf5c9406c5f3ddbb71bbe17ce98f3d4d5893d3179ef369f57aad908e2bf710639100c3ce7e0c");

        byte[] msSeed = Arrays.concatenate(clientHello_random, serverHello_random);

        JcaTlsCrypto crypto = (JcaTlsCrypto)new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(new SecureRandom());

        TlsSecret masterSecret = new JceTlsSecret(crypto, pre_master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_sha384, ExporterLabel.master_secret, msSeed, master_secret.length);

        assertTrue("master secret wrong", Arrays.areEqual(master_secret, masterSecret.extract()));

        byte[] keSeed = Arrays.concatenate(server_random, client_random);

        TlsSecret keyExpansion = new JceTlsSecret(crypto, master_secret)
            .deriveUsingPRF(PRFAlgorithm.tls_prf_sha384, ExporterLabel.key_expansion, keSeed, key_block.length);

        assertTrue("key expansion error", Arrays.areEqual(key_block, keyExpansion.extract()));
    }
}
