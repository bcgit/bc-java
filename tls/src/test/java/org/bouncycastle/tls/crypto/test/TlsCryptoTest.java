package org.bouncycastle.tls.crypto.test;

import java.io.IOException;

import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public abstract class TlsCryptoTest
    extends TestCase
{
    protected final TlsCrypto crypto;

    protected TlsCryptoTest(TlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public void testECDomain() throws Exception
    {
        if (!crypto.hasECDHAgreement())
        {
            return;
        }

        for (int namedGroup = 0; namedGroup < 256; ++namedGroup)
        {
            if (!NamedGroup.refersToAnECDHCurve(namedGroup) || !crypto.hasNamedGroup(namedGroup))
            {
                continue;
            }

            TlsECDomain d = crypto.createECDomain(new TlsECConfig(namedGroup));

            for (int i = 0; i < 10; ++i)
            {
                TlsAgreement aA = d.createECDH();
                TlsAgreement aB = d.createECDH();

                byte[] pA = aA.generateEphemeral();
                byte[] pB = aB.generateEphemeral();

                aA.receivePeerValue(pB);
                aB.receivePeerValue(pA);

                TlsSecret sA = aA.calculateSecret();
                TlsSecret sB = aB.calculateSecret();

                assertArrayEquals(extract(sA), extract(sB));
            }
        }
    }

    public void testHKDF()
        throws IOException
    {
        /*
         * Test vectors drawn from the server-side calculations of example handshake trace in RFC 8448, section 3.
         */

        short hash = HashAlgorithm.sha256;
        int hashLen = HashAlgorithm.getOutputSize(hash);

        TlsSecret init = crypto.hkdfInit(hash), early, handshake, master, c_hs_t, s_hs_t, c_ap_t, s_ap_t, exp_master, res_master;

        // {server}  extract secret "early":
        {
            byte[] ikm = new byte[32];
            early = init.hkdfExtract(hash, ikm);
            expect(early, "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a");
        }

        // {server}  derive secret for handshake "tls13 derived":
        {
            String label = "derived";
            byte[] transcriptHash = hex("e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55");
            handshake = TlsCryptoUtils.hkdfExpandLabel(early, hash, label, transcriptHash, hashLen);
            expect(handshake, "6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba");
        }

        // {server}  extract secret "handshake":
        {
            byte[] ikm = hex("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d");
            handshake = handshake.hkdfExtract(hash, ikm);
            expect(handshake, "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac");
        }

        // {server}  derive secret "tls13 c hs traffic":
        {
            String label = "c hs traffic";
            byte[] transcriptHash = hex("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");
            c_hs_t = TlsCryptoUtils.hkdfExpandLabel(handshake, hash, label, transcriptHash, hashLen);
            expect(c_hs_t, "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21");
        }

        // {server}  derive secret "tls13 s hs traffic":
        {
            String label = "s hs traffic";
            byte[] transcriptHash = hex("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");
            s_hs_t = TlsCryptoUtils.hkdfExpandLabel(handshake, hash, label, transcriptHash, hashLen);
            expect(s_hs_t, "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38");
        }

        // {server}  derive secret for master "tls13 derived":
        {
            String label = "derived";
            byte[] transcriptHash = hex("e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55");
            master = TlsCryptoUtils.hkdfExpandLabel(handshake, hash, label, transcriptHash, hashLen);
            expect(master, "43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5 31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4");
        }

        // {server}  extract secret "master":
        {
            byte[] ikm = new byte[32];
            master = master.hkdfExtract(hash, ikm);
            expect(master, "18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19");
        }

        // {server}  derive write traffic keys for handshake data:
        {
            TlsSecret key = TlsCryptoUtils.hkdfExpandLabel(s_hs_t, hash, "key", TlsUtils.EMPTY_BYTES, 16);
            expect(key, "3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc");

            TlsSecret iv = TlsCryptoUtils.hkdfExpandLabel(s_hs_t, hash, "iv", TlsUtils.EMPTY_BYTES, 12);
            expect(iv, "5d 31 3e b2 67 12 76 ee 13 00 0b 30");
        }

        // {server}  calculate (server) finished "tls13 finished":
        {
            TlsSecret expanded = TlsCryptoUtils.hkdfExpandLabel(s_hs_t, hash, "finished", TlsUtils.EMPTY_BYTES, hashLen);
            expect(expanded, "00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8");

            // TODO[tls13]
//            finished (32 octets):  9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18
        }

        // {server}  derive secret "tls13 c ap traffic":
        {
            String label = "c ap traffic";
            byte[] transcriptHash = hex("96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
            c_ap_t = TlsCryptoUtils.hkdfExpandLabel(master, hash, label, transcriptHash, hashLen);
            expect(c_ap_t, "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5");
        }

        // {server}  derive secret "tls13 s ap traffic":
        {
            String label = "s ap traffic";
            byte[] transcriptHash = hex("96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
            s_ap_t = TlsCryptoUtils.hkdfExpandLabel(master, hash, label, transcriptHash, hashLen);
            expect(s_ap_t, "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43");
        }

        // {server}  derive secret "tls13 exp master":
        {
            String label = "exp master";
            byte[] transcriptHash = hex("96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
            exp_master = TlsCryptoUtils.hkdfExpandLabel(master, hash, label, transcriptHash, hashLen);
            expect(exp_master, "fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 92 c5 0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43 09 d3 cf 50");
        }

        // {server}  derive write traffic keys for application data:
        {
            TlsSecret key = TlsCryptoUtils.hkdfExpandLabel(s_ap_t, hash, "key", TlsUtils.EMPTY_BYTES, 16);
            expect(key, "9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56");

            TlsSecret iv = TlsCryptoUtils.hkdfExpandLabel(s_ap_t, hash, "iv", TlsUtils.EMPTY_BYTES, 12);
            expect(iv, "cf 78 2b 88 dd 83 54 9a ad f1 e9 84");
        }

        // {server}  derive read traffic keys for handshake data:
        {
            TlsSecret key = TlsCryptoUtils.hkdfExpandLabel(c_hs_t, hash, "key", TlsUtils.EMPTY_BYTES, 16);
            expect(key, "db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01");

            TlsSecret iv = TlsCryptoUtils.hkdfExpandLabel(c_hs_t, hash, "iv", TlsUtils.EMPTY_BYTES, 12);
            expect(iv, "5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f");
        }

        // {server}  calculate (client) finished "tls13 finished":
        {
            TlsSecret expanded = TlsCryptoUtils.hkdfExpandLabel(c_hs_t, hash, "finished", TlsUtils.EMPTY_BYTES, hashLen);
            expect(expanded, "b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d 6b f8 3f 84 82 1d 1f 87 fd c7 d3 c7 5b 5a 7b 42 d9 c4");

            // TODO[tls13]
//            finished (32 octets):  a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61
        }
        
        // {server}  derive read traffic keys for application data:
        {
            TlsSecret key = TlsCryptoUtils.hkdfExpandLabel(c_ap_t, hash, "key", TlsUtils.EMPTY_BYTES, 16);
            expect(key, "17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51");

            TlsSecret iv = TlsCryptoUtils.hkdfExpandLabel(c_ap_t, hash, "iv", TlsUtils.EMPTY_BYTES, 12);
            expect(iv, "5b 78 92 3d ee 08 57 90 33 e5 23 d9");
        }

        // {server}  derive secret "tls13 res master":
        {
            byte[] transcriptHash = hex("20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26 84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d");
            res_master = TlsCryptoUtils.hkdfExpandLabel(master, hash, "res master", transcriptHash, hashLen);
            expect(res_master, "7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c");
        }

        // {server}  generate resumption secret "tls13 resumption":
        {
            byte[] context = hex("00 00");
            TlsSecret expanded = TlsCryptoUtils.hkdfExpandLabel(res_master, hash, "resumption", context, hashLen);
            expect(expanded, "4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3");
        }
    }

    private void expect(TlsSecret secret, String expectedHex)
    {
        expect(secret, hex(expectedHex));
    }

    private void expect(TlsSecret secret, byte[] expectedOctets)
    {
        byte[] actualOctets = extract(secret);

        assertArrayEquals(expectedOctets, actualOctets);
    }

    private byte[] extract(TlsSecret secret)
    {
        return crypto.adoptSecret(secret).extract();
    }

    private static void assertArrayEquals(byte[] a, byte[] b)
    {
        assertTrue(Arrays.areEqual(a, b));
    }

    private static byte[] hex(String s)
    {
        return Hex.decode(s.replaceAll(" ", ""));
    }
}
