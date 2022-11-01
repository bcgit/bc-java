package org.bouncycastle.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.Context;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;

public class HPKETestVectors
        extends TestCase
{

    static class Export
    {
        byte[] exporterContext;
        int L;
        byte[] exportedValue;

        Export(byte[] exporterContext, int L, byte[] exportedValue)
        {
            this.exporterContext = exporterContext;
            this.L = L;
            this.exportedValue = exportedValue;
        }
    }

    static class Encryption
    {
        byte[] aad;
        byte[] ct;
        byte[] nonce;
        byte[] pt;

        Encryption(byte[] aad, byte[] ct, byte[] nonce, byte[] pt)
        {
            this.aad = aad;
            this.ct = ct;
            this.nonce = nonce;
            this.pt = pt;
        }

    }

    public void testBaseOneShotPairwise()
            throws Exception
    {
        // test base oneshot pairwise
        HPKE hpke = new HPKE((byte) 0, (short) 16, (short) 1, (short) 1);

        AsymmetricCipherKeyPair kp = hpke.dhkem.GeneratePrivateKey();
        byte[][] output = hpke.Seal(kp.getPublic(), "info".getBytes(), "aad".getBytes(), "message".getBytes(), null, null, null);
        byte[] ct = output[0];
        byte[] encap = output[1];

        byte[] message = hpke.Open(encap, kp, "info".getBytes(), "aad".getBytes(), ct, null, null, null);
        assertTrue( "Failed", Arrays.areEqual(message, "message".getBytes()));

        try
        {
            byte[] brokenCt = Arrays.concatenate(ct, "eh".getBytes());
            hpke.Open(encap, kp, "info".getBytes(), "aad".getBytes(), brokenCt, null, null, null);
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            assertEquals("Failed", "mac check in GCM failed", e.getMessage());
        }
    }
    public void testAuthOneShotPairwise()
            throws Exception
    {
        // test base oneshot pairwise
        HPKE hpke = new HPKE((byte) 2, (short) 18, (short) 1, (short) 1);

        AsymmetricCipherKeyPair reciever = hpke.dhkem.GeneratePrivateKey();
        AsymmetricCipherKeyPair sender = hpke.dhkem.GeneratePrivateKey();

        byte[][] output = hpke.Seal(reciever.getPublic(), "info".getBytes(), "aad".getBytes(), "message".getBytes(), null, null, sender);
        byte[] ct = output[0];
        byte[] encap = output[1];

        byte[] message = hpke.Open(encap, reciever, "info".getBytes(), "aad".getBytes(), ct, null, null, sender.getPublic());
        assertTrue( "Failed", Arrays.areEqual(message, "message".getBytes()));

        // incorrect ct/tag
        try
        {
            byte[] brokenCt = Arrays.concatenate(ct, "eh".getBytes());
            hpke.Open(encap, reciever, "info".getBytes(), "aad".getBytes(), brokenCt, null, null, sender.getPublic());
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            assertEquals("Failed", "mac check in GCM failed", e.getMessage());
        }

        // incorrect public key
        try
        {
            message = hpke.Open(encap, reciever, "info".getBytes(), "aad".getBytes(), ct, null, null, reciever.getPublic());
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            assertEquals("Failed", "mac check in GCM failed", e.getMessage());
        }

    }

    public void testBasePairwise()
            throws Exception
    {
        HPKE hpke = new HPKE((byte) 0, (short) 16, (short) 1, (short) 1);

        AsymmetricCipherKeyPair receiver = hpke.dhkem.GeneratePrivateKey();

        Context ctxS = hpke.SetupBaseS(receiver.getPublic(), "info".getBytes());
        Context ctxR = hpke.SetupBaseR(ctxS.getEnc(), receiver, "info".getBytes());

        assertTrue(Arrays.areEqual(ctxS.Export("context".getBytes(), 512), ctxR.Export("context".getBytes(), 512)));

        byte[] aad = new byte[32];
        byte[] message = new byte[128];
        byte[] ct;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 128; i++)
        {
            random.nextBytes(aad);
            random.nextBytes(message);
            ct = ctxS.aead.Seal(aad, message);
            assertTrue(Arrays.areEqual(message, ctxR.aead.Open(aad, ct)));
        }
    }

    public void testAuthPairwise()
            throws Exception
    {
        HPKE hpke = new HPKE((byte) 2, (short) 16, (short) 1, (short) 1);

        AsymmetricCipherKeyPair receiver = hpke.dhkem.GeneratePrivateKey();
        AsymmetricCipherKeyPair sender = hpke.dhkem.GeneratePrivateKey();

        Context ctxS = hpke.SetupAuthS(receiver.getPublic(), "info".getBytes(), sender);
        Context ctxR = hpke.SetupAuthR(ctxS.getEnc(), receiver, "info".getBytes(), sender.getPublic());

        assertTrue(Arrays.areEqual(ctxS.Export("context".getBytes(), 512), ctxR.Export("context".getBytes(), 512)));

        byte[] aad = new byte[32];
        byte[] message = new byte[128];
        byte[] ct;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 128; i++)
        {
            random.nextBytes(aad);
            random.nextBytes(message);
            ct = ctxS.aead.Seal(aad, message);
            assertTrue(Arrays.areEqual(message, ctxR.aead.Open(aad, ct)));
        }
    }



    //todo test for not implemented for export only aead


    public void testVectors()
            throws Exception
    {
        InputStream src = HPKETestVectors.class.getResourceAsStream("hpke.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line = null;
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> encBuf = new HashMap<String, String>();
        HashMap<String, String> expBuf = new HashMap<String, String>();
        ArrayList<Encryption> encryptions = new ArrayList<Encryption>();
        ArrayList<Export> exports = new ArrayList<Export>();
        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    String count = (String)buf.get("count");

//                    System.out.println("test case: " + count);
                    byte mode = Byte.parseByte(buf.get("mode"));
                    short kem_id = Short.parseShort((String)buf.get("kem_id"));
                    short kdf_id = Short.parseShort((String)buf.get("kdf_id"));
                    short aead_id = (short) Integer.parseInt((String)buf.get("aead_id"));
                    byte[] info = Hex.decode((String)buf.get("info"));
                    byte[] ikmR = Hex.decode((String)buf.get("ikmR"));
                    byte[] ikmE = Hex.decode((String)buf.get("ikmE"));
                    byte[] skRm = Hex.decode((String)buf.get("skRm"));
                    byte[] skSm = null;    // -> mode 2, 3
                    byte[] skEm = Hex.decode((String)buf.get("skEm"));
                    byte[] psk = null;     // -> mode 1, 3
                    byte[] psk_id = null;  // -> mode 1, 3
                    byte[] pkRm = Hex.decode((String)buf.get("pkRm"));
                    byte[] pkSm = null;    // -> mode 2, 3
                    byte[] pkEm = Hex.decode((String)buf.get("pkEm"));
                    byte[] enc = Hex.decode((String)buf.get("enc"));
                    byte[] shared_secret = Hex.decode((String)buf.get("shared_secret"));
                    byte[] key_schedule_context = Hex.decode((String)buf.get("key_schedule_context"));
                    byte[] secret = Hex.decode((String)buf.get("secret"));
                    byte[] key = Hex.decode((String)buf.get("key"));
                    byte[] base_nonce = Hex.decode((String)buf.get("base_nonce"));
                    byte[] exporter_secret = Hex.decode((String)buf.get("exporter_secret"));
                    if (mode == 2 || mode == 3)
                    {
                        skSm = Hex.decode((String)buf.get("skSm"));
                        pkSm = Hex.decode((String)buf.get("pkSm"));
                    }
                    if (mode == 1 || mode == 3)
                    {
                        psk = Hex.decode((String)buf.get("psk"));
                        psk_id = Hex.decode((String)buf.get("psk_id"));
                    }
//                    if(
//                        kem_id != 16
//                        || mode != 3
//                        || kdf_id != 1
//                        || aead_id != 1
//                    )
//                    {
//                        encryptions.clear();
//                        exports.clear();
//                        continue;
//                    }
                    System.out.println("test case: " + count);
//                    System.out.println("kem_id: " + kem_id);
//                    System.out.println("kdf_id: " + kdf_id);
//                    System.out.println("aead_id: " + aead_id);

                    HPKE hpke = new HPKE(mode, kem_id, kdf_id, aead_id);

                    // Testing AEAD ( encryptions )

                    // init aead with key and nonce
                    hpke.AEAD(key, base_nonce);
                    // enumerate encryptions
                    for (Encryption encryption :encryptions)
                    {
                        // seal with aad and pt and check if output is the same as ct
                        byte[] got_ct = hpke.aead.Seal(encryption.aad, encryption.pt);
                        assertTrue( "AEAD failed Sealing:", Arrays.areEqual(got_ct, encryption.ct));
                    }

                    // Testing main ( different modes )
                    // generate a private key from skRm and pkRm
                    AsymmetricCipherKeyPair kp = hpke.dhkem.DeserializePrivateKey(skRm, pkRm);

                    // create a context with setupRecv
                    // use pkEm as encap, private key from above, info as info

                    Context c = null;
                    AsymmetricKeyParameter senderPub = null;
                    switch (mode)
                    {
                        case 0:
                            c = hpke.SetupBaseR(pkEm, kp, info);
                            break;
                        case 1:
                            c = hpke.SetupPSKR(pkEm, kp, info, psk, psk_id);
                            break;
                        case 2:
                            senderPub = hpke.dhkem.DeserializePublicKey(pkSm);
                            c = hpke.SetupAuthR(pkEm, kp, info, senderPub);
                            break;
                        case 3:
                            senderPub = hpke.dhkem.DeserializePublicKey(pkSm);
                            c = hpke.SetupAuthPSKR(pkEm, kp, info, psk, psk_id, senderPub);
                            break;
                        default:
                            fail("invalid mode");
                    }

                    // enumerate encryptions
                    for (int i = 0; i < encryptions.size(); i++)
                    {
                        Encryption encryption = encryptions.get(i);

                        if (i == 0)
                        {
                            // test one shot api (first only!)
                            // open with pkEm, private key, info, aad, ct
                            // compare output with pt
                            byte[] message = hpke.Open(pkEm, kp, info, encryption.aad, encryption.ct, psk, psk_id, senderPub);

                            // use context open with aad, ct and compare output with pt
                            assertTrue("Single-shot failed", Arrays.areEqual(message, encryption.pt));
                        }

                        byte[] got_pt = c.aead.Open(encryption.aad, encryption.ct);
                        assertTrue("context failed Open", Arrays.areEqual(got_pt, encryption.pt));
                    }

                    // enumerate exports
                    for (Export export : exports)
                    {
                        // use context export with exporter context and L
                        byte[] got_val = c.Export(export.exporterContext, export.L);

                        // compare output with exported value
                        assertTrue("context failed Open", Arrays.areEqual(got_val, export.exportedValue));
                    }

                }
                buf.clear();
                encryptions.clear();
                exports.clear();

                continue;
            }

            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.equals("encryptionsSTART"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.equals("encryptionsSTOP"))
                    {
                        break;
                    }
                    if (line.equals("<"))
                    {
                        byte[] aad = Hex.decode((String)encBuf.get("aad"));
                        byte[] ct = Hex.decode((String)encBuf.get("ct"));
                        byte[] nonce = Hex.decode((String)encBuf.get("nonce"));
                        byte[] pt = Hex.decode((String)encBuf.get("pt"));
                        encryptions.add(new Encryption(aad, ct, nonce, pt));
                        encBuf.clear();
                    }
                    else
                    {
                        int b = line.indexOf("=");
                        if (b > -1)
                        {
                            encBuf.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                        }
                    }
                }
            }

            if (line.equals("exportsSTART"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.equals("exportsSTOP"))
                    {
                        break;
                    }
                    if (line.equals("<"))
                    {
                        byte[] exporterContext = Hex.decode((String) expBuf.get("exporter_context"));
                        int L = Integer.parseInt(expBuf.get("L"));
                        byte[] exportedValue = Hex.decode((String) expBuf.get("exported_value"));
                        exports.add(new Export(exporterContext, L, exportedValue));
                        expBuf.clear();
                    }
                    else
                    {
                        int b = line.indexOf("=");
                        if (b > -1)
                        {
                            expBuf.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                        }
                    }
                }
            }


        }
        System.out.println("testing successful!");

    }
}
