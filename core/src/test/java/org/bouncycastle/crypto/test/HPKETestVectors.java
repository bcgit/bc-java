package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.hpke.Context;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class HPKETestVectors
    extends TestCase
{
    class Encryption
    {
        byte[] aad;
        byte[] ct;

        byte[] nonce;

        byte[] pt;

        public Encryption(byte[] aad, byte[] ct, byte[] nonce, byte[] pt)
        {
            this.aad = aad;
            this.ct = ct;
            this.nonce = nonce;
            this.pt = pt;
        }
    }

    class Export
    {
        byte[] exporter_context;
        int L;
        byte[] exported_value;

        public Export(byte[] exporter_context, int l, byte[] exported_value)
        {
            this.exporter_context = exporter_context;
            L = l;
            this.exported_value = exported_value;
        }
    }

    public void testVectors()
        throws Exception
    {
        InputStream src = HPKETestVectors.class.getResourceAsStream("/org/bouncycastle/crypto/test/hpke.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> bufEnc = new HashMap<String, String>();
        HashMap<String, String> bufExp = new HashMap<String, String>();
        ArrayList<Encryption> encryptions = new ArrayList<Encryption>();
        ArrayList<Export> exports = new ArrayList<Export>();
        String line = null;

        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if (line.startsWith("#"))
            {
                continue;
            }
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    String count = (String)buf.get("count");
                    System.out.println("test case: " + count);

                    byte mode = Byte.parseByte((String)buf.get("mode"));
                    short kem_id = (short)Integer.parseInt((String)buf.get("kem_id"));
                    short kdf_id = (short)Integer.parseInt((String)buf.get("kdf_id"));
                    short aead_id = (short)Integer.parseInt((String)buf.get("aead_id"));
                    byte[] info = Hex.decode((String)buf.get("info"));
                    byte[] ikmR = Hex.decode((String)buf.get("ikmR"));
                    byte[] ikmE = Hex.decode((String)buf.get("ikmE"));
                    byte[] ikmS = null;
                    byte[] skRm = Hex.decode((String)buf.get("skRm"));
                    byte[] skSm = null;
                    byte[] skEm = Hex.decode((String)buf.get("skEm"));
                    byte[] pkRm = Hex.decode((String)buf.get("pkRm"));
                    byte[] pkSm = null;
                    byte[] pkEm = Hex.decode((String)buf.get("pkEm"));
                    byte[] psk = null;
                    byte[] psk_id = null;
                    byte[] enc = Hex.decode((String)buf.get("enc"));
                    byte[] shared_secret = Hex.decode((String)buf.get("shared_secret"));
                    byte[] key_schedule_context = Hex.decode((String)buf.get("key_schedule_context"));
                    byte[] secret = Hex.decode((String)buf.get("secret"));
                    byte[] key = Hex.decode((String)buf.get("key"));
                    byte[] base_nonce = Hex.decode((String)buf.get("base_nonce"));
                    byte[] exporter_secret = Hex.decode((String)buf.get("exporter_secret"));
                    if (mode == 2 || mode == 3)
                    {
                        pkSm = Hex.decode((String)buf.get("pkSm"));
                        ikmS = Hex.decode((String)buf.get("ikmS"));
                        skSm = Hex.decode((String)buf.get("skSm"));
                    }
                    if (mode == 1 || mode == 3)
                    {
                        psk = Hex.decode((String)buf.get("psk"));
                        psk_id = Hex.decode((String)buf.get("psk_id"));
                    }


                    HPKE hpke = new HPKE(mode, kem_id, kdf_id, aead_id);

                    // Testing AEAD
                    Context c;
                    for (Encryption encryption : encryptions)
                    {
                        hpke.AEAD(key, encryption.nonce);
                        assertTrue(Arrays.areEqual(hpke.aead.Seal(encryption.aad, encryption.pt), encryption.ct));
                    }

                    // Testing HPKE
                    AsymmetricCipherKeyPair receiver = hpke.dhkem.DeserializePrivateKey(skRm, pkRm);
                    AsymmetricKeyParameter sender = null;
                    Context ctx;
                    byte[] message;

                    switch (mode)
                    {
                    case 0:
                        ctx = hpke.SetupBaseR(pkEm, receiver, info);
                        break;
                    case 1:
                        ctx = hpke.SetupPSKR(pkEm, receiver, info, psk, psk_id);
                        break;
                    case 2:
                        sender = hpke.dhkem.DeserializePublicKey(pkSm);
                        ctx = hpke.SetupAuthR(pkEm, receiver, info, sender);
                        break;
                    case 3:
                        sender = hpke.dhkem.DeserializePublicKey(pkSm);
                        ctx = hpke.SetupAuthPSKR(pkEm, receiver, info, psk, psk_id, sender);
                        break;
                    default:
                        throw new Exception("invalid mode");
                    }

                    byte[] got;
                    for (int i = 0; i < encryptions.size(); i++)
                    {
                        Encryption encryption = encryptions.get(i);
                        // testing one shot api
                        if (i == 0)
                        {
                            message = hpke.Open(pkEm, receiver, info, encryption.aad, encryption.ct, psk, psk_id, sender);
                            assertTrue(Arrays.areEqual(message, encryption.pt));
                        }
                        message = ctx.aead.Open(encryption.aad, encryption.ct);
                        assertTrue(Arrays.areEqual(message, encryption.pt));
                    }
                    for (Export export : exports)
                    {
                        got = ctx.Export(export.exporter_context, export.L);
                        assertTrue(Arrays.areEqual(got, export.exported_value));
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

            a = line.indexOf("encryptionsSTART");
            if (a > -1)
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();

                    if (line.equals("<"))
                    {
                        if (buf.size() > 0)
                        {
                            byte[] aad = Hex.decode((String)bufEnc.get("aad"));
                            byte[] ct = Hex.decode((String)bufEnc.get("ct"));
                            byte[] nonce = Hex.decode((String)bufEnc.get("nonce"));
                            byte[] pt = Hex.decode((String)bufEnc.get("pt"));
                            encryptions.add(new Encryption(aad, ct, nonce, pt));
                            bufEnc.clear();
                        }
                    }

                    a = line.indexOf("=");

                    if (a > -1)
                    {
                        bufEnc.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                    }

                    if (line.equals("encryptionsSTOP"))
                    {
                        break;
                    }
                }
            }
            a = line.indexOf("exportsSTART");
            if (a > -1)
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();

                    if (line.equals("<"))
                    {
                        if (buf.size() > 0)
                        {
                            byte[] exporter_context = Hex.decode((String)bufExp.get("exporter_context"));
                            int L = Integer.parseInt(((String)bufExp.get("L")));
                            byte[] exported_value = Hex.decode((String)bufExp.get("exported_value"));
                            exports.add(new Export(exporter_context, L, exported_value));
                            bufExp.clear();
                        }
                    }

                    a = line.indexOf("=");

                    if (a > -1)
                    {
                        bufExp.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                    }

                    if (line.equals("exportsSTOP"))
                    {
                        break;
                    }
                }
            }

        }


    }
}
