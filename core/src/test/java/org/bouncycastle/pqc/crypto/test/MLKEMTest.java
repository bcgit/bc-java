package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PQCOtherInfoGenerator;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class MLKEMTest
    extends TestCase
{
    private static final Map<String, MLKEMParameters> parametersMap = new HashMap<String, MLKEMParameters>()
    {
        {
            put("ML-KEM-512", MLKEMParameters.ml_kem_512);
            put("ML-KEM-768", MLKEMParameters.ml_kem_768);
            put("ML-KEM-1024", MLKEMParameters.ml_kem_1024);
        }
    };

    public void testKeyGen() throws IOException
    {
        MLKEMParameters[] params = new MLKEMParameters[]{
            MLKEMParameters.ml_kem_512,
            MLKEMParameters.ml_kem_768,
            MLKEMParameters.ml_kem_1024,
        };

        String[] files = new String[]{
            "keyGen_ML-KEM-512.txt",
            "keyGen_ML-KEM-768.txt",
            "keyGen_ML-KEM-1024.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/kyber/acvp", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
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
                        byte[] z = Hex.decode((String)buf.get("z"));
                        byte[] d = Hex.decode((String)buf.get("d"));
                        byte[] ek = Hex.decode((String)buf.get("ek"));
                        byte[] dk = Hex.decode((String)buf.get("dk"));

                        MLKEMParameters parameters = params[fileIndex];

                        MLKEMKeyPairGenerator kpGen = new MLKEMKeyPairGenerator();
                        MLKEMKeyGenerationParameters genParam = new MLKEMKeyGenerationParameters(new SecureRandom(), parameters);

                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParam);
                        AsymmetricCipherKeyPair kp = kpGen.internalGenerateKeyPair(d, z);

                        MLKEMPublicKeyParameters pubParams = (MLKEMPublicKeyParameters)PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((MLKEMPublicKeyParameters)kp.getPublic()));
                        MLKEMPrivateKeyParameters privParams = (MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo((MLKEMPrivateKeyParameters)kp.getPrivate()));

                        assertTrue(name + ": public key", Arrays.areEqual(ek, pubParams.getEncoded()));
                        assertTrue(name + ": secret key", Arrays.areEqual(dk, privParams.getEncoded()));

                    }
                    buf.clear();

                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
        }
    }

    public void testKeyGenCombinedVectorSet() throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/mlkem", "ML-KEM-keyGen.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        String line = null;
        HashMap<String, String> buf = new HashMap<String, String>();
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
                    byte[] z = Hex.decode((String)buf.get("z"));
                    byte[] d = Hex.decode((String)buf.get("d"));
                    byte[] ek = Hex.decode((String)buf.get("ek"));
                    byte[] dk = Hex.decode((String)buf.get("dk"));

                    MLKEMParameters parameters = (MLKEMParameters)parametersMap.get((String)buf.get("parameterSet"));

                    MLKEMKeyPairGenerator kpGen = new MLKEMKeyPairGenerator();
                    MLKEMKeyGenerationParameters genParam = new MLKEMKeyGenerationParameters(new SecureRandom(), parameters);

                    //
                    // Generate keys and test.
                    //
                    kpGen.init(genParam);
                    AsymmetricCipherKeyPair kp = kpGen.internalGenerateKeyPair(d, z);

                    MLKEMPublicKeyParameters pubParams = (MLKEMPublicKeyParameters)PublicKeyFactory.createKey(
                        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((MLKEMPublicKeyParameters)kp.getPublic()));
                    MLKEMPrivateKeyParameters privParams = (MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(
                        PrivateKeyInfoFactory.createPrivateKeyInfo((MLKEMPrivateKeyParameters)kp.getPrivate()));

                    assertTrue("public key", Arrays.areEqual(ek, pubParams.getEncoded()));
                    assertTrue("secret key", Arrays.areEqual(dk, privParams.getEncoded()));
                }
                buf.clear();

                continue;
            }

            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    public void testEncapDecap_encapsulation() throws IOException
    {
        MLKEMParameters[] params = new MLKEMParameters[]{
            MLKEMParameters.ml_kem_512,
            MLKEMParameters.ml_kem_768,
            MLKEMParameters.ml_kem_1024,
        };

        String[] files = new String[]{
            "encapDecap_encapsulation_ML-KEM-512.txt",
            "encapDecap_encapsulation_ML-KEM-768.txt",
            "encapDecap_encapsulation_ML-KEM-1024.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/kyber/acvp", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
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
                        byte[] m = Hex.decode((String)buf.get("m"));
                        byte[] c = Hex.decode((String)buf.get("c"));
                        byte[] k = Hex.decode((String)buf.get("k"));
//                        String reason = (String)buf.get("reason");
                        byte[] ek = Hex.decode((String)buf.get("ek"));
//                        byte[] dk = Hex.decode((String)buf.get("dk"));

                        MLKEMParameters parameters = params[fileIndex];

                        MLKEMPublicKeyParameters pubKey = new MLKEMPublicKeyParameters(parameters, ek);
//                        MLKEMPrivateKeyParameters privKey = new MLKEMPrivateKeyParameters(parameters,  dk);

                        MLKEMPublicKeyParameters pubParams = (MLKEMPublicKeyParameters)PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((MLKEMPublicKeyParameters)pubKey));
//                        MLKEMPrivateKeyParameters privParams = (MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(
//                            PrivateKeyInfoFactory.createPrivateKeyInfo((MLKEMPrivateKeyParameters)privKey));

                        // KEM Enc
                        MLKEMGenerator generator = new MLKEMGenerator(new SecureRandom());
                        SecretWithEncapsulation secWenc = generator.internalGenerateEncapsulated(pubParams, m);
                        byte[] generated_cipher_text = secWenc.getEncapsulation();

                        byte[] secret = secWenc.getSecret();
                        assertTrue(name  + ": c", Arrays.areEqual(c,  generated_cipher_text));
                        assertTrue(name  + ": k", Arrays.areEqual(k, 0, secret.length, secret, 0, secret.length));

                    }
                    buf.clear();

                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
        }
    }

    public void testEncapDecap_decapsulation() throws IOException
    {
        MLKEMParameters[] params = new MLKEMParameters[]{
            MLKEMParameters.ml_kem_512,
            MLKEMParameters.ml_kem_768,
            MLKEMParameters.ml_kem_1024,
        };

        String[] files = new String[]{
            "encapDecap_decapsulation_ML-KEM-512.txt",
            "encapDecap_decapsulation_ML-KEM-768.txt",
            "encapDecap_decapsulation_ML-KEM-1024.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/kyber/acvp", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
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
                        byte[] c = Hex.decode((String)buf.get("c"));
                        byte[] k = Hex.decode((String)buf.get("k"));
//                        String reason = (String)buf.get("reason");
//                        byte[] ek = Hex.decode((String)buf.get("ek"));
                        byte[] dk = Hex.decode((String)buf.get("dk"));

                        MLKEMParameters parameters = params[fileIndex];

//                        MLKEMPublicKeyParameters pubKey = new MLKEMPublicKeyParameters(parameters, ek);
                        MLKEMPrivateKeyParameters privKey = new MLKEMPrivateKeyParameters(parameters,  dk);

//                        MLKEMPublicKeyParameters pubParams = (MLKEMPublicKeyParameters)PublicKeyFactory.createKey(
//                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((MLKEMPublicKeyParameters)pubKey));
                        MLKEMPrivateKeyParameters privParams = (MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo((MLKEMPrivateKeyParameters)privKey));

                        MLKEMExtractor extractor = new MLKEMExtractor(privParams);

                        byte[] dec_key = extractor.extractSecret(c);

                        assertTrue(name  + ": dk", Arrays.areEqual(dec_key,  k));
                    }
                    buf.clear();

                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
        }
    }

    public void testEncapDecapCombinedVectorSet() throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/mlkem", "ML-KEM-encapDecap.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        String line = null;
        HashMap<String, String> buf = new HashMap<String, String>();
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
                    byte[] c = Hex.decode((String)buf.get("c"));
                    byte[] k = Hex.decode((String)buf.get("k"));

                    MLKEMParameters parameters = (MLKEMParameters)parametersMap.get((String)buf.get("parameterSet"));

                    String function = (String)buf.get("function");
                    if ("encapsulation".equals(function))
                    {
                        byte[] m = Hex.decode((String)buf.get("m"));
                        byte[] ek = Hex.decode((String)buf.get("ek"));

                        MLKEMPublicKeyParameters pubKey = new MLKEMPublicKeyParameters(parameters, ek);

                        MLKEMPublicKeyParameters pubParams = (MLKEMPublicKeyParameters)PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((MLKEMPublicKeyParameters)pubKey));

                        MLKEMGenerator generator = new MLKEMGenerator(new SecureRandom());
                        SecretWithEncapsulation secWenc = generator.internalGenerateEncapsulated(pubParams, m);
                        byte[] generated_cipher_text = secWenc.getEncapsulation();
                        byte[] secret = secWenc.getSecret();

                        assertTrue("encap: c", Arrays.areEqual(c,  generated_cipher_text));
                        assertTrue("encap: k", Arrays.areEqual(k, 0, secret.length, secret, 0, secret.length));
                    }
                    else
                    {
                        byte[] dk = Hex.decode((String)buf.get("dk"));
                        
                        MLKEMPrivateKeyParameters privKey = new MLKEMPrivateKeyParameters(parameters,  dk);

                        MLKEMPrivateKeyParameters privParams = (MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo((MLKEMPrivateKeyParameters)privKey));

                        MLKEMExtractor extractor = new MLKEMExtractor(privParams);
                        byte[] dec_key = extractor.extractSecret(c);

                        assertTrue("decap: dk", Arrays.areEqual(dec_key,  k));
                    }
                }
                buf.clear();

                continue;
            }

            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    public void testModulus() throws IOException
    {
        MLKEMParameters[] params = new MLKEMParameters[]{
            MLKEMParameters.ml_kem_512,
            MLKEMParameters.ml_kem_768,
            MLKEMParameters.ml_kem_1024,
        };

        String[] files = new String[]{
            "ML-KEM-512.txt",
            "ML-KEM-768.txt",
            "ML-KEM-1024.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/kyber/modulus", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();
                byte[] key = Hex.decode(line);
                MLKEMParameters parameters = params[fileIndex];

                MLKEMPublicKeyParameters pubParams = (MLKEMPublicKeyParameters) PublicKeyFactory.createKey(
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(new MLKEMPublicKeyParameters(parameters, key)));

                // KEM Enc
                SecureRandom random = new SecureRandom();
                MLKEMGenerator generator = new MLKEMGenerator(random);
                try
                {
                    SecretWithEncapsulation secWenc = generator.generateEncapsulated(pubParams);
                    byte[] generated_cipher_text = secWenc.getEncapsulation();
                    fail();
                }
                catch (Exception ignored)
                {
                }
            }
        }
    }

    public void testPrivInfoGeneration()
        throws IOException
    {
        SecureRandom random = new SecureRandom();
        PQCOtherInfoGenerator.PartyU partyU = new PQCOtherInfoGenerator.PartyU(MLKEMParameters.ml_kem_512,
            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partA = partyU.getSuppPrivInfoPartA();

        PQCOtherInfoGenerator.PartyV partyV = new PQCOtherInfoGenerator.PartyV(MLKEMParameters.ml_kem_512,
            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partB = partyV.getSuppPrivInfoPartB(partA);

        DEROtherInfo otherInfoU = partyU.generate(partB);

        DEROtherInfo otherInfoV = partyV.generate();

        assertTrue(Arrays.areEqual(otherInfoU.getEncoded(), otherInfoV.getEncoded()));
    }
    
    public void testMLKEM()
    {
        byte[] z = Hex.decode("99E3246884181F8E1DD44E0C7629093330221FD67D9B7D6E1510B2DBAD8762F7");
        byte[] d = Hex.decode("49AC8B99BB1E6A8EA818261F8BE68BDEAA52897E7EC6C40B530BC760AB77DCE3");
        String expectedPubKey = "A04184D4BC7B532A0F70A54D7757CDE6175A6843B861CB2BC4830C0012554CFC5D2C8A2027AA3CD967130E9B96241B11C4320C7649CC23A71BAFE691AFC08E680BCEF42907000718E4EACE8DA28214197BE1C269DA9CB541E1A3CE97CFADF9C6058780FE6793DBFA8218A2760B802B8DA2AA271A38772523A76736A7A31B9D3037AD21CEBB11A472B8792EB17558B940E70883F264592C689B240BB43D5408BF446432F412F4B9A5F6865CC252A43CF40A320391555591D67561FDD05353AB6B019B3A08A73353D51B6113AB2FA51D975648EE254AF89A230504A236A4658257740BDCBBE1708AB022C3C588A410DB3B9C308A06275BDF5B4859D3A2617A295E1A22F90198BAD0166F4A943417C5B831736CB2C8580ABFDE5714B586ABEEC0A175A08BC710C7A2895DE93AC438061BF7765D0D21CD418167CAF89D1EFC3448BCBB96D69B3E010C82D15CAB6CACC6799D3639669A5B21A633C865F8593B5B7BC800262BB837A924A6C5440E4FC73B41B23092C3912F4C6BEBB4C7B4C62908B03775666C22220DF9C88823E344C7308332345C8B795D34E8C051F21F5A21C214B69841358709B1C305B32CC2C3806AE9CCD3819FFF4507FE520FBFC27199BC23BE6B9B2D2AC1717579AC769279E2A7AAC68A371A47BA3A7DBE016F14E1A727333663C4A5CD1A0F8836CF7B5C49AC51485CA60345C990E06888720003731322C5B8CD5E6907FDA1157F468FD3FC20FA8175EEC95C291A262BA8C5BE990872418930852339D88A19B37FEFA3CFE82175C224407CA414BAEB37923B4D2D83134AE154E490A9B45A0563B06C953C3301450A2176A07C614A74E3478E48509F9A60AE945A8EBC7815121D90A3B0E07091A096CF02C57B25BCA58126AD0C629CE166A7EDB4B33221A0D3F72B85D562EC698B7D0A913D73806F1C5C87B38EC003CB303A3DC51B4B35356A67826D6EDAA8FEB93B98493B2D1C11B676A6AD9506A1AAAE13A824C7C08D1C6C2C4DBA9642C76EA7F6C8264B64A23CCCA9A74635FCBF03E00F1B5722B214376790793B2C4F0A13B5C40760B4218E1D2594DCB30A70D9C1782A5DD30576FA4144BFC8416EDA8118FC6472F56A979586F33BB070FB0F1B0B10BC4897EBE01BCA3893D4E16ADB25093A7417D0708C83A26322E22E6330091E30152BF823597C04CCF4CFC7331578F43A2726CCB428289A90C863259DD180C5FF142BEF41C7717094BE07856DA2B140FA67710967356AA47DFBC8D255B4722AB86D439B7E0A6090251D2D4C1ED5F20BBE6807BF65A90B7CB2EC0102AF02809DC9AC7D0A3ABC69C18365BCFF59185F33996887746185906C0191AED4407E139446459BE29C6822717644353D24AB6339156A9C424909F0A9025BB74720779BE43F16D81C8CC666E99710D8C68BB5CC4E12F314E925A551F09CC59003A1F88103C254BB978D75F394D3540E31E771CDA36E39EC54A62B5832664D821A72F1E6AFBBA27F84295B2694C498498E812BC8E9378FE541CEC5891B25062901CB7212E3CDC46179EC5BCEC10BC0B9311DE05074290687FD6A5392671654284CD9C8CC3EBA80EB3B662EB53EB75116704A1FEB5C2D056338532868DDF24EB8992AB8565D9E490CADF14804360DAA90718EAB616BAB0765D33987B47EFB6599C5563235E61E4BE670E97955AB292D9732CB8930948AC82DF230AC72297A23679D6B94C17F1359483254FEDC2F05819F0D069A443B78E3FC6C3EF4714B05A3FCA81CBBA60242A7060CD885D8F39981BB18092B23DAA59FD9578388688A09BBA079BC809A54843A60385E2310BBCBCC0213CE3DFAAB33B47F9D6305BC95C6107813C585C4B657BF30542833B14949F573C0612AD524BAAE69590C1277B86C286571BF66B3CFF46A3858C09906A794DF4A06E9D4B0A2E43F10F72A6C6C47E5646E2C799B71C33ED2F01EEB45938EB7A4E2E2908C53558A540D350369FA189C616943F7981D7618CF02A5B0A2BCC422E857D1A47871253D08293C1C179BCDC0437069107418205FDB9856623B8CA6B694C96C084B17F13BB6DF12B2CFBBC2B0E0C34B00D0FCD0AECFB27924F6984E747BE2A09D83A8664590A8077331491A4F7D720843F23E652C6FA840308DB4020337AAD37967034A9FB523B67CA70330F02D9EA20C1E84CB8E5757C9E1896B60581441ED618AA5B26DA56C0A5A73C4DCFD755E610B4FC81FF84E21";
        String expectedPrivKey = "8C8B3722A82E550565521611EBBC63079944C9B1ABB3B0020FF12F631891A9C468D3A67BF6271280DA58D03CB042B3A461441637F929C273469AD15311E910DE18CB9537BA1BE42E98BB59E498A13FD440D0E69EE832B45CD95C382177D67096A18C07F1781663651BDCAC90DEDA3DDD143485864181C91FA2080F6DAB3F86204CEB64A7B4446895C03987A031CB4B6D9E0462FDA829172B6C012C638B29B5CD75A2C930A5596A3181C33A22D574D30261196BC350738D4FD9183A763336243ACED99B3221C71D8866895C4E52C119BF3280DAF80A95E15209A795C4435FBB3570FDB8AA9BF9AEFD43B094B781D5A81136DAB88B8799696556FEC6AE14B0BB8BE4695E9A124C2AB8FF4AB1229B8AAA8C6F41A60C34C7B56182C55C2C685E737C6CA00A23FB8A68C1CD61F30D3993A1653C1675AC5F0901A7160A73966408B8876B715396CFA4903FC69D60491F8146808C97CD5C533E71017909E97B835B86FF847B42A696375435E006061CF7A479463272114A89EB3EAF2246F0F8C104A14986828E0AD20420C9B37EA23F5C514949E77AD9E9AD12290DD1215E11DA274457AC86B1CE6864B122677F3718AA31B02580E64317178D38F25F609BC6C55BC374A1BF78EA8ECC219B30B74CBB3272A599238C93985170048F176775FB19962AC3B135AA59DB104F7114DBC2C2D42949ADECA6A85B323EE2B2B23A77D9DB235979A8E2D67CF7D2136BBBA71F269574B38888E1541340C19284074F9B7C8CF37EB01384E6E3822EC4882DFBBEC4E6098EF2B2FC177A1F0BCB65A57FDAA89315461BEB7885FB68B3CD096EDA596AC0E61DD7A9C507BC6345E0827DFCC8A3AC2DCE51AD731AA0EB932A6D0983992347CBEB3CD0D9C9719797CC21CF0062B0AD94CAD734C63E6B5D859CBE19F0368245351BF464D7505569790D2BB724D8659A9FEB1C7C473DC4D061E29863A2714BAC42ADCD1A8372776556F7928A7A44E94B6A25322D03C0A1622A7FD261522B7358F085BDFB60758762CB901031901B5EECF4920C81020A9B1781BCB9DD19A9DFB66458E7757C52CEC75B4BA740A24099CB56BB60A76B6901AA3E0169C9E83496D73C4C99435A28D613E97A1177F58B6CC595D3B2331E9CA7B57B74DC2C5277D26F2FE19240A55C35D6CFCA26C73E9A2D7C980D97960AE1A04698C16B398A5F20C35A0914145CE1674B71ABC6066A909A3E4B911E69D5A849430361F731B07246A6329B52361904225082D0AAC5B21D6B34862481A890C3C360766F04263603A6B73E802B1F70B2EB00046836B8F493BF10B90B8737C6C548449B294C47253BE26CA72336A632063AD3D0B48C8B0F4A34447EF13B764020DE739EB79ABA20E2BE1951825F293BEDD1089FCB0A91F560C8E17CDF52541DC2B81F972A7375B201F10C08D9B5BC8B95100054A3D0AAFF89BD08D6A0E7F2115A435231290460C9AD435A3B3CF35E52091EDD1890047BCC0AABB1ACEBC75F4A32BC1451ACC4969940788E89412188946C9143C5046BD1B458DF617C5DF533B052CD6038B7754034A23C2F7720134C7B4EACE01FAC0A2853A9285847ABBD06A3343A778AC6062E458BC5E61ECE1C0DE0206E6FE8A84034A7C5F1B005FB0A584051D3229B86C909AC5647B3D75569E05A88279D80E5C30F574DC327512C6BBE8101239EC62861F4BE67B05B9CDA9C545C13E7EB53CFF260AD9870199C21F8C63D64F0458A7141285023FEB829290872389644B0C3B73AC2C8E121A29BB1C43C19A233D56BED82740EB021C97B8EBBA40FF328B541760FCC372B52D3BC4FCBC06F424EAF253804D4CB46F41FF254C0C5BA483B44A87C219654555EC7C163C79B9CB760A2AD9BB722B93E0C28BD4B1685949C496EAB1AFF90919E3761B346838ABB2F01A91E554375AFDAAAF3826E6DB79FE7353A7A578A7C0598CE28B6D9915214236BBFFA6D45B6376A07924A39A7BE818286715C8A3C110CD76C02E0417AF138BDB95C3CCA798AC809ED69CFB672B6FDDC24D89C06A6558814AB0C21C62B2F84C0E3E0803DB337A4E0C7127A6B4C8C08B1D1A76BF07EB6E5B5BB47A16C74BC548375FB29CD789A5CFF91BDBD071859F4846E355BB0D29484E264DFF36C9177A7ACA78908879695CA87F25436BC12630724BB22F0CB64897FE5C41195280DA04184D4BC7B532A0F70A54D7757CDE6175A6843B861CB2BC4830C0012554CFC5D2C8A2027AA3CD967130E9B96241B11C4320C7649CC23A71BAFE691AFC08E680BCEF42907000718E4EACE8DA28214197BE1C269DA9CB541E1A3CE97CFADF9C6058780FE6793DBFA8218A2760B802B8DA2AA271A38772523A76736A7A31B9D3037AD21CEBB11A472B8792EB17558B940E70883F264592C689B240BB43D5408BF446432F412F4B9A5F6865CC252A43CF40A320391555591D67561FDD05353AB6B019B3A08A73353D51B6113AB2FA51D975648EE254AF89A230504A236A4658257740BDCBBE1708AB022C3C588A410DB3B9C308A06275BDF5B4859D3A2617A295E1A22F90198BAD0166F4A943417C5B831736CB2C8580ABFDE5714B586ABEEC0A175A08BC710C7A2895DE93AC438061BF7765D0D21CD418167CAF89D1EFC3448BCBB96D69B3E010C82D15CAB6CACC6799D3639669A5B21A633C865F8593B5B7BC800262BB837A924A6C5440E4FC73B41B23092C3912F4C6BEBB4C7B4C62908B03775666C22220DF9C88823E344C7308332345C8B795D34E8C051F21F5A21C214B69841358709B1C305B32CC2C3806AE9CCD3819FFF4507FE520FBFC27199BC23BE6B9B2D2AC1717579AC769279E2A7AAC68A371A47BA3A7DBE016F14E1A727333663C4A5CD1A0F8836CF7B5C49AC51485CA60345C990E06888720003731322C5B8CD5E6907FDA1157F468FD3FC20FA8175EEC95C291A262BA8C5BE990872418930852339D88A19B37FEFA3CFE82175C224407CA414BAEB37923B4D2D83134AE154E490A9B45A0563B06C953C3301450A2176A07C614A74E3478E48509F9A60AE945A8EBC7815121D90A3B0E07091A096CF02C57B25BCA58126AD0C629CE166A7EDB4B33221A0D3F72B85D562EC698B7D0A913D73806F1C5C87B38EC003CB303A3DC51B4B35356A67826D6EDAA8FEB93B98493B2D1C11B676A6AD9506A1AAAE13A824C7C08D1C6C2C4DBA9642C76EA7F6C8264B64A23CCCA9A74635FCBF03E00F1B5722B214376790793B2C4F0A13B5C40760B4218E1D2594DCB30A70D9C1782A5DD30576FA4144BFC8416EDA8118FC6472F56A979586F33BB070FB0F1B0B10BC4897EBE01BCA3893D4E16ADB25093A7417D0708C83A26322E22E6330091E30152BF823597C04CCF4CFC7331578F43A2726CCB428289A90C863259DD180C5FF142BEF41C7717094BE07856DA2B140FA67710967356AA47DFBC8D255B4722AB86D439B7E0A6090251D2D4C1ED5F20BBE6807BF65A90B7CB2EC0102AF02809DC9AC7D0A3ABC69C18365BCFF59185F33996887746185906C0191AED4407E139446459BE29C6822717644353D24AB6339156A9C424909F0A9025BB74720779BE43F16D81C8CC666E99710D8C68BB5CC4E12F314E925A551F09CC59003A1F88103C254BB978D75F394D3540E31E771CDA36E39EC54A62B5832664D821A72F1E6AFBBA27F84295B2694C498498E812BC8E9378FE541CEC5891B25062901CB7212E3CDC46179EC5BCEC10BC0B9311DE05074290687FD6A5392671654284CD9C8CC3EBA80EB3B662EB53EB75116704A1FEB5C2D056338532868DDF24EB8992AB8565D9E490CADF14804360DAA90718EAB616BAB0765D33987B47EFB6599C5563235E61E4BE670E97955AB292D9732CB8930948AC82DF230AC72297A23679D6B94C17F1359483254FEDC2F05819F0D069A443B78E3FC6C3EF4714B05A3FCA81CBBA60242A7060CD885D8F39981BB18092B23DAA59FD9578388688A09BBA079BC809A54843A60385E2310BBCBCC0213CE3DFAAB33B47F9D6305BC95C6107813C585C4B657BF30542833B14949F573C0612AD524BAAE69590C1277B86C286571BF66B3CFF46A3858C09906A794DF4A06E9D4B0A2E43F10F72A6C6C47E5646E2C799B71C33ED2F01EEB45938EB7A4E2E2908C53558A540D350369FA189C616943F7981D7618CF02A5B0A2BCC422E857D1A47871253D08293C1C179BCDC0437069107418205FDB9856623B8CA6B694C96C084B17F13BB6DF12B2CFBBC2B0E0C34B00D0FCD0AECFB27924F6984E747BE2A09D83A8664590A8077331491A4F7D720843F23E652C6FA840308DB4020337AAD37967034A9FB523B67CA70330F02D9EA20C1E84CB8E5757C9E1896B60581441ED618AA5B26DA56C0A5A73C4DCFD755E610B4FC81FF84E21D2E574DFD8CD0AE893AA7E125B44B924F45223EC09F2AD1141EA93A68050DBF699E3246884181F8E1DD44E0C7629093330221FD67D9B7D6E1510B2DBAD8762F7";

        SecureRandom random = new SecureRandom();
        MLKEMKeyPairGenerator keyGen = new MLKEMKeyPairGenerator();

        keyGen.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_1024));

        AsymmetricCipherKeyPair keyPair = keyGen.internalGenerateKeyPair(d, z);
        assertTrue(Arrays.areEqual(Hex.decode(expectedPubKey), ((MLKEMPublicKeyParameters)keyPair.getPublic()).getEncoded()));

        assertTrue(Arrays.areEqual(Hex.decode(expectedPrivKey), ((MLKEMPrivateKeyParameters)keyPair.getPrivate()).getEncoded()));

        MLKEMGenerator kemGen = new MLKEMGenerator(random);

        byte[] message = Hex.decode("59C5154C04AE43AAFF32700F081700389D54BEC4C37C088B1C53F66212B12C72");

        SecretWithEncapsulation secretEncap = kemGen.internalGenerateEncapsulated(keyPair.getPublic(), message);

        String expectedSharedSecret = "5CF38F578AC4AE95FBFED574B3D8EBF7CB1DC9074F22277360E36D775347C058";

        assertTrue(Arrays.areEqual(Hex.decode(expectedSharedSecret), secretEncap.getSecret()));

        String expectedCipherText = "8B9FE419250C5FB0463C8181FCF7CEC777136B738E015EBA31067AA4A8C378BBAC0121B88214F1AEB866E4F33C277099E09B4BF7E21CDDA30B5B32C18B0E9660C30601D85DAEC07AAF4B343EC5516FA501DD63088B999FB9A414C6CA593806C08CD4C775139BF0F0BF3676D773EDD56E616A13830D5F5FE35E515DBC84E43AAD0167D57E60A9DE30886ACD3F7F2006CAC26A7A07B4DADBEDFBED7F305764386AAD726D5B2BF14A376BAD8B4896688491733FB34E6EDEA10BFD5E448541CB6E69E3D87DF190AFA7FF62577775BAACEA444A6128A20200251D8FA759DC60FDA6A9730CFFE4997FE7EBCDD1644AE2D55290A4074CDD2CE53C18D22BC33671E68727A9B5A2FEAFB114A8045D96A56981E200A09661375987625ACC233EDE817AF1DEEAA21C7C4377423E73C5AF9BFF58A49DE6DAFD07A3E3BABD891F62BBA41D1856B8BC502CC86EE115A3598431E2B54AB0C5EACC3CE6A03090925C1FD5A251B00576763A963994A7A23EE12EBFC1B994F93C6144178F0BEF88245CE77CD32EF651826A6090AF561A5864DEC2A51D846F1F48F88B4B55F58C2373E0F67BDC95DC23A43E8546232A7B234E49F5226A3A63BDBCED7240FC81C2DB68AAEB2671A2FD231997BF8839C63A7F41F15E7242821D42E80BBC0F43FA9E353DE8B25ED8FFC242EB512C6A5260919AAE89A11176532BCCC762A520A37AEC4E7209AA81CEE0DD4ADD932C47EB8100BE98AA1DEEA9EA698115ADCED950A6C536D19AEB325CEA8C5245C0A2281533FB90809DC2BE90567EBE6AE229FE09B44DA2182585EA694D8A9AB33EBC24B44E09BD510F34B4140E1FB41162F9415F2D9106A0CEA00A26ED0920021F4E5BCFB3DABF5850DAB22B2E889D9611FBE06D0C899708EB5E5FAD2FBBE0D5C0BDE080F8E760EDFA037D55DA77F0F39591BF5B050C905FA538B7228E238A290DF340778DCBD6BE40A3B1DD455FB27ADBE176AEF6CC295BEA570BDC221BA14002E3B113B0EF237452FBC9F1AEC42E0D2B33F19832DB0A6171CAEB0B30EEAD3A54B704B761C7D4AFEA8F6AFC15156666A081C43AEB2E04FEECEF8AABA4049BD78B120B9ABA86A60342A0CF806411C473C26C4BE1540E3312388BCBC8523BA73F40EA28D5564274F3661D7ACAA0F1E8D0F28DCF6B501329963E6857FDB2AAE873A7D9D6C14821F6C0B6AA50AC449075CD6F2A256C5A05959DAB5A5912CC8E8F8B9F59941BFCCE6A28CBA74A20382B1FD3382D056547D5BC5EF4AAE62F96F038C595A4F901D6AE790F8978292AD1CC3A1E800B71A5BBE84533646655E3752FBD6B02B97B204E75D28A34C2F990FB8E8CD31CE6E683FA7E67DA03367E8D47DC626F060FBA2D0425004CAC2A61D982D2E3D85008624B45DB022CF51BA265B5E974712A9372EECAC0EA272B2FC56EBED0D32105521BA2C4A8FE0C678CE4E45902C7BA9D510BD47B2B5F931DD732F27DE9B42FD4AA39EAC765283A9965EE97C0D88E23EFA6F718242C67770B87BF8832858C1D13FC520870BD34F2B9C6FBFD1A528B744F814C93F4F4E87108316FE2AB06E02292DEA7FCF6FEFB17BF5AA7376A4A9BDB7C49BF709EB1E05D60EF14CD85A75239B97BCA9A6A3CC1B28F28979D612431BAAC1ACEE5EF62776B4D51B7EB0F63DF507760097223CA903E16E02DEB7FCABFBEC26DAEDC0ED4CC55726BDC31D1775112EF3C35D1DF928C6EB7830D8CA6570CB5CE348E3F26DDE864F20E5BE7B99E264EBC0E9D8DE9C6E4B7FE3CFBE673833CF7E8B3081529062CB6815C7C0766822B3B31E56BA1FC73FE3DED4B5D435BFCE2F2997C1D4B9CE293220DD461103BE084BF12076372668A69836769C1F6D8C32E2C7BC2E7D66714C814793A2970C90DD94DF14C89C60DD35B52A14778E137E750CE83AC3AAB667FCBDCBA38B7FA6D1C6BF7B99D957078176D9779A09F84B75FBC2A11769EF65532B09ACA4C9A3766B4A1FC717F94648FB8B8D9363E54F1C4201C075C18B1EAE098B83598089585ED9DC06B96E2D1C96DC738086EBBC26C3193B64139E1FC1DFB22A17893506EF7B35792B4EB00196693686EB5DEB3CEB436DD16D2D92A0FD31F468AF8662040F5257BFA0F14991C0D560999EEF775178D14955ADF091DD797AC1FDCEC7776055271C0F130562D0B0A6749B159DD0DB9AC69271AC719B83B683CE8B32342AC4AB257B0F8083C8CC86338AFA4D386C9848F413ED0";

        assertTrue(Arrays.areEqual(Hex.decode(expectedCipherText), secretEncap.getEncapsulation()));

        MLKEMExtractor kemExtract = new MLKEMExtractor((MLKEMPrivateKeyParameters)keyPair.getPrivate());

        byte[] decryptedSharedSecret = kemExtract.extractSecret(secretEncap.getEncapsulation());

        assertTrue(Arrays.areEqual(Hex.decode(expectedSharedSecret), decryptedSharedSecret));
    }

    public void testRNG()
    {
        String temp = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
        byte[] seed = Hex.decode(temp);
        NISTSecureRandom r = new NISTSecureRandom(seed, null);
        byte[] testBytes = new byte[48];
        r.nextBytes(testBytes);

        String randBytesString = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E47";
        byte[] randBytes = Hex.decode(randBytesString);

        assertTrue(Arrays.areEqual(randBytes, testBytes));
    }

    public void testParameters()
        throws Exception
    {
        assertEquals(256, MLKEMParameters.ml_kem_512.getSessionKeySize());
        assertEquals(256, MLKEMParameters.ml_kem_768.getSessionKeySize());
        assertEquals(256, MLKEMParameters.ml_kem_1024.getSessionKeySize());
    }

    public void testMLKEMRandom()
    {
        SecureRandom random = new SecureRandom();
        MLKEMKeyPairGenerator keyGen = new MLKEMKeyPairGenerator();

        keyGen.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_1024));

        for (int i = 0; i != 1000; i++)
        {
            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

            MLKEMGenerator kemGen = new MLKEMGenerator(random);

            SecretWithEncapsulation secretEncap = kemGen.generateEncapsulated(keyPair.getPublic());

            MLKEMExtractor kemExtract = new MLKEMExtractor((MLKEMPrivateKeyParameters)keyPair.getPrivate());

            byte[] decryptedSharedSecret = kemExtract.extractSecret(secretEncap.getEncapsulation());

            assertTrue(Arrays.areEqual(secretEncap.getSecret(), decryptedSharedSecret));
        }
    }
}
