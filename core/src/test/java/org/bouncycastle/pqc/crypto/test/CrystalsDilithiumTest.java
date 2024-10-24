package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class CrystalsDilithiumTest
    extends TestCase
{
    public void testKeyGen() throws IOException
    {
        String[] files = new String[]{
                "keyGen_ML-DSA-44.txt",
                "keyGen_ML-DSA-65.txt",
                "keyGen_ML-DSA-87.txt",
        };

        DilithiumParameters[] params = new DilithiumParameters[]{
                DilithiumParameters.dilithium2,
                DilithiumParameters.dilithium3,
                DilithiumParameters.dilithium5,
        };

        TestSampler sampler = new TestSampler();
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            // System.out.println("testing: " + name);
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium/acvp", name);
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
                        byte[] seed = Hex.decode((String)buf.get("seed"));
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] sk = Hex.decode((String)buf.get("sk"));

                        DilithiumParameters parameters = params[fileIndex];

                        DilithiumKeyPairGenerator kpGen = new DilithiumKeyPairGenerator();
                        DilithiumKeyGenerationParameters genParam = new DilithiumKeyGenerationParameters(new SecureRandom(), parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParam);
                        AsymmetricCipherKeyPair kp = kpGen.internalGenerateKeyPair(seed);

                        DilithiumPublicKeyParameters pubParams = (DilithiumPublicKeyParameters)PublicKeyFactory.createKey(
                                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((DilithiumPublicKeyParameters)kp.getPublic()));
                        DilithiumPrivateKeyParameters privParams = (DilithiumPrivateKeyParameters)PrivateKeyFactory.createKey(
                                PrivateKeyInfoFactory.createPrivateKeyInfo((DilithiumPrivateKeyParameters)kp.getPrivate()));

                        assertTrue(name + ": public key", Arrays.areEqual(pk, pubParams.getEncoded()));
                        assertTrue(name + ": secret key", Arrays.areEqual(sk, privParams.getEncoded()));

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
            // System.out.println("testing successful!");
        }
    }
    public void testSigGen() throws IOException
    {
        String[] files = new String[]{
                "sigGen_ML-DSA-44.txt",
                "sigGen_ML-DSA-65.txt",
                "sigGen_ML-DSA-87.txt",
        };

        DilithiumParameters[] params = new DilithiumParameters[]{
                DilithiumParameters.dilithium2,
                DilithiumParameters.dilithium3,
                DilithiumParameters.dilithium5,
        };

        TestSampler sampler = new TestSampler();
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            // System.out.println("testing: " + name);
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium/acvp", name);
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
                        boolean deterministic = !buf.containsKey("rnd");
                        byte[] sk = Hex.decode((String)buf.get("sk"));
                        byte[] message = Hex.decode((String)buf.get("message"));
                        byte[] signature = Hex.decode((String)buf.get("signature"));
                        byte[] rnd = null;
                        if(!deterministic)
                        {
                            rnd = Hex.decode((String)buf.get("rnd"));
                        }

                        DilithiumParameters parameters = params[fileIndex];

                        DilithiumPrivateKeyParameters privParams = new DilithiumPrivateKeyParameters(parameters, sk, null);

                        // sign
                        DilithiumSigner signer = new DilithiumSigner();

                        signer.init(true, privParams);
                        byte[] sigGenerated;
                        if(!deterministic)
                        {
                            sigGenerated = signer.internalGenerateSignature(message, rnd);
                        }
                        else
                        {
                            sigGenerated = signer.generateSignature(message);
                        }
                        assertTrue(Arrays.areEqual(sigGenerated, signature));
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
            // System.out.println("testing successful!");
        }
    }
    public void testSigVer() throws IOException
    {
        String[] files = new String[]{
                "sigVer_ML-DSA-44.txt",
                "sigVer_ML-DSA-65.txt",
                "sigVer_ML-DSA-87.txt",
        };

        DilithiumParameters[] params = new DilithiumParameters[]{
                DilithiumParameters.dilithium2,
                DilithiumParameters.dilithium3,
                DilithiumParameters.dilithium5,
        };

        TestSampler sampler = new TestSampler();
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            // System.out.println("testing: " + name);
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium/acvp", name);
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
                        boolean testPassed = TestUtils.parseBoolean((String)buf.get("testPassed"));
                        String reason = (String)buf.get("reason");
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] sk = Hex.decode((String)buf.get("sk"));
                        byte[] message = Hex.decode((String)buf.get("message"));
                        byte[] signature = Hex.decode((String)buf.get("signature"));

                        DilithiumParameters parameters = params[fileIndex];

                        DilithiumPublicKeyParameters pubParams = new DilithiumPublicKeyParameters(parameters, pk);
                        DilithiumPrivateKeyParameters privParams = new DilithiumPrivateKeyParameters(parameters, sk, null);


                        DilithiumSigner verifier = new DilithiumSigner();
                        verifier.init(false, pubParams);

                        boolean ver = verifier.verifySignature(message, signature);
                        assertEquals("expected " + testPassed + " " + reason, ver, testPassed);
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
            // System.out.println("testing successful!");
        }
    }

    public void testDilithium()
    {
        String seed = "70CEFB9AED5B68E018B079DA8284B9D5CAD5499ED9C265FF73588005D85C225C";
        String pk = "D2FD03F3A1B7F635AF9F34D580A98F524C735BD5BA2355DC6E035BD21765580CBB111923F194A7CC8A7BB2EBC5C0E71AA637CC800E6103B850A539B2A39E1B6D713E5DB8314C9AE1F8BF8A38F06AFB9D73B161B0FFE3A4891706AE26D54FFB496DF8DC0F1983509500C9ABBD28E59B3FCDABBDADABD45EC31499378BDE849E7C1F19B7044D67E05106D7136D95380D5605D4465D877557065DF0A75D3C28542F40FEED42EC7E280637B083D988BCA5F6394E02396C4676184FB63318DAFAF5BBDDE00E308FE84019C2340A3F3E1C0865624970711283356AE14BD6B94D1C9AE188DE1A8A2CA824A8EAE2FE6AFB38D83A2D99996AB21FE3E84C0BE6B6DA08879B677374FA7C691B13D40FA9D4CC26B2288D5A8C9A43724381004D61B0D57FF400314C8E30EE796AF10F7EE21BF13D08180465ABC72EDDB080C6A07184E3EEDC47C19AA7F09D1F3309E183A2BD9B0573DDE474A81BA4F78D0C523D0C04F90060FD571A35C037E079C5E210D7390DF568F2E2F03CE44420C82F3FE69EB9B48EE90962D6B0F24440648F71EDB241EE6566FC1A64CABF66BE6FECBCB1387C82A7BC202D9E367998E2A291AF0CD1570677FE8D63A3285A2EA6EB29AF9DC1AEC1C36C4706B12BAA20839692F286A6E0321468F7479345C4D52FBDB2F06725B554B89E2492612681ACEBC6C7BADA9225818DBC35D64C22C48BFF80A730D0716DFAC99DFD5B8992611D0C93EE90BDB260022AFE25D913E06EFFB59CB1F8A60CBFA5AB2F459A16F467E989525E0A37EBE56E833FDE55DB9D1530ADCF45846DF281E47CAA1E0A27EFDE2107D354CEA0F6A454692F04CD838EBDD46E191E5D9C11839A2C3F488A4FC7CD265A7B5D32B08CBDBFAB9D2CCD76222C8EE37DDCBD2AA063ED861473A6454CAEA377850B1A2B9DDBBCB374FAB5B12F351C8E5888872E5CD1F60A4FAE1FF837D192C22BEB41EE6FA392FCDF4550FF46B5CE906D017EF3077DF132300D8BBFA9BB03C75E79E2F04C284AD06A44399649C3E2A2A8D1EFE9B7A4E0C271047AB75908BFF7DF9E30ECA547745BAE23A86FF9A8B58C2538B88B866401076902DC5F0BD761687B49EAFE36D350CBEDFDD36C121CF23786BFCF7E47076496EAB6BBDA774049C2EBABE2DE99C4C24F2DB73684015B373977496760CF9AC23D8B623133DB2DE10D73FA6AD1C6DAC8434F28C6E251CE7293CFF3F3B61EFCB5A435123670F29846A13DF3EE712604461F1BAB8F4EBC836DE058978AE734396A98081B35CC98188A86949C99270D4709854C5B35B17F48A373134C814CC8A0F3E2FA807F2A918530907864778282D75E03A41B2504EED816A417A3AC6BA16080C39B7310192002A728F7F20395009A9E16767CE1971F5DE7D229A50613369E4382045A8E81901F4DBA8102F3D413FE35B326A874F233B719A7137600D35D33AEB6B7259624083AA968730C8F78292AD28F14EEABE660835984FE69EF23DEC8C327C0EB0B882D587E1EC433DA85C9FD1E0A34994DEA240C854452D18C30F496E49EC904B602E0F5062EDCDA03280A53B4313574CC2C0D5471BC9613BDFD6641F5BD127BAB5B5EB3D499A33114048220E819F8EE12CA922C8F17D9C9F51AD5BD6883B10E6AA2483BA49DC547DA7686151344F4E9099B38E430B5226B059832CF03DB48FB02DBA4E61593DC4576360491890E53EC0E6AC73CF32B25D823B38456E286505A541E5AEEE96B1914F5F76687CE2B0160227ABED77993594BCD831366206D75714082F1C46F1F4439AC81A57AF31C81C555307A070FFA94E0479B784BBD88A60CD4C7CFD94E6AFE02F6B21F72AF0DCD6609D40C965C14E5F2389183E53DE930F7DE1D44215CF49144844E8B87F78A7F132AEFE22BE80B4E3A05EE3A68CCF609EF44047402E4493046E6F9C767FF8A75E28B3CE077FDE7E7EED313B5BF7E460127CA8182E9BC794C0DFA730FB920080575A751B5CAEC85A109B4422BA266743F0D032BDA8F1CA6248CDB917530DF1302A5F8C18DC642D52478C98C12A3F16EF2B62B4F59EA1BB58DE7B65B3C7153CE6DA5E4950746F80E087A0E3586D097791BF36DEF865D68591D39D0903773EEA962147F34704138B54DF7924CDD8C333DB5E1A409CCB2B34E2C3C8C7FDD3FD8D012CBF382AAA85E83A12F235A2D147D035B7B28B34B6F57949F322482A7D4D3B15045C420D5ADDC7F0E69B4DC1CBA58B01D872480B06A260D827D891B13C4C5CA50C748DE3C771BE61E9AA170165CB01F4BF5DA27A7791D3AD3F6267B4CB4E61B28FA1708418D932DFC4161880C5D3B17A9663A9061FA8F1804315850FE4E7306C882B38227E867F80872CDC1944D472615EA4900EF7D270B881D4130F56C5CC980D92A47ADA6657EB6F37A385D2D8CC993E1442EB05281853636991E34AADC68954D04E7ADEF76BF880F059B0CBB55D915A4B123E2F1339A073CBFBC409BEFF6400AE096D5AE18EC42CFFAD5B4980FA35BF03413ADB5D7E6876AC355D1C9ED70CA2B973954D12B3CDD76AC6835DB96003ED8C4E288B71FD77DBAA7635720E12AE0A317DE808C664E317F55275791F3245CA4FE5D4D41077FC150A6E403D5A208E46EADBE8F2CFB8AF472F4A0CEAC015219478E6B86C958CF86525B7485C1734C7EF00E90683FFF5DBD0A7D413A855021026A1B32013A4616CBCD3700ACBC705BE3EFBA625C69A025267BCE9D135E3F5B5CC8C43956407E84B6663103E29C242035551AE797F56C6374BE0C798C0CF398F1ED";
        String sk = "D2FD03F3A1B7F635AF9F34D580A98F524C735BD5BA2355DC6E035BD21765580CE38D1C14F6467C35A9F380D27DE61F7C75031569EA2EC8260EEE9105261B7FE160C91344B0C6764C204E5B8D424650BEC06B9E2E625AF07E23F4950CA24FB4D6EC2C8B3A717C9311EB87279FE25E311F48B8256501F6463412B50DBC89A869BA2241112648400738730212442544575483725033356258423201621183610245665648356120845260685045655512724747212125402221428117650306426152134325243382121135623332074786223150837084264345645148311486246686743371366726014707721161588558387183806701657870647785600288534846622583548804744012574371077544387121142208887223588746148553716773822822741403577328718380781434875207647401607561060861322146156542670820841073130361028650452612166833552584735354526517106000385777812426804146432667410603554128333725230677821516317300087526584634638808846451112405321011181864782241003855754210468343733880078343787413576232688065864853483551585074460588700772013100875488142084166115605685115808058863018286131417220168171786585310622852822615043142885431780580115045688233663636406515244767064536422686750635413347851217808387655142313887566205174085281417213812608124414575018287101002132557042172427861117005304772132030216744315771455710541665741524024371512055116783678252533566424613702232740007068187175780286801721004275522864253158176308640831143305382735303723568704541157314123164326663562151508210302338172127102314227577283771627506887214187313030150715862866288868603270146172271385381703388681378810486573016523140830756821032312850065081630675766511601417121255564811411328826207476424482324775326081758115637483551478685666681732021367522746683445700666477204722285687124702480702542301257137367536005268153335820613732408717615224260185343116457761761566876606554781033631421832160155580423842031312343625273082812547513544126735001001838574424013036127812626811887435120627127515610222281118141666638208675561240065461127440345858781007852572885722222550840041260836462878467805022820771360751443687864313877737355412700540708286880045383432281006435486766501775761275438162403343453887216614704841431466587845820225457315213203024880801371255432720568652468040616835054533737272220680825508472867422361680075518121784448115645071105815511010471621075861187800527264521743234076486730776364875131638468745363842354661048363385214842038251103357468016433402070353221275733465833387438517503660880258758088316360182132261568741110331413053416726535501334808710264868845271442358803557705484287055888683862521827261177885176773005771117851106563570287401340012653451205467518807033356622620070232687726311133333814170622861514731302546511761580741613737061400548877756777665316726666887643583104875706764700436358605203442736486123721610624208608323540355557300610365342714158662558016531018261135468246132583477050060156021168545303687336418886334252015833423288568177555148481201581385041471835707545554552827313602123268321382587028585344867273428418220883610214161712415748852510260736761266172132360325411011226660161632642605186351585131425384566627833354507646508025434157357825430282384745701567517747803152750000947BCA93C27D584E2C66EAC9C7640C1CA217EEF66DABBCB260B4C34300FA051357820F57392544982FD11057DE233E6D2DD84972A7E47D4DBA99BC30CF8F2AD5A2C0243195ED2730FFA92D227D153095972D4B3447FFAC45A23EB41CBC87CDD1250A8A478B0F7A1D5B39AA2206E48645584FE7BF7A13168F482765E57BB924AC6D9A11369F4A6AFFCD169B7D75129B35D5134A31761BB8355AEEED27E201A06313013E307A01A73AEA7955C0578C8C5E5A1A2D2FA4593FACD904C62040BDB9F329933536BF8D81C4256BAAE8723FD4DC66BB5E7F9CA49031A193ECECBB5DC390EC6D5513C79A052B3FD43612FB7375315D8091F79BAB1318F17854561BC93AE0E5CD6D131E562C8114810C939AE563AA10B47CE4484317F34ABD02D0CCAD58DD29BCF657BBD9254B01CA9726091938ED32054B37DD617240F4434C1A4A8711AA3A399A8A5388330B7059ECCBB6B1B9CF7187ADF10B0C9171D3C0F6E2D460A419247672E3B9FEA2C95910BF2FB6A5D61F257453B07AFB64B0BA2758BCD735751F2D53515E236FE8A5B4393B80BF06DF97BDC6380087E6AA8DDE6E098111A7343FCDD1E903708E637EBF28323CDA6B9405810EDCFB3691149ECF224C50F8DF92A94AA4770A0E91466194BB0E27BF1CABF16ADFD351220033F76F5925557BCF9634E9461359621D80B4BBAD7E2A6E432DC43B126CA42AB88AA88F0A84AF58029C99A0248F0C454071F35B831FED1254D6F4E2720485786215F7C7F0C4ED15FA853CD3AA07259B39240A82135C2923A72B876FABB3F0F2C09613DE39D459A07C14E7BA437D8041491FCEC1433404BAD1DA9EE9471E17CB691B2A353710C9FFA4E5178112027764EB7DE809C3E1F1FA4178A5D4DC9EE27857EFF26B91711FC144D5A775B8B50D5DB939BA3207680C242FC821947F934C8DAEE203563D28606BE624A32901932DAE85712AF6C8016026927E9B8129574BE3CB1E95332B052707AC8AA8F435E88B7E568D4987C6AC0E902B0609A02D91B3F5FD3FD901DDD0DB9873BD7C71ED921D4577A78C4FCC9BF075203D38F5E76E74F277484E057B6189004131B0C9B1A155294D1CD3D5208E266901D7D314FACCE7E2AA584583A11E4D7C21B94A32E508EDDBBD7A65AA86B4FDFA6BC285D4CFF53926C7173FBE1F89CC303234B878C6B8101F58AC8D3E5E1BF5AB6B26297CC97B95954AABDB25BE008A3F47E56487B00D3DEDA890D92C83957FEAC6B8291AF65959E1D1FCA3BD196E9FC9E67E0607094822E5B4191DB96824B9F03F2EF57F5238BA7E1E84ED55B7DFF3D6C2C1273692A9A19272166130DB89FC67DC94DB614E3E82BA3A3512B012D51FB486B5A3150B78E724E2A12DE07D8671FBA2DA7FD5D147208FC3AF653E6520FC40871AF2177E65CBD0EAF304217B367A665F224CAEDFE93006AC1E14BCD67A88D171F3D8F3E358A71926BA3E5C239A531263EC9437BF2A033B8B55B2C0CB6E7E97316E22DF77CAD910D20EECE1C50910A5CC32ADAB09377550F92D5BB1F4C07F4A2822338E2CFF5348DF77CF8EF8E6657DED1E0CE058E3CCFBF39B3F166E303D33C3556C9AC8ECB3DF7C74AB36D0F2794441BA9808827B578FB5C29E494E21539AD3AB2B41BF161D7F69589D4524C54C89B486F75D252F541CC63B9E706D64A1289A2306C595363CB6FBEF0A1B5B17AB5B1794BF27036F64EAF0BD430DD58D80010CCDADA4A5A3A1E41A6FBF129D73779A37AE5C8D6841A9993C51E364E04FAC8E25A4E6872F6C860FA265C1C4426AD9C21D26DA8C278546ADCD831F2B8B26D4E1F670623D95C8362DA662D1FF0AB687503F328DE095810EDE12B49EAD1533519558C1E940B46E4EDB027BE9DA2039B25DCF7357E19E5416AE268C14FB3A8BABCB3D23F70CC9D59681C5D833AC22E653D86E22CE822540755D8D243C15213D076C6B26436DDC07C7E001347B0CB8783DFEFEDF275FEC4792686734007F0FF8540811C2AFE6CA151420532FA5526A1074C3D789F2932DE42E3ACFBF94760F426D96CF033FA49E2F458F9A9C2E71DACFE009DD9C3F3C8AB3282D6F383B981C82D6364F0E4BDB2AF6A95BA61F474150CAD7233F8903DF972DBB0328C0CB9D0CCBEF883D2E6ADD180ECA1B662FC1D2DBBDDB3634219E1EFF38B1E52875356C03EADE942055F483504BBBCB4302A417CF6D328ED793B1A3C0969B7B3418F50AB39F83C5666C90E38356F7F9D494A6DCB63D67C34E3D14A4E15596497926C8568D8EC3DBD9C2E82C385BCFB8D9674863BD4FBF1757DB447BF804AE950147C91FBF9AA17891044CCAA73B45528597462CED751D015EBBA9E2B7CDCBE6DC05AA9EAE0C86848A3475BB1C5744F5903EE4A842A469CC181271F245AD70D02A4837863B296B4ADB4E8D03D82B64AA11DD31CDF21EDF1DFE3276C4DBC877E35B15FB2835EC3A1C453168A38CA8E563CF3E9A00736CD5CFBD2841D10F94AD55799C2927E5461B28BAC5174D0CE3F8F7CD7609FBC8DA0C38CC21695CEDAD12F8D2E64951A8996E510D6D52797C5BA0EB4AFA6BF2CC43DA09DE3179E899BD7188B32A98A499D372F3707CED479B0981CB50C0C0539CF7E3100B720E466652A4F499C2BA3A17F5232268730B962BC572C0DE96E8C9E28F7E3532C2224196AA9E27688DD050D7CB7854FB3C35F9C62EFB10DA84833F29BB1BE5EF3B533638EEF743D8119DDC290BDF08B6F0F9E4E1E13446C53ED69805DA26908A15DF1C48E009EC1253BD5A5898EBB5121CC24904C8B10E24E680E565985076FDA11D13FFDFA4DB28AC9F0AEA2F81FD7ED4DCA8D3B2E3848B4D6046F6E0DE3A4F683F25E0605E84B36F483C404EF899CB3FCCBE8CB2A6F0A7E10B1948CD4F93F181555F661D31D426808BBF9F66FD60D649269CA3FE991B22428C37AD2A08680F747CC0360CCD373DC6A9F43A66470E014E72B3D8C38E020442D8AAB974E6049374145B04CB7F3044AAC1EFDAB2A18BB464D4F2F2D8143974C95EEE856D59EC00288ED43FF5CC8803006C995514A2CC9CA622B61BCD75EC51C202A917105B4A4BED1B80146831DCED07EFD2ED25739F54096911B150D3077CCD731A0361682725D53803F8FCEAA83919291EDB4493EC84CCE1D0F82A679236EAD1002AE8018CAC9FDBD246FF093D803C0DE3326A57907B0DD6B01D081458C75728C600829928890A56AAAFEFCF7423B70A6D86B415B8358DD044ABEE00B9C9795FC8F61A64686DF5F876A8F33061599AE830F7EB4C4BFF875F4A936C403C5D160DE5D33CAEE40FB718DDA4478AC6F51C59C2155254BD77671118411E2609D000306FC9507004A31E8957EA40C2564B83C3ABB71A87C11BD18D7891C449DBBE79B4A4FB048307CE0E812B2C68ECAB77FD1111526AB0817306CEBCB0497C552431CE15E4AB52283F679480D69DDDE1F2579CFDBE0BCA95FC5B2DB0C5CC76A31950F5116AAE5F02D46710E4257A75FDEDF2F47CE37C203E7F24D3C9179713C5D807C296149A75CCB444F0C6F6ABDD2DBB2985FE267482858A1E";

        SecureRandom random = new SecureRandom();

        DilithiumKeyPairGenerator keyGen = new DilithiumKeyPairGenerator();

        keyGen.init(new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium3));

        AsymmetricCipherKeyPair keyPair = keyGen.internalGenerateKeyPair(Hex.decode(seed));

        assertTrue(Arrays.areEqual(Hex.decode(sk), ((DilithiumPrivateKeyParameters)keyPair.getPrivate()).getEncoded()));
        DilithiumPublicKeyParameters dPub = (DilithiumPublicKeyParameters)keyPair.getPublic();
        assertTrue(Arrays.areEqual(Hex.decode(pk), dPub.getEncoded()));
    }

    public void testRNG()
    {
        String temp = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
        byte[] seed = Hex.decode(temp);

        NISTSecureRandom r = new NISTSecureRandom(seed, null);

        String testBytesString = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D";
        byte[] testBytes = Hex.decode(testBytesString);

        byte[] randBytes = new byte[testBytes.length];
        r.nextBytes(randBytes);

        assertTrue(Arrays.areEqual(randBytes, testBytes));
    }

    public void testVectors()
        throws Exception
    {
        //Disabled OLD KATs

//        String[] files = new String[]{
//            "PQCsignKAT_Dilithium2.rsp",
//            "PQCsignKAT_Dilithium3.rsp",
//            "PQCsignKAT_Dilithium5.rsp",
//        };
//
//        DilithiumParameters[] parameters = new DilithiumParameters[]{
//            DilithiumParameters.dilithium2,
//            DilithiumParameters.dilithium3,
//            DilithiumParameters.dilithium5,
//        };
//
//        TestSampler sampler = new TestSampler();
//        for (int fileindex = 0; fileindex < files.length; fileindex++)
//        {
//            String name = files[fileindex];
//            // System.out.println("testing: " + name);
//            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium", name);
//            BufferedReader bin = new BufferedReader(new InputStreamReader(src));
//            String line = null;
//            HashMap<String, String> buf = new HashMap<String, String>();
//            while ((line = bin.readLine()) != null)
//            {
//                line = line.trim();
//
//                if (line.startsWith("#"))
//                {
//                    continue;
//                }
//                if (line.length() == 0)
//                {
//                    if (buf.size() > 0)
//                    {
//                        String count = (String)buf.get("count");
//                        if (sampler.skipTest(count))
//                        {
//                            continue;
//                        }
//                        // System.out.println("test case: " + count);
//
//                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for Dilithium secure random
//                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
//                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
//                        byte[] sm = Hex.decode((String)buf.get("sm"));     // signed message
//                        int sm_len = Integer.parseInt((String)buf.get("smlen"));
//                        byte[] msg = Hex.decode((String)buf.get("msg")); // message
//                        int m_len = Integer.parseInt((String)buf.get("mlen"));
//
//                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
//
//                        // keygen
//                        DilithiumKeyGenerationParameters kparam = new DilithiumKeyGenerationParameters(random, parameters[fileindex]);
//                        DilithiumKeyPairGenerator kpg = new DilithiumKeyPairGenerator();
//                        kpg.init(kparam);
//
//                        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
//
//                        DilithiumPublicKeyParameters pubParams = (DilithiumPublicKeyParameters)PublicKeyFactory.createKey(
//                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((DilithiumPublicKeyParameters)kp.getPublic()));
//                        DilithiumPrivateKeyParameters privParams = (DilithiumPrivateKeyParameters)PrivateKeyFactory.createKey(
//                            PrivateKeyInfoFactory.createPrivateKeyInfo((DilithiumPrivateKeyParameters)kp.getPrivate()));
//
//                        assertTrue(name + " " + count + " public key", Arrays.areEqual(pk, pubParams.getEncoded()));
//                        assertTrue(name + " " + count + " secret key", Arrays.areEqual(sk, privParams.getEncoded()));
//
//                        // sign
//                        DilithiumSigner signer = new DilithiumSigner();
//                        DilithiumPrivateKeyParameters skparam = (DilithiumPrivateKeyParameters)kp.getPrivate();
//
//                        signer.init(true, skparam);
//
//                        byte[] sigGenerated = signer.generateSignature(msg);
//                        byte[] attachedSig = Arrays.concatenate(sigGenerated, msg);
//
//                        // verify
//                        DilithiumSigner verifier = new DilithiumSigner();
//                        DilithiumPublicKeyParameters pkparam = pubParams;
//                        verifier.init(false, pkparam);
//
//                        boolean vrfyrespass = verifier.verifySignature(msg, sigGenerated);
//                        sigGenerated[3]++; // changing the signature by 1 byte should cause it to fail
//                        boolean vrfyresfail = verifier.verifySignature(msg, sigGenerated);
//
//                        // print results
//                            /*
//                            // System.out.println("--Keygen");
//                            boolean kgenpass = true;
//                            if (!Arrays.areEqual(respk, pk)) {
//                                // System.out.println("  == Keygen: pk do not match");
//                                kgenpass = false;
//                            }
//                            if (!Arrays.areEqual(ressk, sk)) {
//                                // System.out.println("  == Keygen: sk do not match");
//                                kgenpass = false;
//                            }
//                            if (kgenpass) {
//                                // System.out.println("  ++ Keygen pass");
//                            } else {
//                                // System.out.println("  == Keygen failed");
//                                return;
//                            }
//
//                            // System.out.println("--Sign");
//                            boolean spass = true;
//                            if (!Arrays.areEqual(ressm, sm)) {
//                                // System.out.println("  == Sign: signature do not match");
//                                spass = false;
//                            }
//                            if (spass) {
//                                // System.out.println("  ++ Sign pass");
//                            } else {
//                                // System.out.println("  == Sign failed");
//                                return;
//                            }
//
//                            // System.out.println("--Verify");
//                            if (vrfyrespass && !vrfyresfail) {
//                                // System.out.println("  ++ Verify pass");
//                            } else {
//                                // System.out.println("  == Verify failed");
//                                return;
//                            }
//                             */
//                        // AssertTrue
//
//                        //sign
//                        // // System.out.println("attached Sig = ");
//                        // Helper.printByteArray(attachedSig);
//                        // // System.out.println("sm = ");
//                        // Helper.printByteArray(sm);
//
//                        assertTrue(name + " " + count + " signature", Arrays.areEqual(attachedSig, sm));
//
//                        //verify
//                        assertTrue(name + " " + count + " verify failed when should pass", vrfyrespass);
//                        assertFalse(name + " " + count + " verify passed when should fail", vrfyresfail);
//
//                    }
//                    buf.clear();
//
//                    continue;
//                }
//
//                int a = line.indexOf("=");
//                if (a > -1)
//                {
//                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
//                }
//
//
//            }
//            // System.out.println("testing successful!");
//        }
    }

    public void testDilithiumRandom()
    {
        byte[] msg = Strings.toByteArray("Hello World!");
        DilithiumKeyPairGenerator keyGen = new DilithiumKeyPairGenerator();

        SecureRandom random = new SecureRandom();

        keyGen.init(new DilithiumKeyGenerationParameters(random, DilithiumParameters.dilithium3));

        for (int i = 0; i != 1000; i++)
        {
            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

            // sign
            DilithiumSigner signer = new DilithiumSigner();
            DilithiumPrivateKeyParameters skparam = (DilithiumPrivateKeyParameters)keyPair.getPrivate();
            ParametersWithRandom skwrand = new ParametersWithRandom(skparam, random);
            signer.init(true, skwrand);

            byte[] sigGenerated = signer.generateSignature(msg);

            // verify
            DilithiumSigner verifier = new DilithiumSigner();
            DilithiumPublicKeyParameters pkparam = (DilithiumPublicKeyParameters)keyPair.getPublic();
            verifier.init(false, pkparam);

            assertTrue("count = " + i, verifier.verifySignature(msg, sigGenerated));
        }
    }
}
