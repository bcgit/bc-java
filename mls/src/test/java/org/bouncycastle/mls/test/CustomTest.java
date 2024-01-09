package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import mls_client.MlsClient;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LifeTime;
import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;
import org.bouncycastle.mls.client.Group;
import org.bouncycastle.mls.client.KeyPackageWithSecrets;
import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.ContentType;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.ExtensionType;
import org.bouncycastle.mls.codec.ExternalSender;
import org.bouncycastle.mls.codec.FramedContent;
import org.bouncycastle.mls.codec.GroupInfo;
import org.bouncycastle.mls.codec.KeyPackage;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.codec.ProtocolVersion;
import org.bouncycastle.mls.codec.Sender;
import org.bouncycastle.mls.codec.SenderType;
import org.bouncycastle.mls.codec.Welcome;
import org.bouncycastle.mls.codec.WireFormat;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.bouncycastle.mls.client.Group.NORMAL_COMMIT_PARAMS;

public class CustomTest
        extends TestCase
{

    public void testMsg()
        throws Exception
    {
        byte[] data = Hex.decode("000100012433633932633932622d373430302d343865652d386162362d333535623031376138306665000000000000000201000000000002000401206325253fec738dd7a9e28bf921119c160f0702448615bbda08313f6a8eb668d2206a7f55e70e258689023d00e700c151184be51504a2f529aab293512d731bb35540403ada148b52c4ebc465c73d533509ccd618435cbb52a981e4780465263356448d89cdc3668ff3f43886b3ce0fb0f5260cd0e1e9ead8a73ab0fab690af52f1fb0920f851aeebdd8706101d63c8a3a67df9e06c55349f5ac671d93434fed0cc24e097");
        MLSMessage message = (MLSMessage) MLSInputStream.decode(data, MLSMessage.class);

        byte[] mlspp = Hex.decode("000100012466666566613934382d396262332d343166632d623965632d34333333363132323739356500000000000000020100000000000200040120ba53ab705b18db94b4d338a5143e63408d8724b0cf3fae17a3f79be1072fb63c202ae9b31e898b91dfc1cbe65420a7c7cca4687b15d9c4854013bc24f8350428a940406e9d8dcc6c0262512549bf00c87c05392fe2dddaaed24074e7d87ba0a226ac8a4e591d4721043738a0bf32981e9696c6d5e3d4b90b0265c28fe21f4e6ab7f80020c3ecf9d6dde87b5ffe51f5cef51647c61721f9b174f9a2434f7a5c0d264cf3bb");
        MLSMessage Msgmlspp = (MLSMessage) MLSInputStream.decode(mlspp, MLSMessage.class);


        int x = 9;
    }

    public void testGroupInfo()
        throws Exception
    {

//        Executing function: createGroup
        /**
         * Alice creates a group
         * < group id
         * < cipher suite
         * < encrypt
         * < identity
         *
         * > state id
         */
        System.out.println("\n Alice creates a group");
        byte[] groupIDBytes = Hex.decode("32623731656231662d346130332d346233382d616632322d633837356532353335346538");
        CipherSuite suite = new CipherSuite((short) 1);
        byte[] identity = Hex.decode("616C696365");
        boolean encrypt = false;

//        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        byte[] sig_priv = Hex.decode("7e46c392882a90fdfa94a497512c1c393d3582fd8e6d49bbbbc44449ca8e16e0");
        byte[] leaf_priv = Hex.decode("99b91ff2d448c65ee9af5095a1db39089515d3ce071b2ca8ebb9d626de341e8a");
        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().deserializePrivateKey(leaf_priv, null);
        AsymmetricCipherKeyPair sigKeyPair = suite.deserializeSignaturePrivateKey(sig_priv);

        Credential cred = Credential.forBasic(identity);

        LeafNode leafnode0 = new LeafNode(
                suite,
                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
                cred,
                new Capabilities(),
                new LifeTime(0, -1),
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        leafnode0.signature = Hex.decode("01558d40c6818cab772d5c89a6125423aca9b9f8071197aea6373ab20b0222521c45ce9c070a380aced95387ed98eac2f2dc5b7f7e2b1ea387a9a6e3df209501");

        Group group0 = new Group(
                groupIDBytes,
                suite,
                leafKeyPair,
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate()),
                leafnode0,
                new ArrayList<>()
        );

//        Executing function: createKeyPackage
        /**
         * Bob creates a KeyPackage
         * < cipher suite
         * < identity
         *
         * > transaction id
         * > key package
         * > init priv
         * > encryption priv
         * > signature priv
         */
        System.out.println("\n Bob creates a KeyPackage");

        byte[] bobIdentity = Hex.decode("626F62");
        KeyPackageWithSecrets kpSecrets = newKeyPackage(suite, bobIdentity
                ,
                Hex.decode("019df193ca89236f104a58bcfb36f4fbb0bf4d987b207a34b474f9e25f2c73db"),
                Hex.decode("81539b369bd5c02ee4c9b0c056a26b88a209e6f089c8e4363c9d4982ae70e262"),
                Hex.decode("b03dc11e670d0dec284ceaf08bedcac33559a9304a34b02b08133a7e1c2f15ef"),
                Hex.decode("7694fd6323497445c1a4f41d2289e98343474890a31a996dc79bc39496dd911ba7692966f1b3a6622ae82d21075cafa228e0a29c805b67823481298dcd2b220a"),
                Hex.decode("d2c49628bb5f647123ecae4abf263dff8d52fc67c9e926c0d981a5a348513a2506ddc86b5a8462e3665cf1a5043d1986de700813a73c391f43aa1fb0da1f930b")
        );
        KeyPackage keyPackage = kpSecrets.keyPackage;
        byte[] keyPackageBytes = MLSOutputStream.encode(MLSMessage.keyPackage(keyPackage));
        byte[] gotKeyPackageBytes = Hex.decode("00010005000100012041FA374317788F1FE19DD5E6E2D26B5226C649CC4945B263DFDB869555EE1F1B209F8F8947AAB701C461DB236C72159B5A170E68C91A248EC3D056FB2E863EB53D20FAB00003F9FA0E16A365023EA8039A078928029263FF4373598D00F4FDDCE46D000103626F620200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF0040407694FD6323497445C1A4F41D2289E98343474890A31A996DC79BC39496DD911BA7692966F1B3A6622AE82D21075CAFA228E0A29C805B67823481298DCD2B220A004040D2C49628BB5F647123ECAE4ABF263DFF8D52FC67C9E926C0D981A5A348513A2506DDC86B5A8462E3665CF1A5043D1986DE700813A73C391F43AA1FB0DA1F930B");
        assertTrue(Arrays.areEqual(keyPackageBytes, gotKeyPackageBytes));


//        Executing function: commit
        /**
         * Alice commits
         * < state id
         * < by_value
         *      < proposal type + key package
         *
         * > commit
         * > welcome
         */
        System.out.println("\n Alice commits");

        // No by ref
        // 1 by value
        List<Proposal> byValue = new ArrayList<>();
        MLSMessage kp = (MLSMessage) MLSInputStream.decode(keyPackageBytes, MLSMessage.class);
        Proposal add = Proposal.add(kp.keyPackage);
        byValue.add(add);

        boolean forcePath = false;
        boolean inlineTree = true;

//        SecureRandom random = new SecureRandom();
        byte[] leafSecret = Hex.decode("dee5d7e93b86273b99fd3de77d4d6a542006ed44ed48d07a0ca22032e2b0bddb");
//        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm1 = group0.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes = MLSOutputStream.encode(gwm1.message);
        gwm1.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes = MLSOutputStream.encode(gwm1.message);

        byte[] expcommitBytes = Hex.decode("000100012432623731656231662D346130332D346233382D616632322D633837356532353335346538000000000000000001000000000003411E010001000100012041FA374317788F1FE19DD5E6E2D26B5226C649CC4945B263DFDB869555EE1F1B209F8F8947AAB701C461DB236C72159B5A170E68C91A248EC3D056FB2E863EB53D20FAB00003F9FA0E16A365023EA8039A078928029263FF4373598D00F4FDDCE46D000103626F620200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF0040407694FD6323497445C1A4F41D2289E98343474890A31A996DC79BC39496DD911BA7692966F1B3A6622AE82D21075CAFA228E0A29C805B67823481298DCD2B220A004040D2C49628BB5F647123ECAE4ABF263DFF8D52FC67C9E926C0D981A5A348513A2506DDC86B5A8462E3665CF1A5043D1986DE700813A73C391F43AA1FB0DA1F930B0040403D861CC88D3D86F52AC324F25B701046E862AB3B0BCD72D1C3805B9024D86069C81C13706C4F11DE555DEF6D34F7A72A43064196AB33BF02D9510BA407B11C03208AEE28D2FD00D1C5D7287CEAB1B821C1B92938F5ADF666F6A7CAF9C82ED7C8472062EC6B1CED498B972FDDEC8FCBA94614C314337CC6C7E749DC7BE397F49C3CD0");
        byte[] expwelcomeBytes = Hex.decode("0001000300014076204A9B9D5B63B0B2D88E8171CF58DF89733DFDE96818EBAFFF48BA135D479C26522058E6B6D3DCADA324422DCFEF0C0E67B3F12E6D905FECAEED23822348FFED667233BB519CBD9130B3B8AC7A201A66B335B6354D121E1BE1F0D8CB9F1405F178F9386E7DF70FE3565C47E691C44AD335E5069948F24260F65E4891D7169B27C85FBD8BB2AD8E0040401D6B805201CBD1F0008A69E34B5123191A11F4D16E0ED114851CE9ABB16BDCD53C3A4953A92AFD5E9198BA5BE02BF0459A5E3913ED20C0CE84BA9CB1B6D42F0DE1B754C1C265D4239B1FAAE3B0BEC7BD6E14C4D0D6BD8D0254663FABA0E360F2D6BC4C23074F5628BDCEBB72E9955439BCA5053999FFB655F22B5E9C1B5DDB55B9E606EF0D48A1C4A53B78086D3E02664E2CBBF471375271AF7BE431EA0BAC4D9FC511160BB537B712C49C4FB93E414CCAF384BCF3E6AEE97CB95CCFE6A9B3D9B94805F02489C44D145D3A5CE5CE6F8C3C274C3E8B23B7D3480E929AD28EDB7DFB52A4C189B28165A77F3B5BC4C3952718DAA50B759E5B8CF661D0DE9C3378A22A1C9BF512A2E8F8171B06BE227ABE26AEB88A2117CFD0325F1846AAB7F79188376D0AA7E0DD7CB6B749441473D04C63C85F05B585F14756B837B3FCB95FE3582A864269A8465CF57440E34227DE412C9DD71AFCF59273DB8A25FC2743643E5E31BEB6C9FABC4063645FD0C821609AB408716351814E77C0F06C84D62993FF1B32C3BD0F502F0CD9594FCC21D07CF4559FF498F0A2981B84C5B9F0F3D98D72039A2CF59CE7061DCFB4F496C5B59BD6ACF2F84024653F34B04AB3D3F37BECBB31F38BD7E55002006181C23A4BF1B05E158E9070C6D919B41EEC8620DBDF07ECC1E71AE2798ACBDCB87F3F4F23F0CA177E4099350DB0F57346E0A6B898D3026B8BB86652E4E87D398EAA484C71F4A605811600B7D4F5403A86AF46416F00F13D1DB07289E64E1DEA4B7E71B4A030653D394DC50EAC129DDF1CF48A3B7FED934887728217A6E7586368BB3FC3356614");
        System.out.println("gotc: " + Hex.toHexString(commitBytes));
        System.out.println("expc: " + Hex.toHexString(expcommitBytes));
        assertTrue(Arrays.areEqual(commitBytes, expcommitBytes));

        System.out.println();
        System.out.println("gotw: " + Hex.toHexString(welcomeBytes));
        System.out.println("expw: " + Hex.toHexString(expwelcomeBytes));
        assertTrue(Arrays.areEqual(welcomeBytes, expwelcomeBytes));

        // pending commit = commitBytes
        // pending groupid = gwp1.group id

//        Executing function: handlePendingCommit
        /**
         * Alice handles pending commit
         * < state id
         *
         * > new state id
         * > epoch authenticator
         */
        System.out.println("\n Alice handles commit");

        // gets group0 and returns gwm1.group
        byte[] epochAuthenticator = gwm1.group.getEpochAuthenticator();

//        Executing function: joinGroup
        /**
         * Bob joins group
         * < transaction id
         * < welcome
         * < encrypt
         * < identity
         *
         * > new state id
         * > epoch authenticator
         */
        System.out.println("\n Bob joins group");

        MLSMessage welcomeMsg = (MLSMessage) MLSInputStream.decode(welcomeBytes, MLSMessage.class);
        Welcome welcome = welcomeMsg.welcome;
        TreeKEMPublicKey ratchetTree = null;
        Group group2 = new Group(
                suite.getHPKE().serializePrivateKey(kpSecrets.initKeyPair.getPrivate()),
                kpSecrets.encryptionKeyPair,
                suite.serializeSignaturePrivateKey(kpSecrets.signatureKeyPair.getPrivate()),
                kpSecrets.keyPackage,
                welcome,
                ratchetTree,
                new HashMap<>(),//TODO WHERE IS JOIN.EXTERNALPSKS POPULATED
                new HashMap<>()
        );
        byte[] bob_join_epochAuthenticator = group2.getEpochAuthenticator();
        // state id = group2 id

//        Executing function: createExternalSigner
        /**
         * ds creates external signer
         * < suite
         * < identity
         *
         * > signer id
         * > external signer
         */
        System.out.println("\n Ds creates external signer");

        byte[] dsIdentity = Hex.decode("6473");
//        AsymmetricCipherKeyPair sigSk = suite.generateSignatureKeyPair();
        byte[] sigSkBytes = Hex.decode("43158fb03b2f886f3ea929999028ae7acfb54d4daf558fa0275dddb0ce7e425a");

        AsymmetricCipherKeyPair sigSk = suite.deserializeSignaturePrivateKey(sigSkBytes);
        cred = Credential.forBasic(dsIdentity);
        byte[] signer = suite.serializeSignaturePublicKey(sigSk.getPublic());

        ExternalSender extSender = new ExternalSender(suite.serializeSignaturePublicKey(sigSk.getPublic()), cred);
        byte[] expextsender = Hex.decode("20BCE7ADA71EA198B5E741D6ABB40B034D9092548BDF833B49F7C8474ADEED8E4E0001026473");

        assertTrue(Arrays.areEqual(expextsender, MLSOutputStream.encode(extSender)));
//        Executing function: addExternalSigner
        /**
         * alice add external signer
         * > state id
         * > external sender
         *
         * < proposal
         */
        System.out.println("\n Alice adds external signer");

        List<Extension> extList = new ArrayList<>(gwm1.group.extensions);
        List<ExternalSender> extSenders = new ArrayList<>();
        System.out.println("extlist size(): " + extList.size());
        for (Extension ext : extList)
        {
            if (ext.extensionType == ExtensionType.EXTERNAL_SENDERS)
            {
                extSenders = ext.getSenders();
            }
        }
//        extSenders.add((ExternalSender) MLSInputStream.decode(extSender, ExternalSender.class));
        extSenders.add(extSender);
        extList.add(Extension.externalSender(extSenders));

        MLSMessage proposal = gwm1.group.groupContextExtensions(extList,
                new Group.MessageOptions(encrypt, new byte[0], 0)
        );

        byte[] expproposal = Hex.decode("000100012432623731656231662D346130332D346233382D616632322D63383735653235333534653800000000000000010100000000000200072A0005272620BCE7ADA71EA198B5E741D6ABB40B034D9092548BDF833B49F7C8474ADEED8E4E00010264734040B9B77E15D47BA4D04BC0D8D027A92780A82EFF3647FA0DA155617DF7F95B6C7BD4172415E7B5A5DB29CC1D3D410257D34FFD7FFD398AA7C524C8D33E3F8F210A202B4001AAED34A12DC27C7B8B971A436AF0C6BD8E53238F2E723EF98ABF81C0AB");
        MLSMessage expProposal = (MLSMessage) MLSInputStream.decode(expproposal, MLSMessage.class);
//        proposal = (MLSMessage) MLSInputStream.decode(expproposal, MLSMessage.class);

        System.out.println("gotep: " + Hex.toHexString(MLSOutputStream.encode(proposal)));
        System.out.println("expep: " + Hex.toHexString(expproposal));
        assertTrue(Arrays.areEqual(expproposal, MLSOutputStream.encode(proposal)));

//        Executing function: commit
        /**
         * Alice commits
         * < state id
         * < by_ref
         *      < proposal
         *
         * > commit
         * > welcome
         */
        System.out.println("\n Alice commits");
        // 1 by ref
        Group shouldbenull = gwm1.group.handle(MLSOutputStream.encode(proposal), null);
        if (shouldbenull != null)
        {
            throw new Exception("Commit included among proposals");
        }

        // no by value
        byValue = new ArrayList<>();

        forcePath = false;
        inlineTree = true;

//        SecureRandom random = new SecureRandom();
        leafSecret = Hex.decode("f67847de530d36454cf86a32925bda6bb363d3d9ead857098cd9fd76a7444f0e");
//        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm3 = gwm1.group.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes2 = MLSOutputStream.encode(gwm3.message);
        gwm3.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes2 = MLSOutputStream.encode(gwm3.message);

        byte[] expcommitBytes2 = Hex.decode("000100012432623731656231662D346130332D346233382D616632322D633837356532353335346538000000000000000101000000000003220220EBC7C348742D014D72160C7E6A1F0A291510F4C40F44582E2C2B4C2DDEA25F3C01201E5E7835EBBA2E1EDAD77999CD8C211B3E11768E54D427C83EACFB5E0985C327202CE76295CBDAF760F4D9A1D75A31758B7D92C3BAA22F3C0040135DED12FD7F6F000105616C6963650200010C000100020003000400050006000004000100020320C0611D52336B6695495F7B6B44E43856472785CE1F200BA1C1C98974F070E53E004040286C3894BC8FD3BAB09D9D199A783F6AECED2661E6CA64D5680FCADF004953C951E2C75B25DBD11BC9BA23A9828E3D1ABEE500B77553C9C7C177F89EA518320F407520724B8182DFE61523996C9B499CF70E237274E0B79587ECF59603E17E5329A96B4052201B9E3CD2798390D4A1114DBE90247E3846DCCE437844878DCD45001BDA95A37B304886803268AA9982CB45EC73E49B124466281F22F6173DB334D900F3FBE3D16824727CA9702A2A839D41637F0D48CDD440403919A83F50913FD07E6ED5E3A5D5BEFF5F228A5D40498A3B4CCFC11A4A0A12AE39112B3D8148A7451CB1DCBB75D73F987B1F35E2D06D33966476474A04388A0B202EA8289AFAB5F31D9B66F21E2CF75D7BE3609A8D32CE24DFA8AB3EEEFA6ED6E82079C0E366D9E92FEB645C2D47C1EE266EDAADC8CC2BE7DBEF1E3EA3F3981A9FB3");
        byte[] expwelcomeBytes2 = Hex.decode("0001000300010042BF5780CD26604B16FCFA64A3F47F4E22B04F542CC38CB894781D59DA98597AEA58EF9E8B354945647AE92297A59253B867EB26D6877093D569DFA99483EF06A20F3C404E9A2A05699B1888D5F43F83BCC6E175C6C2174E7A4A897F4E14676A7B42D91F51B5D4B872BEADEC2CE75F7E8E1180B0EC19BE51ECA2053A00A4DC29AB2F387A31469BC126C2190DE8ABD4B5A2CC9309E90D5D31475CE9A9846F3191F9C3E85CA9CD54B34CC4CDF7258EC39FADA58031D6A9C42A796272D460C61D91776BFC53400971AEA999CD0202254B2424BA4B252E16C864E08FB90505E19B45FF1839A9E1BC627215D1F619A8A3AB6963F4D8508488AFDE9721791577F33ED032E9D0987D01D1FAAAE3085571F040AB67DC3B9FC18F65CEEE0AEC652522F962A5C0CB828C72F6874F85DE4AABCB3F2103DCB63C33F9E998234B526F43F408E62CF98A5FB8A84A573F61F6B2BD6BE8B5FAF5A988047738D01CEB6859ED07AB95B9A53B99ACCBFD71BA7B573B404A1B30E53F5669AA470E7C4574262E1AD130B5291EE70016EF8BB61090AF1B602738DA9132C2F428F4845646808815D5E5631A61D068A322DDB6A823F0910720878C35C5E5FDE10124F366D72951C53DBF54ACAD59DDC79ED5D275D53884C165C643D3A6A784553B847A0AA42C6B1152BEEEEE37007F9F32A169E67D692CC1A52E36734A3345F95A9EE7988EC51E1CE4FFE75D2F6D6389FB5772041810E3E20C7B3021522813DE20EC58A7681DC2A9F91D4A9F513FABB2BB7A272501B4860BEF4F780F9E14A6FB9DB45FC93E3386E253B9919AFD658786F575B914CAACB71E7B113A1B916216278BB0756315A5D8E9DE07DA9BE3ED79B6B0689E85074F69B390D2FD1BBD4FD215D27DB0E2A6421292A380604B63E76602605C879FB61939750ADD780195BF6D8D8C615575228A65B4740B7E0DDC893DB5F1D83EE7446F231C1906E93CA859AFF5BF881DD6EDEE5DD0D2D5A7BDF3");
        System.out.println("gotc: " + Hex.toHexString(commitBytes2));
        System.out.println("expc: " + Hex.toHexString(expcommitBytes2));
        assertTrue(Arrays.areEqual(commitBytes2, expcommitBytes2));

        System.out.println("gotw: " + Hex.toHexString(welcomeBytes2));
        System.out.println("expw: " + Hex.toHexString(expwelcomeBytes2));
        assertTrue(Arrays.areEqual(welcomeBytes2, expwelcomeBytes2));

        // pending commit = commitBytes2
        // pending groupid = gwp3.group id

//        Executing function: handlePendingCommit
        /**
         * Alice handles pending commit
         * < state id
         *
         * > new state id
         * > epoch authenticator
         */
        System.out.println("\n Alice handles commit");

        // gets group0 and returns gwm3.group
        byte[] epochAuthenticator3 = gwm3.group.getEpochAuthenticator();

//        Executing function: handleCommit
        /**
         * Bob handle commit
         * < state id
         * < proposal
         * < commit
         *
         * > new state id
         * > epoch authenticator
         */
        System.out.println("\n Bob handles commit");

        // state id = group2
        // proposal = proposalMessage/ByReference
        // commit = commitBytes2
        shouldbenull = group2.handle(MLSOutputStream.encode(proposal), null);
        if (shouldbenull != null)
        {
            throw new Exception("Commit included among proposals");
        }

        Group group4 = group2.handle(commitBytes2, null);
        if (group4 == null)
        {
            throw new Exception("Commit failed to produce a new state");
        }

        //Executing function: createKeyPackage
        /**
         * Charlie creates a KeyPackage
         * < cipher suite
         * < identity
         *
         * > transaction id
         * > key package
         * > init priv
         * > encryption priv
         * > signature priv
         */
        byte[] cIdentity = Hex.decode("636861726C6965");
        kpSecrets = newKeyPackage(suite, cIdentity
                ,
                Hex.decode("b2a005aa4415f91d10d100c8582de82c37578f2c52426d15525231f72adbc901"),
                Hex.decode("03aa8fe48cf061a509e1f79cd5c8d57e28263d396f20859a424155e4305e2916"),
                Hex.decode("1ced268bbb1aeb8d9e4356f703eb1c27a4a4cf69a4b08a38f0b4e9bce4c40916"),
                Hex.decode("a3f1350a92ec06fa5f3c60fe0f85910e219fca6230d4f40a9090612dfd3c3772867fab7dc411b7a20a5d5f2eb7c7a4f0817c79cb5227a162ec8bac2a16f33b06"),
                Hex.decode("247403d6d8f516ab416c7104772c90d94abffe8801f04bc8e1695b64bc25aa686430bd97b4ccad964c2b8e718aa1bcea66ed0ddef7b101b151c4ec489f37da05")
        );
        keyPackage = kpSecrets.keyPackage;
        byte[] keyPackageBytes2 = MLSOutputStream.encode(MLSMessage.keyPackage(keyPackage));
        byte[] gotKeyPackageBytes2 = Hex.decode("0001000500010001208CAB7B55BBE4040AD9643982480A13A43E021D2BB329F9DDF4D3B9988C95E96C20E624DCBE67A5D9928DF25CC673014A2BC0359D1EE4AF1193A9F9919552206906201B84574A89C41B92E4DCA3303D151A209C733F15CA31560B0063B5C6BE482424000107636861726C69650200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF004040A3F1350A92EC06FA5F3C60FE0F85910E219FCA6230D4F40A9090612DFD3C3772867FAB7DC411B7A20A5D5F2EB7C7A4F0817C79CB5227A162EC8BAC2A16F33B06004040247403D6D8F516AB416C7104772C90D94ABFFE8801F04BC8E1695B64BC25AA686430BD97B4CCAD964C2B8E718AA1BCEA66ED0DDEF7B101B151C4EC489F37DA05");
        assertTrue(Arrays.areEqual(keyPackageBytes2, gotKeyPackageBytes2));

        //Executing function: groupInfo
        /**
         * Alice creates a group info
         * < state id
         * < external tree (TRUE)
         *
         * > group info
         * > ratchet tree
         */
        MLSMessage groupInfoMsg = gwm3.group.getGroupInfo(false);
        GroupInfo groupInfo = groupInfoMsg.groupInfo;
        byte[] gotGroupInfoBytes = MLSOutputStream.encode(groupInfoMsg);
        byte[] expGroupInfoBytes = Hex.decode("00010004000100012432623731656231662D346130332D346233382D616632322D633837356532353335346538000000000000000220D15A61470F872954434C0E3DCF7F0DBC66CB9D278EE352C6C4CB8EBF7294FE1820BA64A1B12383189375791ED1751321FEF4037EBD08367AD40E2C96C016E7BF1E2A0005272620BCE7ADA71EA198B5E741D6ABB40B034D9092548BDF833B49F7C8474ADEED8E4E00010264732400042120EAEA2C32D7EB7A51CC06F4C3B8F54888DCCF5D2454A114211DAABBD1D5F9F201202EA8289AFAB5F31D9B66F21E2CF75D7BE3609A8D32CE24DFA8AB3EEEFA6ED6E8000000004040C1F1A358B3E74E8B2B0C12600E183C38A275267CCC3B18BE4F041EE48807973D79E37E24A44D8C63A542C5404CEC88020AE5F918AB37F3383C24C047C5D15207");
        byte[] gotTree = MLSOutputStream.encode(gwm3.group.tree);
        byte[] expTree = Hex.decode("41A20101201E5E7835EBBA2E1EDAD77999CD8C211B3E11768E54D427C83EACFB5E0985C327202CE76295CBDAF760F4D9A1D75A31758B7D92C3BAA22F3C0040135DED12FD7F6F000105616C6963650200010C000100020003000400050006000004000100020320C0611D52336B6695495F7B6B44E43856472785CE1F200BA1C1C98974F070E53E004040286C3894BC8FD3BAB09D9D199A783F6AECED2661E6CA64D5680FCADF004953C951E2C75B25DBD11BC9BA23A9828E3D1ABEE500B77553C9C7C177F89EA518320F010220724B8182DFE61523996C9B499CF70E237274E0B79587ECF59603E17E5329A96B00000101209F8F8947AAB701C461DB236C72159B5A170E68C91A248EC3D056FB2E863EB53D20FAB00003F9FA0E16A365023EA8039A078928029263FF4373598D00F4FDDCE46D000103626F620200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF0040407694FD6323497445C1A4F41D2289E98343474890A31A996DC79BC39496DD911BA7692966F1B3A6622AE82D21075CAFA228E0A29C805B67823481298DCD2B220A");

        System.out.println("gott: " + Hex.toHexString(gotTree));
        System.out.println("expt: " + Hex.toHexString(expTree));
        assertTrue(Arrays.areEqual(gotTree, expTree));

        System.out.println("gotgi: " + Hex.toHexString(gotGroupInfoBytes));
        System.out.println("expgi: " + Hex.toHexString(expGroupInfoBytes));
        assertTrue(Arrays.areEqual(gotGroupInfoBytes, expGroupInfoBytes));

        //Executing function: externalSignerProposal
        /**
         * dc external signer proposal
         * < signer id
         * < gruop info
         * < ratchet tree
         * < desc
         *  add + key package
         *
         *  > proposal
         */
//        MLSMessage groupMsg = (MLSMessage) MLSInputStream.decode(groupInfoMsg, MLSMessage.class);

        suite = new CipherSuite(groupInfo.groupContext.ciphersuite);
        byte[] groupID = groupInfo.groupContext.groupID;
        long epoch = groupInfo.groupContext.epoch;

//        byte[] treeData = request.getRatchetTree().toByteArray();
//        TreeKEMPublicKey tree = (TreeKEMPublicKey) MLSInputStream.decode(treeData, TreeKEMPublicKey.class);
        TreeKEMPublicKey tree = (TreeKEMPublicKey) MLSInputStream.decode(gotTree, TreeKEMPublicKey.class);


        // Look up the signer index of this signer
        extSenders = new ArrayList<>();
        for (Extension ext : groupInfo.groupContext.extensions)
        {
            if (ext.extensionType == ExtensionType.EXTERNAL_SENDERS)
            {
                extSenders = ext.getSenders();
            }
        }
        int sigIndex = -1;
        for (int i = 0; i < extSenders.size(); i++)
        {
            if (java.util.Arrays.equals(extSenders.get(i).signatureKey, signer))
            {
                sigIndex = i;
            }
        }
        if (sigIndex == -1)
        {
            throw new Exception("Requested signer not allowed for this group");
        }

        // Sign the proposal
//        proposal = proposalFromDescription(suite, groupID, tree, request.getDescription());
        //PROPOSAL FROM DESC
        Proposal proposalkp = Proposal.add(keyPackage);

        signer = suite.serializeSignaturePrivateKey(sigSk.getPrivate());

        MLSMessage signedProposal = MLSMessage.externalProposal(suite, groupID, epoch, proposalkp, sigIndex, signer);


        byte[] expkeypackage = Hex.decode("000100012432623731656231662D346130332D346233382D616632322D633837356532353335346538000000000000000202000000000002000100010001208CAB7B55BBE4040AD9643982480A13A43E021D2BB329F9DDF4D3B9988C95E96C20E624DCBE67A5D9928DF25CC673014A2BC0359D1EE4AF1193A9F9919552206906201B84574A89C41B92E4DCA3303D151A209C733F15CA31560B0063B5C6BE482424000107636861726C69650200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF004040A3F1350A92EC06FA5F3C60FE0F85910E219FCA6230D4F40A9090612DFD3C3772867FAB7DC411B7A20A5D5F2EB7C7A4F0817C79CB5227A162EC8BAC2A16F33B06004040247403D6D8F516AB416C7104772C90D94ABFFE8801F04BC8E1695B64BC25AA686430BD97B4CCAD964C2B8E718AA1BCEA66ED0DDEF7B101B151C4EC489F37DA054040DDE040142D1CD2D24D08B2C683E3BB3FBAA2C90B8CE99D5E77779702EE49397092446CDD0BD7E3F94E2C4D6169E186C82A1D6F583C47DA9746B4C5480D473507");
        byte[] gotkeypackage = MLSOutputStream.encode(signedProposal);
        System.out.println("gotkp: " + Hex.toHexString(gotkeypackage));
        System.out.println("expkp: " + Hex.toHexString(expkeypackage));
        assertTrue(Arrays.areEqual(gotkeypackage, expkeypackage));

        //Executing function: commit
        /**
         * Alice commits
         * < state id
         * < by_ref
         *      < proposal
         *
         * > commit
         * > welcome
         */
        System.out.println("\n Alice commits");
        // 1 by ref
        shouldbenull = gwm3.group.handle(MLSOutputStream.encode(signedProposal), null);
        if (shouldbenull != null)
        {
            throw new Exception("Commit included among proposals");
        }

        // no by value
        byValue = new ArrayList<>();

        forcePath = false;
        inlineTree = true;

//        SecureRandom random = new SecureRandom();
        leafSecret = Hex.decode("1a1766af8d6f287dc1d616d0493a036169c858c02cb1449486e9e69ad0ab6cd8");
//        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm5 = gwm3.group.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes3 = MLSOutputStream.encode(gwm5.message);
        gwm5.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes3 = MLSOutputStream.encode(gwm5.message);

        byte[] expcommitBytes3 = Hex.decode("000100012432623731656231662D346130332D346233382D616632322D6338373565323533353465380000000000000002010000000000032202205AB798C6E53C04417EFD2C200FEFC037AA20578E9DBCEDDC26674B3116E7625A004040DC6825A3B6C8B6FF0507A0940E91A5E64CAAF47EE326198A97650BAFC5AEFF982C1F56C61586294F2ED60F98F6A35492C546493FD450FEF964A58496C7FF6D0E20CEB3ED1B8C6C7FE997DB47A68E53FE9E8D7CD46C1C15D1EF87D60B7BA7FBCD6120988138978793033FC1E7DAAD2C7BAD05CFCF6DBED527EF734B0E3FA67A2AF298");
        byte[] expwelcomeBytes3 = Hex.decode("000100030001407620FA6E6E881FD39128CD53B7863416ABC83EFC05E7CE289BF38AABCCBE38621DD32054FF6B56A4D09D5D45E8E39AF8328C879B083F1199001499D6521785DCD5C06E3355324F7AC6D5E74B598B65649CF532FF0DE05AEBE9DC052D9E906CDFBC09DE1ADDA39282A1BA6BD656F89468B3CCAFB1C04BCF43795E5472198AD95A6F2CD27146800848CBBF2AB43CE9C34E10F446AB4FC782FEF12F44F64CC1A49595A8635A48D3A34A2EF6DE3D3C96276793609C66350F46155A86AD9EA8F664B1D8081342BB6F7397F98FA58AC2A95A8134CF2E82B2F4C74AC05D3D9FBB65BF554D16A855EA158C020A6FC84C9F28B8DC9BEC308B66ECAE0073602BDA2D5F90530798ABE52CB00283054BA1B97C68CAA6294BFCDC65DDACEE8F5F7F2B0EF9DCA8C669352D365DBEAA92D8BA77B4DB102B9C0FD63A96F9D7FA104947AC94DDE8C9C18A1EEA1CFC8FBFE3C58DB178EB2935FAE927DD3CADD1B11FEB288166FCFAD5852A984A0599A64E6371AE886D4DA0577C8D34BACF83E461E3B2E567959BF57C0F0D6F87B95D7983FA467F43C70554680D8A2AEADB8B085F50FC01EF7D60CFC7D0B981F28964F29F270C8A860296B09C427BA5B2D3231788E7BAEF72675BB487100B77D53484708D6242C39CB9AA6EC13D110898CAEB491BC00944F9DE433947CC3E465E917854F53255939EB2B1ED8AB929DD88D7384571DCE24C1091A54CFF85982955CD3EF0637F4EA518063A25D286A4F288808F67BF4F0791BF51ECDBEECC765E9058F0D9BFC83A9C10324C108F058EEDE0E71F0AE72B9EB3976FE6B03CAF800868F956DA088AAE10A215DBB09E6758763776FBC8CB6D29C09F63F6A9E290A2CEBF85C899C23B29DD7E90B53366B48BD068483A044ACEDFFB94FD85A795B58FCCBD7FFA67817BDD8F44F659ACA94A5DC4C6EE5F223134E6FD75ED0CAD90950B8B9C819F31C71256AFBD943A89434B828A6D69333118F2635988890B3A74CC327D6B082362A80F5B3E84E2E77BD3D5A076359C050533C20F9EB166761FE653AF63CC1C5C48068C9B9C63D86684AD48587BA56C66468FA8D32E800CE0F1FE85A28792A6CED197D190790BFBEAC9BDE2C724E1D2B30BD49AD9682D3C0EC87CB288ED5FEB3D6ED3C81C75A77A2FC82FC2F03644F7B935F4270071790FE1082529304801D93BA3B10D5F7D2CC9F854FF25FA6F2060036FB7C9F483CD5918A6650DFAAC6E509296E223C1903FFD765F74D759534181ABAFD18735BFFC587117A55701DE7707A3349230BC3623541FFB4A9D51622256735EA29D25FE3581CB849807871ADE2F9A2E46DCA499B674B834D92A88D9664F2D72A1F3063ED8DE595E9E5EBE4F59FF767BFC84B0964B42F3FC7AE99D4893DC6072BC384BF76A3ADE7B066AFEFB0B068546944F2B67DBC057A9A56D22");
        System.out.println("gotc: " + Hex.toHexString(commitBytes3));
        System.out.println("expc: " + Hex.toHexString(expcommitBytes3));
        assertTrue(Arrays.areEqual(commitBytes3, expcommitBytes3));

        System.out.println("gotw: " + Hex.toHexString(welcomeBytes3));
        System.out.println("expw: " + Hex.toHexString(expwelcomeBytes3));
        assertTrue(Arrays.areEqual(welcomeBytes3, expwelcomeBytes3));

        // pending commit = commitBytes3
        // pending groupid = gwp5.group id


    }
 public void testExternalJoin()
        throws Exception
    {

        // Executing function: createGroup
        /**
         * Alice creates a group
         * < group id
         * < cipher suite
         * < encrypt
         * < identity
         *
         * > state id
         */
        byte[] groupIDBytes = Hex.decode("61633361626434352D323937362D343663612D616533652D663731336438643431353034");
        CipherSuite suite = new CipherSuite((short) 1);
        byte[] identity = Hex.decode("616C696365");
        boolean encrypt = false;

//        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        byte[] sig_priv = Hex.decode("e5328cd274c6cc98c41fc4cf3e3ab91c953a957c00adaf0d27338dfe092d6adb");
        byte[] leaf_priv = Hex.decode("a649479b2b84abbbbb976f62db14708cd460441c6e099cdb1fb1aa04806e152d");
        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().deserializePrivateKey(leaf_priv, null);
        AsymmetricCipherKeyPair sigKeyPair = suite.deserializeSignaturePrivateKey(sig_priv);

        Credential cred = Credential.forBasic(identity);

        LeafNode leafnode0 = new LeafNode(
                suite,
                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
                cred,
                new Capabilities(),
                new LifeTime(0, -1),
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        leafnode0.signature = Hex.decode("b5719040eee66e22f879595593bed2ac466110df1a169f9b57eaffda84e548ffeae3928917c1ee56607e27bd0e9ff68aa647708d76617d39bcb9ff0dee64cf0b");

        Group group0 = new Group(
                groupIDBytes,
                suite,
                leafKeyPair,
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate()),
                leafnode0,
                new ArrayList<>()
        );
        // Executing function: groupInfo
        /**
         * Alice creates a group info
         * < state id
         *
         * > group info
         * > ratchet tree
         */
        MLSMessage groupInfoMsg = group0.getGroupInfo(true);
        GroupInfo groupInfo = groupInfoMsg.groupInfo;
        byte[] gotGroupInfoBytes = MLSOutputStream.encode(groupInfoMsg);
        byte[] expGroupInfoBytes = Hex.decode("00010004000100012461633361626434352D323937362D343663612D616533652D66373133643864343135303400000000000000002037F2CBAE79C24053D35D6E087F525D88A4D9EB2DFAD25D5570FAA3E7569ADEFD000040E10004212092F560ACFA69C8995EBC5228DE79D16E3D11C7E3DDA9C1FD53DA84DB0746CF43000240B940B7010120125FE61431D890F49B6A733F7F85252FA7939D3587936171549F7E8DEA11CC73200EB9DCCEBB25B99F5F45EB0D2CE730C483C8CB778A8E908E7D051D4EA808C6BD000105616C6963650200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF004040B5719040EEE66E22F879595593BED2AC466110DF1A169F9B57EAFFDA84E548FFEAE3928917C1EE56607E27BD0E9FF68AA647708D76617D39BCB9FF0DEE64CF0B2048AC208A0BE8D5044139BE58DD5165B59CD6D2698E23E2A7C71202338362921300000000404005B5A114A4A1DE2018EBF887B64ACB6180655FDDC1F3AD56D430EC7F55B3AFB8B9899B61943B8FB123BEB1A067F4239C4AB89A9C480EAC3087607A9D05639905");

        System.out.println("gotgi: " + Hex.toHexString(gotGroupInfoBytes));
        System.out.println("expgi: " + Hex.toHexString(expGroupInfoBytes));
        assertTrue(Arrays.areEqual(gotGroupInfoBytes, expGroupInfoBytes));

        // Executing function: externalJoin
        /**
         * Bob external join
         * < group info
         * < identity
         *
         * > state id
         * > commit
         * > epoch authenticator
         */
        identity = Hex.decode("626F62");

//        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().generatePrivateKey();
//         leafKeyPair = suite.getHPKE().generatePrivateKey();
//         sigKeyPair = suite.generateSignatureKeyPair();
        byte[] init_priv = Hex.decode("fe6ab97bb17a75ac8774dbab322208bdde66c77f1162b52483f2e280d13783cc");
        byte[] leaf_priv1 = Hex.decode("a8042cf17e45ad1d4ba08cbfa8dfca68677189bde0856a709f54fb94ffef7a55");
        byte[] sig_priv1 = Hex.decode("67cac4a16a255e7c0406399b7062744a9bfd57dbdb98e5ea086a9741b26bd56f");
        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().deserializePrivateKey(init_priv, null);
        leafKeyPair = suite.getHPKE().deserializePrivateKey(leaf_priv1, null);
        sigKeyPair = suite.deserializeSignaturePrivateKey(sig_priv1);

        cred = Credential.forBasic(identity);

        LeafNode leafnode1 = new LeafNode(
                suite,
                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
                cred,
                new Capabilities(),
                new LifeTime(0, -1),
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        leafnode1.signature = Hex.decode("9417aa7ac67b47b55ecaa1210951dfe461cf9abace0b20df45db636b1031e1f64c7b6178dbb26ee42876d9d22315537a6a0d4d9917c4b0d434303b1caaeba504");

        KeyPackage kp = new KeyPackage(
                suite,
                suite.getHPKE().serializePublicKey(initKeyPair.getPublic()),
                leafnode1,
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        kp.signature = Hex.decode("5138637f397b0bc7d723fa04c871e2474dda3c27a4ec77d9c4ba9a51cb89be8b1175d0c941ae67724ceec88cb6520634268fb31b8982927a7509eb9d1925bc02");

        TreeKEMPublicKey ratchetTree = null;
        LeafIndex removeIndex = null;
        boolean removePrior = false;
        // no remove prior
        if (removePrior)
        {
            // same as importTree()
            TreeKEMPublicKey outTree = null;
            for (Extension ext : groupInfo.extensions)
            {
                outTree = ext.getRatchetTree();
                if (outTree != null)
                {
                    break;
                }
            }
            if (ratchetTree != null)
            {
                //TODO: check if it should be a deep copy
                outTree = TreeKEMPublicKey.clone(ratchetTree);
            }
            else if (outTree == null)
            {
                throw new Exception("No tree available");
            }

            // Scan through to find a matching identity
            for (int i = 0; i < outTree.size.leafCount(); i++)
            {
                LeafIndex index = new LeafIndex(i);
                LeafNode leaf = outTree.getLeafNode(index);
                if (leaf == null)
                {
                    continue;
                }

                if (!java.util.Arrays.equals(identity, leaf.getCredential().getIdentity()))
                {
                    continue;
                }
                System.out.println("removedIndex: " + i);
                removeIndex = index;
            }
            if (removeIndex == null)
            {
                throw new Exception("Prior appearance not found");
            }
        }

        // no psks

        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(leafSecret);
        leafSecret = Hex.decode("b9d81412d8b2ff2cfe276a9d352a18c3fdc5d1b600d2a3abf45be38465fb4bca");

        System.out.println("LEAFSECRETHERE");
        Group.GroupWithMessage gwm1 = Group.externalJoin(
                new Secret(leafSecret),
                sigKeyPair,
                kp,
                groupInfo,
                ratchetTree,
                new Group.MessageOptions(false, new byte[0], 0),// encrypt should be false for external join!
                removeIndex,
                new HashMap<>()
        );

        byte[] commitBytes = MLSOutputStream.encode(gwm1.message);
        byte[] expCommitBytes = Hex.decode("000100012461633361626434352D323937362D343663612D616533652D663731336438643431353034000000000000000004000324010006208533764049808656AE660D3215AB3801C760AF269E2B80823D1EBB7F37B89350012098ECD2E3C2E7B2ABBB50D3955AB45BA47E5E0D72CFE9DED01AE76ABB6D64654C2041856E53D310F88CE1A82E674EC3D2EBC36AB9C5E125E57433167488E98D6834000103626F620200010C000100020003000400050006000004000100020320659F1FEF67062D12D509D09A0279A88739CCE431D03FCE34482494989F137628004040EFFC2E2B0727A52EE22B86BCB830B9C3C1EE86BCEB008EFE588B0F04A553D813DA4200653869D20237A31BB1D9C509FBD01AFF408D1BE272792D78EDAFEF120D4075203DBB3B1265761871827CB2CA7DE67754B15AEA360D1EAD3DD9D43364B065D00240522076EC09BBFB456617463404071CF57A964790FDB072AD00ACE49C01D673E05B5A30937A03AC0143710FEDF2A8B5F95F11D3D5BE099345712C6EBC1E56CE38203E0F711A3BA80DCE10AA448C2BF06B1A01EC4040D256E19DB17676979B278BD661B6EC8320FE49FEAFA6969645D48C2E10376C4E2E82BE7ABCBCA452C4F4067E8D9844F4FA11E15A4F5787DE0DEAEC712659D1082087683706EB321BC92FA57CDB04944211B338748750EDD235A37876E09D49C00D");

        System.out.println("gotc: " + Hex.toHexString(commitBytes));
        System.out.println("expc: " + Hex.toHexString(expCommitBytes));
        assertTrue(Arrays.areEqual(commitBytes, expCommitBytes));

        // Executing function: handleCommit;
        /**
         * Alice handle commit
         * < state id
         * < commit
         *
         * > new state id
         * > epoch authenticator
         */
        Group group2 = group0.handle(commitBytes, null);
        if (group2 == null)
        {
            throw new Exception("Commit failed to produce a new state");
        }
        byte[] epochAuthenticator = group2.getEpochAuthenticator();

        /**
         * Alice creates a group info
         * < state id
         *
         * > group info
         * > ratchet tree
         */
        MLSMessage groupInfoMsg2 = group2.getGroupInfo(true);
        GroupInfo groupInfo2 = groupInfoMsg2.groupInfo;
        byte[] gotGroupInfo2Bytes = MLSOutputStream.encode(groupInfoMsg2);
        byte[] expGroupInfo2Bytes = Hex.decode("00010004000100012461633361626434352D323937362D343663612D616533652D6637313364386434313530340000000000000001205B81B48B02C8D049362164724C08F12C88B9B21688872DB647D01F948271AA60205C25D2FB91CCE6301E3BA5BDBB50EFECED3A3350C9BACAA723A5FB97519056D50041CC000421205D84A38A3DD0B3A2E51458FEA73215956825C1D12ACB637040B72BACD097976F000241A441A2010120125FE61431D890F49B6A733F7F85252FA7939D3587936171549F7E8DEA11CC73200EB9DCCEBB25B99F5F45EB0D2CE730C483C8CB778A8E908E7D051D4EA808C6BD000105616C6963650200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF004040B5719040EEE66E22F879595593BED2AC466110DF1A169F9B57EAFFDA84E548FFEAE3928917C1EE56607E27BD0E9FF68AA647708D76617D39BCB9FF0DEE64CF0B0102203DBB3B1265761871827CB2CA7DE67754B15AEA360D1EAD3DD9D43364B065D002000001012098ECD2E3C2E7B2ABBB50D3955AB45BA47E5E0D72CFE9DED01AE76ABB6D64654C2041856E53D310F88CE1A82E674EC3D2EBC36AB9C5E125E57433167488E98D6834000103626F620200010C000100020003000400050006000004000100020320659F1FEF67062D12D509D09A0279A88739CCE431D03FCE34482494989F137628004040EFFC2E2B0727A52EE22B86BCB830B9C3C1EE86BCEB008EFE588B0F04A553D813DA4200653869D20237A31BB1D9C509FBD01AFF408D1BE272792D78EDAFEF120D2087683706EB321BC92FA57CDB04944211B338748750EDD235A37876E09D49C00D0000000040401C28881136C0D82A35B1B037260C5D00AD4CCF92D67545942CFB08C5736F5381C90A952519BB3F74946CEC7F32DBA8C886822E1BA1CB93C8A12028CE3F2D2406");

        System.out.println("gotgi2: " + Hex.toHexString(gotGroupInfo2Bytes));
        System.out.println("expgi2: " + Hex.toHexString(expGroupInfo2Bytes));
        assertTrue(Arrays.areEqual(gotGroupInfo2Bytes, expGroupInfo2Bytes));

        /**
         * Bob external join
         * < group info
         * < identity
         *
         * > state id
         * > commit
         * > epoch authenticator
         */
        identity = Hex.decode("626F62");

//        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().generatePrivateKey();
//         leafKeyPair = suite.getHPKE().generatePrivateKey();
//         sigKeyPair = suite.generateSignatureKeyPair();
        byte[] init_priv2 = Hex.decode("be03079473f6e91c4998360bbf13e3ca014e0fd320bc6a32c97e00c5efb99971");
        byte[] leaf_priv2 = Hex.decode("1c05166e3ab0bb712c4f24b2ba0f1564832e92d0cd85556ed0fc52f18b57b1b6");
        byte[] sig_priv2 = Hex.decode("1d1bf7802211a72376aeec9d3cff30ef7cfaa4f4c10c46c6f58205326a3e73cc");
        initKeyPair = suite.getHPKE().deserializePrivateKey(init_priv2, null);
        leafKeyPair = suite.getHPKE().deserializePrivateKey(leaf_priv2, null);
        sigKeyPair = suite.deserializeSignaturePrivateKey(sig_priv2);

        cred = Credential.forBasic(identity);

        LeafNode leafnode2 = new LeafNode(
                suite,
                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
                cred,
                new Capabilities(),
                new LifeTime(0, -1),
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        leafnode2.signature = Hex.decode("2864cf6a4f163f74ad7838d08bb826f7f82f7e2e8ea8cd8dd03baafc66b019f4cd2345826b0d4a0f90b2bd3e84ddd657b56b6a270593816a060093d88b90b208");

        KeyPackage kp2 = new KeyPackage(
                suite,
                suite.getHPKE().serializePublicKey(initKeyPair.getPublic()),
                leafnode2,
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        kp.signature = Hex.decode("1fd17701620830c876f2a49109fa08316090c0b4a9d5011e6d3bf67054f9c9230434dace8c17d2145946e5099740e3db277f7afd972709acf7949b9f1ebb1e05");

        ratchetTree = null;
        removeIndex = null;
        removePrior = true;
        // no remove prior
        if (removePrior)
        {
            // same as importTree()
            TreeKEMPublicKey outTree = null;
            for (Extension ext : groupInfo2.extensions)
            {
                outTree = ext.getRatchetTree();
                if (outTree != null)
                {
                    break;
                }
            }
            if (ratchetTree != null)
            {
                //TODO: check if it should be a deep copy
                outTree = TreeKEMPublicKey.clone(ratchetTree);
            }
            else if (outTree == null)
            {
                throw new Exception("No tree available");
            }

            // Scan through to find a matching identity
            for (int i = 0; i < outTree.size.leafCount(); i++)
            {
                LeafIndex index = new LeafIndex(i);
                LeafNode leaf = outTree.getLeafNode(index);
                if (leaf == null)
                {
                    continue;
                }

                if (!java.util.Arrays.equals(identity, leaf.getCredential().getIdentity()))
                {
                    continue;
                }
                System.out.println("removedIndex: " + i);
                removeIndex = index;
            }
            if (removeIndex == null)
            {
                throw new Exception("Prior appearance not found");
            }
        }

        // no psks

//        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(leafSecret);
        leafSecret = Hex.decode("1b7057e092a91f51b2f46041f93568a943ef56a40102387c07cc1ddd6085ade9");

        System.out.println("LEAFSECRETHERE");
        Group.GroupWithMessage gwm3 = Group.externalJoin(
                new Secret(leafSecret),
                sigKeyPair,
                kp2,
                groupInfo2,
                ratchetTree,
                new Group.MessageOptions(false, new byte[0], 0),// encrypt should be false for external join!
                removeIndex,
                new HashMap<>()
        );

        byte[] commitBytes2 = MLSOutputStream.encode(gwm3.message);
        byte[] expCommitBytes2 = Hex.decode("000100012461633361626434352D323937362D343663612D616533652D66373133643864343135303400000000000000010400032B01000620314568CEFCC8D759EE28688F5AAF615B1B9DCBED9D7EE176589C0BFDE26AAB21010003000000010120EAA840CB50BC3531AF53E21FFE1C77FC82A2BCE0C31F96211A05066D1FCEB6272011A2C0814D8868900DA36C07A579554F1FAF13929C72C35DF97032E152B054BA000103626F620200010C000100020003000400050006000004000100020320862A54ACFE2BB6F1D1C723C48887C46430A6EB533A98C71E9C75D703CE8C8749004040EE1CE1251E5C7BA0011916F26E4AB33FBF5E48C4112A1A96635907B4C59DB2F4198F738BFBF6C6F17A1CF316CDB051E3834D11B384478E3C94714D58F8EFFC0540752098143BA10B12CE70AB92685CEB83C8C271B8DD44E71520266A17A1AA7E7724304052206D976108A83B3E698A9E9CECBCF3E0096DB0DD178B81F994443ADB9E19B6311F301380EA78EC1853A82B4A891F209A8F0E8D74B737EFE5FD871926D12D29B68EC0CA11A8DDD217120276372DA6C28B3C544040CFCFD88C98913F4CFF733CA45FAD8B56D7B9C552AC2E8553A548D181CBB9F884D3A0A484D02C77439A5E66C373A56AC51C292F1377822CADB8E1A5B14135650D20E0577B277251CDA94330A673D7015D380CCBE32644DCF28C515D7D2FAE955C5C");

        System.out.println("gotc2: " + Hex.toHexString(commitBytes2));
        System.out.println("expc2: " + Hex.toHexString(expCommitBytes2));
        assertTrue(Arrays.areEqual(commitBytes2, expCommitBytes2));

        // Executing function: handleCommit;
        /**
         * Alice handle commit
         * < state id
         * < commit
         *
         * > new state id
         * > epoch authenticator
         */
        Group group4 = group2.handle(commitBytes2, null);
        if (group4 == null)
        {
            throw new Exception("Commit failed to produce a new state");
        }
        byte[] epochAuthenticator4 = group4.getEpochAuthenticator();


    }
    public void testCommitGCE()
        throws Exception
    {
         // Executing function: createGroup
        /**
         * Alice creates a group
         * < group id
         * < cipher suite
         * < encrypt
         * < identity
         *
         * > state id
         */
        byte[] groupIDBytes = Hex.decode("64316530373330652d666536652d343735642d613066342d666362626635343863383330");
        CipherSuite suite = new CipherSuite((short) 1);
        byte[] identity = Hex.decode("616C696365");
        boolean encrypt = false;

        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
//        byte[] sig_priv = Hex.decode("5efa9f0a244067ea8dc5dd0504779af2e3a1ed2cb1374782cc2cf440dd56fda5");
//        byte[] leaf_priv = Hex.decode("edca7b8c2d3e8904fab96cae6b86f18f26500a28d4c0f56cca322076cd7b1358");
//        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().deserializePrivateKey(leaf_priv, null);
//        AsymmetricCipherKeyPair sigKeyPair = suite.deserializeSignaturePrivateKey(sig_priv);

        Credential cred = Credential.forBasic(identity);

        LeafNode leafnode0 = new LeafNode(
                suite,
                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
                cred,
                new Capabilities(),
                new LifeTime(0, -1),
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
//        leafnode0.signature = Hex.decode("1909da4db9c225fcfec102853c1187dd271dd53721191fe92c35fdd2cd254f74ed1ffffd0aafabbef2f0c8d273fbd2c822a88782ba4030de85d1e55ff5b60804");

        Group group0 = new Group(
                groupIDBytes,
                suite,
                leafKeyPair,
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate()),
                leafnode0,
                new ArrayList<>()
        );

         // Executing function: createKeyPackage
        /**
         * Bob creates a KeyPackage
         * < cipher suite
         * < identity
         *
         * > transaction id
         * > key package
         * > init priv
         * > encryption priv
         * > signature priv
         */
        byte[] bobIdentity = Hex.decode("626F62");
        KeyPackageWithSecrets kpSecrets = newKeyPackage(suite, bobIdentity
//                ,
//                Hex.decode("f88aa80c5242dd864e0e4d31a8cbd9f957fda27715a217463bf2aef2d66f191a"),
//                Hex.decode("dfaeaff781a6c6585bb50b5ef0ddb8c34436f9c22c80f0b0efd892efbcc77a06"),
//                Hex.decode("f4ac289eb383bdc2da78be3c19072959c3081c93a8847e090c1b1233d27e5e95"),
//                Hex.decode("4fc9349c51dd30aed878b3f60cfb78a39d6672bd34a39d5f96a97c1e538042fb4be87adc682289c39ad12ddd1611bfdf0de636ecab752c821185a3a56c1bdd0e"),
//                Hex.decode("838483765947df946955b8a53e72fe880469cc3012b994a22d3b1573c6d1de3d3d64ca0c84530a23da0bd9f198555d0ce1b71efd29b5fbc3af976c4582fa3b0b")
        );
        KeyPackage keyPackage = kpSecrets.keyPackage;
        byte[] keyPackageBytes = MLSOutputStream.encode(MLSMessage.keyPackage(keyPackage));
        byte[] gotKeyPackageBytes = Hex.decode("0001000500010001200A81114311D1EC8A6B1587FC7BCE6902D67AFA8FFCA7C44FC08C943320355A5A201EF7A4687D85BA983002D6239F793F590E245286964ED520F9C90380A671230720E35F42BFDD1291B194663E9B9C476679EA8A42E5D58407784048BD051878AD38000103626F620200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF0040404FC9349C51DD30AED878B3F60CFB78A39D6672BD34A39D5F96A97C1E538042FB4BE87ADC682289C39AD12DDD1611BFDF0DE636ECAB752C821185A3A56C1BDD0E004040838483765947DF946955B8A53E72FE880469CC3012B994A22D3B1573C6D1DE3D3D64CA0C84530A23DA0BD9F198555D0CE1B71EFD29B5FBC3AF976C4582FA3B0B");
//        assertTrue(Arrays.areEqual(keyPackageBytes, gotKeyPackageBytes));

         // Executing function: commit
        /**
         * Alice commits
         * < state id
         * < by_value
         *      < proposal type + key package
         *
         * > commit
         * > welcome
         */
        // No by ref
        // 1 by value
        List<Proposal> byValue = new ArrayList<>();
        MLSMessage kp = (MLSMessage) MLSInputStream.decode(keyPackageBytes, MLSMessage.class);
        Proposal add = Proposal.add(kp.keyPackage);
        byValue.add(add);

        boolean forcePath = false;
        boolean inlineTree = true;

        SecureRandom random = new SecureRandom();
        byte[] leafSecret = Hex.decode("11db9cac16289d1d69c4eac3afd0bab1a8d46c83b4d6718bcc55306e412efa49");
        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm1 = group0.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes = MLSOutputStream.encode(gwm1.message);
        gwm1.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes = MLSOutputStream.encode(gwm1.message);

        byte[] expcommitBytes = Hex.decode("000100012464316530373330652D666536652D343735642D613066342D666362626635343863383330000000000000000001000000000003411E01000100010001200A81114311D1EC8A6B1587FC7BCE6902D67AFA8FFCA7C44FC08C943320355A5A201EF7A4687D85BA983002D6239F793F590E245286964ED520F9C90380A671230720E35F42BFDD1291B194663E9B9C476679EA8A42E5D58407784048BD051878AD38000103626F620200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF0040404FC9349C51DD30AED878B3F60CFB78A39D6672BD34A39D5F96A97C1E538042FB4BE87ADC682289C39AD12DDD1611BFDF0DE636ECAB752C821185A3A56C1BDD0E004040838483765947DF946955B8A53E72FE880469CC3012B994A22D3B1573C6D1DE3D3D64CA0C84530A23DA0BD9F198555D0CE1B71EFD29B5FBC3AF976C4582FA3B0B00404009C308E66CA2CE01DDFBCECAA473A6163F78019EA6E3039DED5F1A27F41EA20EACCA32CEF9FE007B832CC6DFD058F030D77C80CF3ED5A4A9B41DB47FEE5E05082082D920D942694561990729DA804A0025789E54F8589CBFFB25CF0DD02C1D92E7203FBFF338DD91BC2B267AAE2BC161D0D4AC7709914EC8DF9FCC83ABE53C4E0B77");
        byte[] expwelcomeBytes = Hex.decode("000100030001407620F8B63D34A753D3FB79086229D3B8D7116E24E2E46B8EEAB3D2754622B8A9412B206DC8E6518F07A8FF73C37006264393E780AD3BAE0271ADAD4E7AFEACA9D0D87B336B512C0C59EC6B3F4D03608DE8F93B08C7AFE4CBE95E989E4D81CC81379E34BD2EADBC0CD4F7EF5D38E9E76F8A0666D18803D442609E42F473E631FB47232A7ECA5F822D1D72A65C4C03CB40FA738AEAE28BB04F17613F8EF6458A9F989E1CE3ACEBC9C42104595A08352C962437760802B42B6EC710B4AE8C3A615FBB9540D727D643016A0E36D85DFF813DE1E5CCECF44E28CCD5ADF5089C3AE4ADE0EF0F095572B815D2C28C92A40BD842B6804005DAD95CFC4A0092BB44DB559490719BEE6479C3039A81EF37D580E40AAEF04340D77ED1C91CC76D46B82A379F691B735399DB9F8FE4E8C45EA17B5355B4FE785F3EAEB965554DD2EC67A1FF8F45371F9F4AE3F01710D508BEF87ABB9B0D94880F1FB3C5668B9FAB4F1C89F1F51B451D041B1F919162016A1DE2BD1706587F34E4E5C2D4E7C89B71F996FC051DC415622A58A51E1C9810796EB7DDFD134984A2E7234A3C3438C8ADC14CC49331EBFC25748C6805AC81833D93DEE7503C29C1275D31F17479699E3B5A3060B5BC06B63647D8B7968AE5F369D190411508BB8CF55407E7F8EF70096303611730CF6B2248B663C4E15591CB43CA2B6731EFC63EC21486DD064AC9232BDD48A5A6A1969BCF0E281E834C6C8EC0C5334E6BAB1A4332EBEB638F40BAF7E9FF9213E7E064ED8D3D4D161A4EE55EF3F25215235FE5B914AE32531CE2B4DFEE861F7F15A71F2705DE5B26C248C2AB707173B9704CAA7B8AC56620C29359B940E0925915FB0D35874EF13998FCCC217C935520BF39540F31A9C74291DAE0F6C0BFF9C54544D4815C6E4EBD8DE601AE1FB8F0FAF820DFE3AA4B551B3EE35C166DC4A6A0B4420C0049F204925352C5CC0AD8582C7ADF1F7086BDFBEDF0A99947A42D02D1F0C4418CA28632F94BC0E65437326C4A854561CB3C31ED4241D720");
//        System.out.println("gotc: " + Hex.toHexString(commitBytes));
//        System.out.println("expc: " + Hex.toHexString(expcommitBytes));
//        assertTrue(Arrays.areEqual(commitBytes, expcommitBytes));

//        System.out.println("gotw: " + Hex.toHexString(welcomeBytes));
//        System.out.println("expw: " + Hex.toHexString(expwelcomeBytes));
//        assertTrue(Arrays.areEqual(welcomeBytes, expwelcomeBytes));

        // pending commit = commitBytes
        // pending groupid = gwp1.group id

         // Executing function: handlePendingCommit
        /**
         * Alice handles pending commit
         * < state id
         *
         * > new state id
         * > epoch authenticator
         */
        // gets group0 and returns gwm1.group
        byte[] epochAuthenticator = gwm1.group.getEpochAuthenticator();

         // Executing function: joinGroup
        /**
         * Bob joins group
         * < transaction id
         * < welcome
         * < encrypt
         * < identity
         *
         * > new state id
         * > epoch authenticator
         */
        MLSMessage welcomeMsg = (MLSMessage) MLSInputStream.decode(welcomeBytes, MLSMessage.class);
        Welcome welcome = welcomeMsg.welcome;
        TreeKEMPublicKey ratchetTree = null;
        Group group2 = new Group(
                suite.getHPKE().serializePrivateKey(kpSecrets.initKeyPair.getPrivate()),
                kpSecrets.encryptionKeyPair,
                suite.serializeSignaturePrivateKey(kpSecrets.signatureKeyPair.getPrivate()),
                kpSecrets.keyPackage,
                welcome,
                ratchetTree,
                new HashMap<>(),//TODO WHERE IS JOIN.EXTERNALPSKS POPULATED
                new HashMap<>()
        );
        byte[] bob_join_epochAuthenticator = group2.getEpochAuthenticator();
        // state id = group2 id

         // Executing function: groupContextExtensionsProposal
        /**
         * Alice GroupContextExtensions Proposal
         * < state id
         * < extensions
         *    < extension (type + data)
         *    < extension (type + data)
         *
         * > proposal
         */
        // 2 extensions
        List<Extension> extList = new ArrayList<>();
        extList.add(new Extension(3, Hex.decode("000000")));
        extList.add(new Extension(5, Hex.decode("00")));

        MLSMessage gceMessage = gwm1.group.groupContextExtensions(extList,
                new Group.MessageOptions(encrypt, new byte[0], 0)
        );


        // Executing function: commit
        /**
         * Alice commit
         * < state id
         *
         * > commit
         * > welcome
         */
        // state id should be the output of the handle pending commit
        // state id = gwm1.group

        // 1 by ref
        byte[] byReference = MLSOutputStream.encode(gceMessage);
        Group shouldBeNull = gwm1.group.handle(byReference, null);
        if (shouldBeNull != null)
        {
            throw new Exception("Commit included among proposals");
        }

        // no by val
        byValue = new ArrayList<>();

        forcePath = false;
        inlineTree = true;

        leafSecret = Hex.decode("7f664136d8d20e300f864453d472a06bb574c37a4c48685424fe9a61f01b7aee");
        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm3 = gwm1.group.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes2 = MLSOutputStream.encode(gwm3.message);
        gwm3.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes2 = MLSOutputStream.encode(gwm3.message);

//        byte[] expcommitBytes2 = Hex.decode("000100012431373236643162322D353562322D346437332D386462392D3634623830393032333965640000000000000001010000000000030001209D2A04A8DAF49AE80B71DDF009AD10D83CE3969383BEB6021B80B0C2E5657534207B0EEC9A4072F87E8DC4EE0D5BE14A6FCD04BDA8FA5AE33D19570E68C73B2FB6000105616C6963650200010C000100020003000400050006000004000100020320C537F07F331F25552E8B7CB7A2CA0BC2FC4AE5FB4BEF7AC6E47557E04CADB221004040D58DFAA4A663728AE119C3C9EF478F4DDA823D24F9A73573BA2DBD4F79DA7C4063C0D57058B55BDFDD5CE1F45BF3335603730D0517A291E06543BA8941638C05407520A09D6DE8C2387458A688F473169AA709F1613ABB2468DEB142B9C7A036F49E0A405220EF374EE7EACC2437045FCB54A45AE3B3D16CD3E96B555A136DC0F95223ED7C6E308D03A83B79120FFC97C4F5B2FCE261FAEAAC1659A9250E02D4F78D00A7E44AA7631BD669B223CC036970213F8ABD2B4640409ECC54ECEB6C4773D928A652F5C535B821644AC5BDD346712E367AF3614E5D325DB2BB6F65DC65C25FDAC8CEE3F0635D8A63E384E07541CFB5B3A0DDAD92A00C20F0606E9D360BDA8CD72FB3BF4684AC85B327C50449EA5AA4539B65033C81C7752056C809DD1278F36C9F40B6109FFCD2B805EE5702995561C4D9D936CAC6626376");
//        System.out.println("gotc2: " + Hex.toHexString(commitBytes2));
//        System.out.println("expc2: " + Hex.toHexString(expcommitBytes2));
//        assertTrue(Arrays.areEqual(commitBytes2, expcommitBytes2));

        // pending commit = commitBytes2
        // pending groupid = gwp3.group id

         // Executing function: handlePendingCommit
        /**
         * Alice handles pending commit
         * < state id
         *
         * > new state id
         * > epoch authenticator
         */
        // gets gwm1.group and returns gwm3.group
        byte[] epochAuthenticator2 = gwm3.group.getEpochAuthenticator();

         // Executing function: handleCommit
        /**
         * Bob handle commit
         * < state id
         * < proposal
         * < commit
         *
         * > new state id
         * > epoch authenticator
         */
        shouldBeNull = group2.handle(byReference, null);
        if (shouldBeNull != null)
        {
            throw new Exception("Commit included among proposals");
        }

        Group group4 = group2.handle(commitBytes2, null);
        if (group4 == null)
        {
            throw new Exception("Commit failed to produce a new state");
        }
        byte[] epochAuthenticator4 = group4.getEpochAuthenticator();

        // Executing function: groupContextExtensionsProposal
        /**
         * Bob GroupContextExtensions Proposal
         * < state id
         *
         * > proposal
         */
        // 2 extensions
        extList = new ArrayList<>();
        MLSMessage gceMessage2 = group4.groupContextExtensions(extList,
                new Group.MessageOptions(encrypt, new byte[0], 0)
        );

         // Executing function: commit
        /**
         * Alice commit
         * < state id
         *
         * > commit
         * > welcome
         */
        // state id should be the output of the handle pending commit
        // state id = gwm1.group

        // 1 by ref
        byReference = MLSOutputStream.encode(gceMessage2);
        shouldBeNull = gwm3.group.handle(byReference, null);
        if (shouldBeNull != null)
        {
            throw new Exception("Commit included among proposals");
        }
        // no by val
        byValue = new ArrayList<>();

        forcePath = false;
        inlineTree = true;

        leafSecret = Hex.decode("7f664136d8d20e300f864453d472a06bb574c37a4c48685424fe9a61f01b7aee");
//        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm5 = gwm3.group.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes3 = MLSOutputStream.encode(gwm3.message);
        gwm3.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes3 = MLSOutputStream.encode(gwm3.message);

//        byte[] expcommitBytes2 = Hex.decode("000100012431373236643162322D353562322D346437332D386462392D3634623830393032333965640000000000000001010000000000030001209D2A04A8DAF49AE80B71DDF009AD10D83CE3969383BEB6021B80B0C2E5657534207B0EEC9A4072F87E8DC4EE0D5BE14A6FCD04BDA8FA5AE33D19570E68C73B2FB6000105616C6963650200010C000100020003000400050006000004000100020320C537F07F331F25552E8B7CB7A2CA0BC2FC4AE5FB4BEF7AC6E47557E04CADB221004040D58DFAA4A663728AE119C3C9EF478F4DDA823D24F9A73573BA2DBD4F79DA7C4063C0D57058B55BDFDD5CE1F45BF3335603730D0517A291E06543BA8941638C05407520A09D6DE8C2387458A688F473169AA709F1613ABB2468DEB142B9C7A036F49E0A405220EF374EE7EACC2437045FCB54A45AE3B3D16CD3E96B555A136DC0F95223ED7C6E308D03A83B79120FFC97C4F5B2FCE261FAEAAC1659A9250E02D4F78D00A7E44AA7631BD669B223CC036970213F8ABD2B4640409ECC54ECEB6C4773D928A652F5C535B821644AC5BDD346712E367AF3614E5D325DB2BB6F65DC65C25FDAC8CEE3F0635D8A63E384E07541CFB5B3A0DDAD92A00C20F0606E9D360BDA8CD72FB3BF4684AC85B327C50449EA5AA4539B65033C81C7752056C809DD1278F36C9F40B6109FFCD2B805EE5702995561C4D9D936CAC6626376");
//        System.out.println("gotc2: " + Hex.toHexString(commitBytes2));
//        System.out.println("expc2: " + Hex.toHexString(expcommitBytes2));
//        assertTrue(Arrays.areEqual(commitBytes2, expcommitBytes2));

        // pending commit = commitBytes3
        // pending groupid = gwp5.group id


    }
    public void testCommitUpdate()
            throws Exception
    {
        // Executing function: createGroup
        /**
         * Alice creates a group
         * < group id
         * < cipher suite
         * < encrypt
         * < identity
         *
         * > state id
         */
        byte[] groupIDBytes = Hex.decode("64316530373330652d666536652d343735642d613066342d666362626635343863383330");
        CipherSuite suite = new CipherSuite((short) 1);
        byte[] identity = Hex.decode("616C696365");
        boolean encrypt = false;

//        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        byte[] sig_priv = Hex.decode("5efa9f0a244067ea8dc5dd0504779af2e3a1ed2cb1374782cc2cf440dd56fda5");
        byte[] leaf_priv = Hex.decode("edca7b8c2d3e8904fab96cae6b86f18f26500a28d4c0f56cca322076cd7b1358");
        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().deserializePrivateKey(leaf_priv, null);
        AsymmetricCipherKeyPair sigKeyPair = suite.deserializeSignaturePrivateKey(sig_priv);

        Credential cred = Credential.forBasic(identity);

        LeafNode leafnode0 = new LeafNode(
                suite,
                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
                cred,
                new Capabilities(),
                new LifeTime(0, -1),
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        leafnode0.signature = Hex.decode("1909da4db9c225fcfec102853c1187dd271dd53721191fe92c35fdd2cd254f74ed1ffffd0aafabbef2f0c8d273fbd2c822a88782ba4030de85d1e55ff5b60804");

        Group group0 = new Group(
                groupIDBytes,
                suite,
                leafKeyPair,
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate()),
                leafnode0,
                new ArrayList<>()
        );

        // Executing function: createKeyPackage
        /**
         * Bob creates a KeyPackage
         * < cipher suite
         * < identity
         *
         * > transaction id
         * > key package
         * > init priv
         * > encryption priv
         * > signature priv
         */
        byte[] bobIdentity = Hex.decode("626F62");
        KeyPackageWithSecrets kpSecrets = newKeyPackage(suite, bobIdentity,
                Hex.decode("f88aa80c5242dd864e0e4d31a8cbd9f957fda27715a217463bf2aef2d66f191a"),
                Hex.decode("dfaeaff781a6c6585bb50b5ef0ddb8c34436f9c22c80f0b0efd892efbcc77a06"),
                Hex.decode("f4ac289eb383bdc2da78be3c19072959c3081c93a8847e090c1b1233d27e5e95"),
                Hex.decode("4fc9349c51dd30aed878b3f60cfb78a39d6672bd34a39d5f96a97c1e538042fb4be87adc682289c39ad12ddd1611bfdf0de636ecab752c821185a3a56c1bdd0e"),
                Hex.decode("838483765947df946955b8a53e72fe880469cc3012b994a22d3b1573c6d1de3d3d64ca0c84530a23da0bd9f198555d0ce1b71efd29b5fbc3af976c4582fa3b0b")
                );
        KeyPackage keyPackage = kpSecrets.keyPackage;
        byte[] keyPackageBytes = MLSOutputStream.encode(MLSMessage.keyPackage(keyPackage));
        byte[] gotKeyPackageBytes = Hex.decode("0001000500010001200A81114311D1EC8A6B1587FC7BCE6902D67AFA8FFCA7C44FC08C943320355A5A201EF7A4687D85BA983002D6239F793F590E245286964ED520F9C90380A671230720E35F42BFDD1291B194663E9B9C476679EA8A42E5D58407784048BD051878AD38000103626F620200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF0040404FC9349C51DD30AED878B3F60CFB78A39D6672BD34A39D5F96A97C1E538042FB4BE87ADC682289C39AD12DDD1611BFDF0DE636ECAB752C821185A3A56C1BDD0E004040838483765947DF946955B8A53E72FE880469CC3012B994A22D3B1573C6D1DE3D3D64CA0C84530A23DA0BD9F198555D0CE1B71EFD29B5FBC3AF976C4582FA3B0B");
        assertTrue(Arrays.areEqual(keyPackageBytes, gotKeyPackageBytes));

        // Executing function: commit
        /**
         * Alice commits
         * < state id
         * < by_value
         *      < proposal type + key package
         *
         * > commit
         * > welcome
         */
        // No by ref
        // 1 by value
        List<Proposal> byValue = new ArrayList<>();
        MLSMessage kp = (MLSMessage) MLSInputStream.decode(keyPackageBytes, MLSMessage.class);
        Proposal add = Proposal.add(kp.keyPackage);
        byValue.add(add);

        boolean forcePath = false;
        boolean inlineTree = true;

//        SecureRandom random = new SecureRandom();
        byte[] leafSecret = Hex.decode("11db9cac16289d1d69c4eac3afd0bab1a8d46c83b4d6718bcc55306e412efa49");
//        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm1 = group0.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes = MLSOutputStream.encode(gwm1.message);
        gwm1.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes = MLSOutputStream.encode(gwm1.message);

        byte[] expcommitBytes = Hex.decode("000100012464316530373330652D666536652D343735642D613066342D666362626635343863383330000000000000000001000000000003411E01000100010001200A81114311D1EC8A6B1587FC7BCE6902D67AFA8FFCA7C44FC08C943320355A5A201EF7A4687D85BA983002D6239F793F590E245286964ED520F9C90380A671230720E35F42BFDD1291B194663E9B9C476679EA8A42E5D58407784048BD051878AD38000103626F620200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF0040404FC9349C51DD30AED878B3F60CFB78A39D6672BD34A39D5F96A97C1E538042FB4BE87ADC682289C39AD12DDD1611BFDF0DE636ECAB752C821185A3A56C1BDD0E004040838483765947DF946955B8A53E72FE880469CC3012B994A22D3B1573C6D1DE3D3D64CA0C84530A23DA0BD9F198555D0CE1B71EFD29B5FBC3AF976C4582FA3B0B00404009C308E66CA2CE01DDFBCECAA473A6163F78019EA6E3039DED5F1A27F41EA20EACCA32CEF9FE007B832CC6DFD058F030D77C80CF3ED5A4A9B41DB47FEE5E05082082D920D942694561990729DA804A0025789E54F8589CBFFB25CF0DD02C1D92E7203FBFF338DD91BC2B267AAE2BC161D0D4AC7709914EC8DF9FCC83ABE53C4E0B77");
        byte[] expwelcomeBytes = Hex.decode("000100030001407620F8B63D34A753D3FB79086229D3B8D7116E24E2E46B8EEAB3D2754622B8A9412B206DC8E6518F07A8FF73C37006264393E780AD3BAE0271ADAD4E7AFEACA9D0D87B336B512C0C59EC6B3F4D03608DE8F93B08C7AFE4CBE95E989E4D81CC81379E34BD2EADBC0CD4F7EF5D38E9E76F8A0666D18803D442609E42F473E631FB47232A7ECA5F822D1D72A65C4C03CB40FA738AEAE28BB04F17613F8EF6458A9F989E1CE3ACEBC9C42104595A08352C962437760802B42B6EC710B4AE8C3A615FBB9540D727D643016A0E36D85DFF813DE1E5CCECF44E28CCD5ADF5089C3AE4ADE0EF0F095572B815D2C28C92A40BD842B6804005DAD95CFC4A0092BB44DB559490719BEE6479C3039A81EF37D580E40AAEF04340D77ED1C91CC76D46B82A379F691B735399DB9F8FE4E8C45EA17B5355B4FE785F3EAEB965554DD2EC67A1FF8F45371F9F4AE3F01710D508BEF87ABB9B0D94880F1FB3C5668B9FAB4F1C89F1F51B451D041B1F919162016A1DE2BD1706587F34E4E5C2D4E7C89B71F996FC051DC415622A58A51E1C9810796EB7DDFD134984A2E7234A3C3438C8ADC14CC49331EBFC25748C6805AC81833D93DEE7503C29C1275D31F17479699E3B5A3060B5BC06B63647D8B7968AE5F369D190411508BB8CF55407E7F8EF70096303611730CF6B2248B663C4E15591CB43CA2B6731EFC63EC21486DD064AC9232BDD48A5A6A1969BCF0E281E834C6C8EC0C5334E6BAB1A4332EBEB638F40BAF7E9FF9213E7E064ED8D3D4D161A4EE55EF3F25215235FE5B914AE32531CE2B4DFEE861F7F15A71F2705DE5B26C248C2AB707173B9704CAA7B8AC56620C29359B940E0925915FB0D35874EF13998FCCC217C935520BF39540F31A9C74291DAE0F6C0BFF9C54544D4815C6E4EBD8DE601AE1FB8F0FAF820DFE3AA4B551B3EE35C166DC4A6A0B4420C0049F204925352C5CC0AD8582C7ADF1F7086BDFBEDF0A99947A42D02D1F0C4418CA28632F94BC0E65437326C4A854561CB3C31ED4241D720");
//        System.out.println("gotc: " + Hex.toHexString(commitBytes));
//        System.out.println("expc: " + Hex.toHexString(expcommitBytes));
        assertTrue(Arrays.areEqual(commitBytes, expcommitBytes));

        System.out.println("gotw: " + Hex.toHexString(welcomeBytes));
        System.out.println("expw: " + Hex.toHexString(expwelcomeBytes));
        assertTrue(Arrays.areEqual(welcomeBytes, expwelcomeBytes));

        // pending commit = commitBytes
        // pending groupid = gwp1.group id

        // Executing function: handlePendingCommit
        /**
         * Alice handles pending commit
         * < state id
         *
         * > new state id
         * > epoch authenticator
         */
        // gets group0 and returns gwm1.group
        byte[] epochAuthenticator = gwm1.group.getEpochAuthenticator();

        // Executing function: joinGroup
        /**
         * Bob joins group
         * < transaction id
         * < welcome
         * < encrypt
         * < identity
         *
         * > new state id
         * > epoch authenticator
         */
        MLSMessage welcomeMsg = (MLSMessage) MLSInputStream.decode(welcomeBytes, MLSMessage.class);
        Welcome welcome = welcomeMsg.welcome;
        TreeKEMPublicKey ratchetTree = null;
        Group group2 = new Group(
                suite.getHPKE().serializePrivateKey(kpSecrets.initKeyPair.getPrivate()),
                kpSecrets.encryptionKeyPair,
                suite.serializeSignaturePrivateKey(kpSecrets.signatureKeyPair.getPrivate()),
                kpSecrets.keyPackage,
                welcome,
                ratchetTree,
                new HashMap<>(),//TODO WHERE IS JOIN.EXTERNALPSKS POPULATED
                new HashMap<>()
        );
        byte[] bob_join_epochAuthenticator = group2.getEpochAuthenticator();
        // state id = group2 id

        // Executing function: updateProposal
        /**
         * Bob update Proposal
         * < state id
         *
         * > proposal
         */
        // state id = group2
//        AsymmetricCipherKeyPair leafKeyPair1 = group2.suite.generateSignatureKeyPair();
        byte[] priv_leaf_update = Hex.decode("c49c766dcc8dd12e66c6ada7bc599898b5e3926bdef9bc641c3a6526b5b7a893");
        AsymmetricCipherKeyPair leafKeyPair1 = group2.suite.getHPKE().deserializePrivateKey(priv_leaf_update, null);
        Proposal update = group2.updateProposal(leafKeyPair1, new Group.LeafNodeOptions());
        MLSMessage proposalMessage = group2.update(update, new Group.MessageOptions(encrypt, new byte[0], 0));
        byte[] proposalBytes = MLSOutputStream.encode(proposalMessage);
        byte[] expProposalBytes = Hex.decode("000100012464316530373330652D666536652D343735642D613066342D6663626266353438633833300000000000000001010000000100020002204E17C5C39A9667CCB1CAE0E2CAC7F36D75D30B1B9B90370658DF5002B65D603020E35F42BFDD1291B194663E9B9C476679EA8A42E5D58407784048BD051878AD38000103626F620200010C000100020003000400050006000004000100020200404033104D6408BDBA1D7D97A4609C823746F575AEAEDCC49F56F650D8ACC63DDA4AB1DB5512162CBBE7E3BB9EDD6974B13198D94A5046196972E43D63F2BE62780540405F594FF87A152535F9F2FC61779E499F477AD92BE007D315342AF4ED774F420C2219D53257F2B6400DCF5410956A8620D8BBB8207BEBA6E3C19FB8B89EFE2F0A202075E6C44C54F67C55104BE7D90D2C5836B14222F2F9C2985768E0C4008CD541");
        System.out.println("gotp: " + Hex.toHexString(proposalBytes));
        System.out.println("expp: " + Hex.toHexString(expProposalBytes));

        assertTrue(Arrays.areEqual(proposalBytes, expProposalBytes));

        // Executing function: commit
        /**
         * Alice commit
         * < state id
         *
         * > commit
         * > welcome
         */
        // state id should be the output of the handle pending commit
        // state id = gwm1.group

        // 1 by ref
        byte[] byReference = MLSOutputStream.encode(proposalMessage);
        Group shouldBeNull = gwm1.group.handle(byReference, null);
        if (shouldBeNull != null)
        {
            throw new Exception("Commit included among proposals");
        }

        // no by val
        byValue = new ArrayList<>();

        forcePath = false;
        inlineTree = true;

        leafSecret = Hex.decode("7f664136d8d20e300f864453d472a06bb574c37a4c48685424fe9a61f01b7aee");
//        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm3 = gwm1.group.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes2 = MLSOutputStream.encode(gwm3.message);
        gwm3.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes2 = MLSOutputStream.encode(gwm3.message);

//        byte[] expcommitBytes2 = Hex.decode("000100012431373236643162322D353562322D346437332D386462392D3634623830393032333965640000000000000001010000000000030001209D2A04A8DAF49AE80B71DDF009AD10D83CE3969383BEB6021B80B0C2E5657534207B0EEC9A4072F87E8DC4EE0D5BE14A6FCD04BDA8FA5AE33D19570E68C73B2FB6000105616C6963650200010C000100020003000400050006000004000100020320C537F07F331F25552E8B7CB7A2CA0BC2FC4AE5FB4BEF7AC6E47557E04CADB221004040D58DFAA4A663728AE119C3C9EF478F4DDA823D24F9A73573BA2DBD4F79DA7C4063C0D57058B55BDFDD5CE1F45BF3335603730D0517A291E06543BA8941638C05407520A09D6DE8C2387458A688F473169AA709F1613ABB2468DEB142B9C7A036F49E0A405220EF374EE7EACC2437045FCB54A45AE3B3D16CD3E96B555A136DC0F95223ED7C6E308D03A83B79120FFC97C4F5B2FCE261FAEAAC1659A9250E02D4F78D00A7E44AA7631BD669B223CC036970213F8ABD2B4640409ECC54ECEB6C4773D928A652F5C535B821644AC5BDD346712E367AF3614E5D325DB2BB6F65DC65C25FDAC8CEE3F0635D8A63E384E07541CFB5B3A0DDAD92A00C20F0606E9D360BDA8CD72FB3BF4684AC85B327C50449EA5AA4539B65033C81C7752056C809DD1278F36C9F40B6109FFCD2B805EE5702995561C4D9D936CAC6626376");
//        System.out.println("gotc2: " + Hex.toHexString(commitBytes2));
//        System.out.println("expc2: " + Hex.toHexString(expcommitBytes2));
//        assertTrue(Arrays.areEqual(commitBytes2, expcommitBytes2));

        // pending commit = commitBytes2
        // pending groupid = gwp3.group id

        // Executing function: handlePendingCommit
        /**
         * Alice handles pending commit
         * < state id
         *
         * > new state id
         * > epoch authenticator
         */
        // gets gwm1.group and returns gwm3.group
        byte[] epochAuthenticator2 = gwm3.group.getEpochAuthenticator();

        // Executing function: handleCommit
        /**
         * Bob handle commit
         * < state id
         * < proposal
         * < commit
         *
         * > new state id
         * > epoch authenticator
         */
        // state id = group2
        // proposal = proposalMessage/ByReference
        // commit = commitBytes2
        shouldBeNull = group2.handle(byReference, null);
        if (shouldBeNull != null)
        {
            throw new Exception("Commit included among proposals");
        }
        Group group4 = group2.handle(commitBytes2, null);
        if (group4 == null)
        {
            throw new Exception("Commit failed to produce a new state");
        }
    }

    public void testCommitProblem()
            throws Exception
    {

        /**
         * Alice creates a group
         * < group id
         * < cipher suite
         * < encrypt
         * < identity
         *
         * > state id
         */
        byte[] groupIDBytes = Hex.decode("31373236643162322d353562322d346437332d386462392d363462383039303233396564");
        CipherSuite suite = new CipherSuite((short) 1);
        byte[] identity = Hex.decode("616C696365");
        boolean encrypt = false;

//        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        byte[] sig_priv = Hex.decode("f9b67c377aa0bfe699cd4ca3a097e5e32225913341cce98b5acc6ce129185f6e");
        byte[] leaf_priv = Hex.decode("be8d49ef017d4a84a93a373300f8bdc9e01afbc5326060838c2d80d110fff49f");
        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().deserializePrivateKey(leaf_priv, null);
        AsymmetricCipherKeyPair sigKeyPair = suite.deserializeSignaturePrivateKey(sig_priv);

        Credential cred = Credential.forBasic(identity);

        LeafNode alice_create_group_leafNode = new LeafNode(
                suite,
                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
                cred,
                new Capabilities(),
                new LifeTime(0, -1),
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        alice_create_group_leafNode.signature = Hex.decode("9f330281ea5d64844509e8c1f2056418a2bf6635c30f427eac3af9b9f70b4cffc51f7605a9abd6dba89db09fe6bf74bd9a45c366c5fb810f5b8a9d19c6c4300d");
        Group first_group = new Group(
                groupIDBytes,
                suite,
                leafKeyPair,
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate()),
                alice_create_group_leafNode,
//                leafNode.copy(leafNode.encryption_key),
                new ArrayList<>()
        );
        //

        /**
         * Bob creates a KeyPackage
         * < cipher suite
         * < identity
         *
         * > transaction id
         * > key package
         * > init priv
         * > encryption priv
         * > signature priv
         */
        byte[] bobIdentity = Hex.decode("626F62");
        KeyPackageWithSecrets kpSecrets = newKeyPackage(suite, bobIdentity);
        KeyPackage keyPackage = kpSecrets.keyPackage;
        byte[] keyPackageBytes = MLSOutputStream.encode(MLSMessage.keyPackage(keyPackage));
        byte[] gotKeyPackageBytes = Hex.decode("000100050001000120594C6BBFA77366BBE0DCA135E07B460073F926798AC7535E31BCD0B1611D68542093CBFA93FE70AED3A90BC0B4F921E6020AB266B9B66401F1DB25AD3A60FC5C2E202D8B90C208B130741AEA15F843B24E594B96919303DAFACDA5FB71CC83A68928000103626F620200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF00404010213700709B400423B007AA475852B410DB89E0FB407A8B570CC0312BF4000415B868B94701A80432563AF0446D332FD848ED6A5A39C8A05A27A99B2B927401004040760FB58676CC2408DBA1FCB4D3BD819E4FAE866C59ED821C247BC052837AF58E79383E95950107126394A1CDDF4E5116DD139F0FE2942C6FB32E37AD6C087604");


        assertTrue(Arrays.areEqual(keyPackageBytes, gotKeyPackageBytes));
        //

        /**
         * Alice commits
         * < state id
         * < by_value
         *      < proposal type + key package
         *
         * > commit
         * > welcome
         */
        // No by ref
        // 1 by value
        List<Proposal> byValue = new ArrayList<>();
        MLSMessage kp = (MLSMessage) MLSInputStream.decode(gotKeyPackageBytes, MLSMessage.class);
        Proposal add = Proposal.add(kp.keyPackage);
        byValue.add(add);

        boolean forcePath = false;
        boolean inlineTree = true;

//        SecureRandom random = new SecureRandom();
        byte[] leafSecret = Hex.decode("a6d66d90e9ce4b98dd42564bab2068218c24a2016ff84742f4d6c57b573a39ee");
//        random.nextBytes(leafSecret);
        Group.GroupWithMessage gwm = first_group.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes = MLSOutputStream.encode(gwm.message);
        byte[] expcommitBytes = Hex.decode("000100012431373236643162322D353562322D346437332D386462392D363462383039303233396564000000000000000001000000000003411E0100010001000120594C6BBFA77366BBE0DCA135E07B460073F926798AC7535E31BCD0B1611D68542093CBFA93FE70AED3A90BC0B4F921E6020AB266B9B66401F1DB25AD3A60FC5C2E202D8B90C208B130741AEA15F843B24E594B96919303DAFACDA5FB71CC83A68928000103626F620200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF00404010213700709B400423B007AA475852B410DB89E0FB407A8B570CC0312BF4000415B868B94701A80432563AF0446D332FD848ED6A5A39C8A05A27A99B2B927401004040760FB58676CC2408DBA1FCB4D3BD819E4FAE866C59ED821C247BC052837AF58E79383E95950107126394A1CDDF4E5116DD139F0FE2942C6FB32E37AD6C087604004040357B383B9618C84028F0741A74D6CA3FA66C29B65EB4C76101DB5D171B977DED92976B927079AC4B06A7F551C3AF63844D96B94AABBB1184E45035A349E7090020AD8B3C99E9F6F7CA5B16B5B241FEE8D7B67B5FBD432FF0D06F085F44C1A55F5120785843EEAB3F9FD62250CEC84610648A588BC298E9DB954DC4263AFF19AB15A2");
        byte[] expwelcomeBytes = Hex.decode("00010003000140762060481A1A544908A6C5FC0F259C438C73A89D3D2975E607B41FBC169424D3C27E20E75C9FE41D31FAB8649F3C52D5E7F8B9AA4399BEBB3E379F7EF96B4B09C0804A33B91D6E7D5B290A749FD9AC8575905778518D229FB5328D5D7B54DFCE69E69281D957C2382D91E8BEEDA31EE2B64042F445B4A3426091AE6569D9FE441B05166F365234AB5FDEB08801F64C9A2FBF31ADA2CDFE387888009E148860C5AEBD4160C44EB995411E06E7FCEF4193D9197B015DBC0631069155A772953DFD49052B2AD90239FE1D07E5FEAF511D2F8752436B0ED2C1BFF023EEC4C7343F380B9042AE7D918063EE72F037BFEBEA989F322D71F3B878789574693E880541F17623101AF7730468F5CB3242B4257491062FA43E529F5645137F0C8B76DC5311BFDBA60773847EC6ACC8EC1B18A28B5A0DD2B1F6968929494B1A408DF90BCF26C954DD4FAFDC0F56EF36E9C61AE21759036B94459F2534A5F1B1C2A526011BAFEC0329A9A8437069DC177CE2FC9008EC893AAC3833CC5DF47BC614CF9B07F4F06F102827E871DDB79DA0FF59735EEA64F6547233ACD6E93D30617E9861527DAAFCEBB3568F0521504175DE23D1A51C810BE6C6AA26E81103FCCDE4F98486B9C027D240020A593657BA885C5FCDD822B1E01F1972AFCF08D89139B3614A4FCBD58F00B323F4929B1F7836153A88B3C04E3CD33CCD522C590CC5AEE5127DB2B527CA48C9859D9C4E261E02FF361D472FB1C32ED60346DB10774C631C783393E4B50FEEB62B8F5857D66BBA1AFAD370C7CE114CBBE78298A48E9362BD86AF0E966F13115F0757616DD82181F3A48513EC0D1FE262CD5146E24B9C50AB2C56F324E4FD95E51AA1FD5D6F3BF10341CB1F6E1D4A5319B07C5B44E63175FA64E67197758216EC43D388DD8903BDDE7556F02245AF4F59F33D6A09385D2B3C76712027044D8B19BC576EDEDD7634E50969F2C2E5EDD1BA4CE077F2617EC8AD55FC14D9A367D2E655E7508B6BB807F0809E8ACBB1DFFE0C2484EAD01C9D");

//        System.out.println("gotc: " + Hex.toHexString(commitBytes));
//        System.out.println("expc: " + Hex.toHexString(expcommitBytes));
        assertTrue(Arrays.areEqual(commitBytes, expcommitBytes));

        gwm.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes = MLSOutputStream.encode(gwm.message);

        System.out.println("gotw: " + Hex.toHexString(welcomeBytes));
        System.out.println("expw: " + Hex.toHexString(expwelcomeBytes));
        assertTrue(Arrays.areEqual(welcomeBytes, expwelcomeBytes));

        // pending commit = commitBytes
        // pending groupid = gwp.group id

        /**
         * Alice handles pending commit
         * < state id
         *
         * > new state id
         * > epoch authenticator
         */
        // gets alice_create_group and returns gwm.group
        byte[] epochAuthenticator = gwm.group.getEpochAuthenticator();

        /**
         * Bob joins group
         * < transaction id
         * < welcome
         * < encrypt
         * < identity
         *
         * > new state id
         * > epoch authenticator
         */
        MLSMessage welcomeMsg = (MLSMessage) MLSInputStream.decode(expwelcomeBytes, MLSMessage.class);
        Welcome welcome = welcomeMsg.welcome;
        TreeKEMPublicKey ratchetTree = null;
        Group bob_join_group = new Group(
                suite.getHPKE().serializePrivateKey(kpSecrets.initKeyPair.getPrivate()),
                kpSecrets.encryptionKeyPair,
                suite.serializeSignaturePrivateKey(kpSecrets.signatureKeyPair.getPrivate()),
                kpSecrets.keyPackage,
                welcome,
                ratchetTree,
                new HashMap<>(),//TODO WHERE IS JOIN.EXTERNALPSKS POPULATED
                new HashMap<>()
        );
        byte[] bob_join_epochAuthenticator = bob_join_group.getEpochAuthenticator();
        // state id = bob_join_group id

        /**
         * Alice commit
         * < state id
         *
         * > commit
         * > welcome
         */
        // state id should be the output of the handle pending commit
        // state id = gwm.group

        // no by ref
        // no by val
        byValue = new ArrayList<>();

        forcePath = false;
        inlineTree = true;
        leafSecret = Hex.decode("1221136af8dc679261310dd937a9ed403a208698f97911b9c4244a9ef407704e");
//        random.nextBytes(leafSecret);
        Group.GroupWithMessage gwm2 = gwm.group.commit(
                new Secret(leafSecret),
                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
                new Group.MessageOptions(encrypt, new byte[0], 0),
                new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes2 = MLSOutputStream.encode(gwm2.message);
        gwm2.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes2 = MLSOutputStream.encode(gwm2.message);

        byte[] expcommitBytes2 = Hex.decode("000100012431373236643162322D353562322D346437332D386462392D3634623830393032333965640000000000000001010000000000030001209D2A04A8DAF49AE80B71DDF009AD10D83CE3969383BEB6021B80B0C2E5657534207B0EEC9A4072F87E8DC4EE0D5BE14A6FCD04BDA8FA5AE33D19570E68C73B2FB6000105616C6963650200010C000100020003000400050006000004000100020320C537F07F331F25552E8B7CB7A2CA0BC2FC4AE5FB4BEF7AC6E47557E04CADB221004040D58DFAA4A663728AE119C3C9EF478F4DDA823D24F9A73573BA2DBD4F79DA7C4063C0D57058B55BDFDD5CE1F45BF3335603730D0517A291E06543BA8941638C05407520A09D6DE8C2387458A688F473169AA709F1613ABB2468DEB142B9C7A036F49E0A405220EF374EE7EACC2437045FCB54A45AE3B3D16CD3E96B555A136DC0F95223ED7C6E308D03A83B79120FFC97C4F5B2FCE261FAEAAC1659A9250E02D4F78D00A7E44AA7631BD669B223CC036970213F8ABD2B4640409ECC54ECEB6C4773D928A652F5C535B821644AC5BDD346712E367AF3614E5D325DB2BB6F65DC65C25FDAC8CEE3F0635D8A63E384E07541CFB5B3A0DDAD92A00C20F0606E9D360BDA8CD72FB3BF4684AC85B327C50449EA5AA4539B65033C81C7752056C809DD1278F36C9F40B6109FFCD2B805EE5702995561C4D9D936CAC6626376");
        System.out.println("gotc2: " + Hex.toHexString(commitBytes2));
        System.out.println("expc2: " + Hex.toHexString(expcommitBytes2));
        assertTrue(Arrays.areEqual(commitBytes2, expcommitBytes2));

        // pending commit = commitBytes2
        // pending groupid = gwp2.group id

        /**
         * Alice handles pending commit
         * < state id
         *
         * > new state id
         * > epoch authenticator
         */
        // gets gwm.group and returns gwm2.group
        byte[] epochAuthenticator2 = gwm2.group.getEpochAuthenticator();

        /**
         * Bob handle commit
         * < state id
         * < commit
         *
         * > new state id
         * > epoch authenticator
         */
        // no proposals
//        byte[] testcommit = Hex.decode("000100012430353935633461312D616264622D343230662D383165332D373061663963333365393761000000000000000101000000000003000120537C08D43C5EC381D6E3E11B9D29BF76552A35255BF258B2407BD7AB48EFC97020A447541D323F639DC4C4CD9533FBA809155930F47EFB828DC05601A3B0B76FED000105616C69636502000112000100022A2A0003000400058A8A00064A4A044A4A7A7A02CACA06000100025A5A03204DC13B9DAE91148AC33E2E8201126266D0862CA987FC904368265D22A6EF0EC0037A7A0040403A12EC6E0129FE443CE08F8AD046064831E09B1D20FF527EE35A6DA50A5A4415E6C42C2805A9A67EAE0104932E37BDD07CE8F6C0F24CF1EFF3EAAB6E647F2E044075209DD075D2840EA0057BEE4E5FE3C90125DCA5D28E951D02630A45E8530E3B3B01405220E43CCCF34F9AC4F92543B29E1F281D3F0E6777AD86D793B7D5E8A30DFDC48F47302582DD40E61D36252479BF6FE7F82A004D954EB30D6D089AA6E8776F7CD7F07824F650C04AF6B28EF656C36A683F21674040CAC13E842064BEA28F38B9F8746F19CAB5745F607BDB4539EF214F001C6CEA32CA0C7A8CC4EAC5BDA166A232FC0D37EF58D4430ADE5CCB398B66A7E8BEC8870720F15E0D0DB32B96A01A8C0C9DAD602583CB3B0C1EB47C79A2A22177127D012D3520AB10854B884FDF862A562CCC775CED36EA8D68FE2A00FF689F951C8E7389B089");

        Group bob_handle_group = bob_join_group.handle(commitBytes2, null);


        int x = 9;
    }

//    public void testGeneratingCommit() throws Exception
//    {
//        CipherSuite suite = new CipherSuite((short) 2);
//        byte[] alice_sig_priv = Hex.decode("841e7dff98390e75021e484a9b1adf3284b5b37f80ab5f85937db5c48b249caa");
//        byte[] alice_leaf_priv = Hex.decode("cedaff6d844f373493db6a6fdb51ae6565ada9c4a3fdec6d6141520a8c7fa5fb");
//        byte[] alice_leaf_pub = Hex.decode("04ae6813be63540eb71d8fe35235eef086835c9f8bb5d621d04ec0777e775daf262122d4f81d0c4a62e335361b60a8ccd423a5845bd99b7358421ee127c8398008");
//        byte[] alice_sig_pub = Hex.decode("0495ded23c6fdb01df62ea8218ca325713d8f297ee3a2cf786542c42f5bfe58e32631d380459e8ade5dc4d03db910de292ee6bbe197c7660315473f52839bc7771");
//        byte[] alice_identity = Hex.decode("616c696365");
//        byte[] alice_leaf_before_bytes = Hex.decode("656f7dc9");
//        byte[] alice_leaf_after_bytes = Hex.decode("6750b149");
//        long alice_leaf_before = Pack.littleEndianToInt(alice_leaf_before_bytes, 0);
//        long alice_leaf_after = Pack.littleEndianToInt(alice_leaf_after_bytes, 0);
//
//        byte[] alice_leaf_signature = Hex.decode("3046022100a177543d8dd2e755e9aec906b64a843c40aa09fc36dd91901003b9718e99631802210096741a2cf97c48b2a22ea897fb6541418803bf85975a31f3c18d483364be57e1");
//        byte[] alice_group_id = Hex.decode("66663735343139322d303038352d343266322d383334312d626433653134656630373931");
//
//        byte[] alice_epoch_secret = Hex.decode("d444d075dac80d5fa3744b7d1a69752ae1813585432a3539c8a46abb64689c71");
//        // Alice KeySchedule >
//        byte[] alice_ks_exporter_secret = Hex.decode("fa7897796d9c48d37c4a5857f3feee43468fb4375438e2b58b471b94b56093f4");
//        byte[] alice_ks_authentication_secret = Hex.decode("536a95cc96adb9eb11df045106c6cda470bd396978ad3722e801cde90e7197e7");
//        byte[] alice_ks_external_secret = Hex.decode("3344064a8dbde0886acaa5fd64807820e90ff088bd547b737ef36d3df40080ac");
//        byte[] alice_ks_membership_key = Hex.decode("6a3c99e98b96d91c45cdaa40e52a8e1beee7fe6f2d0932763cf47454be64e63f");
//        byte[] alice_ks_InitSecret = Hex.decode("156ea6d8667fe5a42e7548d880a0be6ea1b67405e0b6cc4d42ab30a60bddf075");
//        //
//        // Alice EpochSecrets
//        byte[] alice_es_resumption_secret = Hex.decode("6c6b9b783592407d02553cdd1ec2b258674b0d55ad6a33ae82588205a1a768a7");
//        byte[] alice_es_sender_data_secret = Hex.decode("9bbdddcc68cb339d7020bb9e388e581106f66fe1bbd43d5880bb28997a99b359");
//        byte[] alice_es_tree_secret = Hex.decode("2680ae81f80880aa36cfe7c8cbd195c5e23b11b7032a4757af89354a5da59173");
//        //
//        byte[] alice_confirmation_key = Hex.decode("366e40b34d96b8bf47d84307c518cb53f4d74288e298a05a4741271af0467005");
//        byte[] alice_interim_hash = Hex.decode("34e28caf756014ba4d438085e5efc2a3f5c3c92b992f380c3969410fe40fef9a");
//
//        byte[] name_here = Hex.decode("");
//
//        //Sanity Checks
//        AsymmetricCipherKeyPair got_alice_sig_key_pair = suite.deserializeSignaturePrivateKey(alice_sig_priv);
//        AsymmetricCipherKeyPair got_alice_leaf_key_pair = suite.getHPKE().deserializePrivateKey(alice_leaf_priv, null);
//        byte[] got_alice_sig_pub = suite.serializeSignaturePublicKey(got_alice_sig_key_pair.getPublic());
//        assertTrue(Arrays.areEqual(got_alice_sig_pub, alice_sig_pub));
//
//        byte[] got_alice_leaf_pub = suite.getHPKE().serializePublicKey(got_alice_leaf_key_pair.getPublic());
//        assertTrue(Arrays.areEqual(got_alice_leaf_pub, alice_leaf_pub));
//
//        // Checking leaf node
//        LeafNode got_alice_leaf_node = new LeafNode(
//                suite,
//                got_alice_leaf_pub,
//                got_alice_sig_pub,
//                Credential.forBasic(alice_identity),
//                new Capabilities(),
//                new LifeTime(alice_leaf_before, alice_leaf_after),
//                new ArrayList<>(),
//                alice_sig_priv
//        );
//        got_alice_leaf_node.signature = alice_leaf_signature;// THIS IS RANDOM CANNOT CONTROL SIGNATURE GENERATION
//
//        //Create Alice Group
//        Group got_alice_group = new Group(
//                alice_group_id,
//                suite,
//                got_alice_leaf_key_pair,
//                alice_sig_priv,
//                got_alice_leaf_node,
//                new ArrayList<>()
//        );
//        assertTrue(Arrays.areEqual(alice_ks_exporter_secret, got_alice_group.keySchedule.exporterSecret.value()));
//        assertTrue(Arrays.areEqual(alice_ks_authentication_secret, got_alice_group.keySchedule.epochAuthenticator.value()));
//        assertTrue(Arrays.areEqual(alice_ks_external_secret, got_alice_group.keySchedule.externalSecret.value()));
//        assertTrue(Arrays.areEqual(alice_ks_membership_key, got_alice_group.keySchedule.membershipKey.value()));
//        assertTrue(Arrays.areEqual(alice_ks_InitSecret, got_alice_group.keySchedule.initSecret.value()));
//        assertTrue(Arrays.areEqual(alice_es_resumption_secret, got_alice_group.keySchedule.resumptionPSK.value()));
//        assertTrue(Arrays.areEqual(alice_es_sender_data_secret, got_alice_group.keySchedule.senderDataSecret.value()));
////        assertTrue(Arrays.areEqual(alice_es_tree_secret, got_alice_group.keySchedule.groupKeySet.secretTree.));
//        assertTrue(Arrays.areEqual(alice_confirmation_key, got_alice_group.keySchedule.confirmationKey.value()));
//        assertTrue(Arrays.areEqual(alice_interim_hash, got_alice_group.transcriptHash.interim));
//
//
//        // Bob creates keyPackage
//        //TODO:
//
//        byte[] bob_key_package = Hex.decode("00010005000100024041047c958fd1ea63c6b628de9edcf4579c7b631e9ae883ab76fdc34d5e5d2c1ca7767f948378609ed6081bee9a979eac6a621dd5b7dd5183aa724439419d0c41cb9840410422fa34bad72eba8162351e7350115f335e1017a69f89b13ca1b95f6a0053bd301a7f84e13a6f7e3a68ede44d835072f43f0eb1c586e1ecd4d551f5f21f1e04e64041045f728ab9b392dfe007a4d861fbc142500c838016ec95ba986dadd47932439a350e9b48c17556186dea1147bd137bd76886ee05761af71e8fd148b5856ea40d02000103626f620200010e000100020003000400050006000700000200010100000000656f7dc9000000006750b1490040473045022100be9c7236596b57d41ffc692538c5bd98ee33fdc64d4314a473acc837e25a28850220196faa7aa43fb00f9a615fdffc12ba027025a611140b7977183f560c1d1667ea0040463044022035911fc013632f20b30db6dba27a4c4ad306370aadb897fd46cc58c2f73c51400220575759e88f873df58b11bf4a6ea1081fed7a65f9369eb17a662e1b878e0458c4");
//        MLSMessage got_bob_key_package = (MLSMessage) MLSInputStream.decode(bob_key_package, MLSMessage.class);
//
//        // Alice recieves key package ref and adds Proposal
//        //TODO: instead of doing add() try creating a private message from mls-rs and see if handle works with it
//        // most likely there is a problem with generating the private message
//        // check if the keys match the private key generator
//        MLSMessage got_alice_add_proposal = got_alice_group.add(got_bob_key_package.keyPackage, new Group.MessageOptions(true, new byte[0], 0));
////        System.out.println(Hex.toHexString(MLSOutputStream.encode(got_alice_add_proposal)));
//
////        MLSMessage protectedProposal = new MLSMessage();
//
//
//        byte[] got_alice_add_proposal_ref = MLSOutputStream.encode(got_alice_add_proposal);
//        Group shouldBeNull = got_alice_group.handle(got_alice_add_proposal_ref, null);
//
//
//        int x = 0;
//
//    }

    private KeyPackageWithSecrets newKeyPackage(CipherSuite suite, byte[] identity,
                                                byte[] init_priv, byte[] encryption_priv, byte[] signature_priv,
                                                byte[] leafSignature, byte[] kpSignature) throws Exception
    {
        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().deserializePrivateKey(init_priv, null);
        AsymmetricCipherKeyPair encryptionKeyPair = suite.getHPKE().deserializePrivateKey(encryption_priv, null);
        AsymmetricCipherKeyPair sigKeyPair = suite.deserializeSignaturePrivateKey(signature_priv);

        Credential cred = Credential.forBasic(identity);

        LeafNode leafNode = new LeafNode(
                suite,
                suite.getHPKE().serializePublicKey(encryptionKeyPair.getPublic()),
                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
                cred,
                new Capabilities(),
                new LifeTime(0, -1),
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        leafNode.signature = leafSignature;

        KeyPackage kp = new KeyPackage(
                suite,
                suite.getHPKE().serializePublicKey(initKeyPair.getPublic()),
                leafNode,
                new ArrayList<>(),
//                suite.serializeSignaturePublicKey(sigKeyPair.getPublic())
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        kp.signature = kpSignature;
        return new KeyPackageWithSecrets(initKeyPair, encryptionKeyPair, sigKeyPair, kp);
    }

    private KeyPackageWithSecrets newKeyPackage(CipherSuite suite, byte[] identity) throws Exception
    {
        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair encryptionKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        Credential cred = Credential.forBasic(identity);

        LeafNode leafNode = new LeafNode(
                suite,
                suite.getHPKE().serializePublicKey(encryptionKeyPair.getPublic()),
                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
                cred,
                new Capabilities(),
                new LifeTime(0, -1),
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );

        KeyPackage kp = new KeyPackage(
                suite,
                suite.getHPKE().serializePublicKey(initKeyPair.getPublic()),
                leafNode,
                new ArrayList<>(),
//                suite.serializeSignaturePublicKey(sigKeyPair.getPublic())
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        return new KeyPackageWithSecrets(initKeyPair, encryptionKeyPair, sigKeyPair, kp);
    }
}
