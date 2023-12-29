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
import org.bouncycastle.mls.codec.FramedContent;
import org.bouncycastle.mls.codec.GroupInfo;
import org.bouncycastle.mls.codec.KeyPackage;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.Proposal;
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
        byte[] groupIDBytes = Hex.decode("35303030393332372d653034392d343531342d616232632d666430616466326466383838");
        CipherSuite suite = new CipherSuite((short) 1);
        byte[] identity = Hex.decode("616C696365");
        boolean encrypt = false;

//        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        byte[] sig_priv = Hex.decode("95f0faf3c26513b03bd2526538d55c1ec202028679c106a940a1ca086db9a85a");
        byte[] leaf_priv = Hex.decode("a100e271470814a05bffc2ca54ca955af7c5b51f28dacce3b6cd866f5c8b87c9");
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
        leafnode0.signature = Hex.decode("89cdeafaeae1110b11112681511d5a3b09b9f2b8e14333a177483c9db06c42d30d7b94d5346a8950db2e68ad7536c94c51a88335cee7a4e5059ba32c1ceafc02");

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
        byte[] expGroupInfoBytes = Hex.decode("00010004000100012435303030393332372D653034392D343531342D616232632D666430616466326466383838000000000000000020DA51435D5D6F6C06FAFD88EE16917C176CD2BFF729EDC596AFBA5BFB6705DAD0000040E10004212018A311C5466D6A428B53A199FC0E2BA4C534F7BCA6D9871259525BE7EADFBD33000240B940B70101202724938320EE803F262E293872BCE24522D6DD82BCDE41C39A256A1F6E739C1620A04F762B97241B4173BA12B3EA98611B639285CC149664AA1E41CFC70ADC986C000105616C6963650200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF00404089CDEAFAEAE1110B11112681511D5A3B09B9F2B8E14333A177483C9DB06C42D30D7B94D5346A8950DB2E68AD7536C94C51A88335CEE7A4E5059BA32C1CEAFC0220A5DFF379BDA1D0EBEBE50A30C88EB1181646FB2A846245C67685D4D5569A5E3B000000004040F5A710C9BFC06F65D828B0F701814D1B418141C3C9CBEFD3DAA471AA4F01FD1A4D1FB10144F1B608F6AF27F7DD8C20F469682EEA6167E7B0DE36C469E2EFA50B");

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
        byte[] init_priv = Hex.decode("619c300a3e813f378fbfb956f3970331a111ce8d5e5ab368f15e4fd06ce00ac9");
        byte[] leaf_priv1 = Hex.decode("4d4386f8efcc9823347d98d3175df830fb96dbcdf22ab6be10a36ce2d49d17d5");
        byte[] sig_priv1 = Hex.decode("85c79e0e2aeea4b0ea42307b9a1e2c95a1fd1800a2970d3b8cea793efb181f7a");
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
        leafnode1.signature = Hex.decode("ba614362953fbc5fa7754b8cdea95b2e2ab63f4861fb82c4417f01f7aee15002515b2b9317e9313f7dc045e5f2f99c9d673f58eb8fa2c944095ff62d8ac2690f");

        KeyPackage kp = new KeyPackage(
                suite,
                suite.getHPKE().serializePublicKey(initKeyPair.getPublic()),
                leafnode1,
                new ArrayList<>(),
                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        kp.signature = Hex.decode("d5025bfe5f68d70fc824b5efabd7fbe883d1a50b604b1fd65a066ef46dce4ebd7197a47efc04bd0890c1b260bed24e873e7ba27d0817892cf93191c1dfae040f");

        TreeKEMPublicKey ratchetTree = null;
        LeafIndex removeIndex = null;
        boolean removePrior = false;
        // no remove prior
        // no psks

        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(leafSecret);
        leafSecret = Hex.decode("2a0b1921243095deba2b1ccaa88d9a3b373e4be5b02a5937f6cb01c4e18b7a44");

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
        byte[] expCommitBytes = Hex.decode("000100012435303030393332372D653034392D343531342D616232632D66643061646632646638383800000000000000000400032401000620E398076AB0ABA9030D08F8CF421B12B815AAC97A352B481F44C6EF007BED976B01202DA0CE9057189DA9807ECC21BDBE1DD875E0AA86A019C8FE9B5FF90C7F751F1D2091C7A2F3645B38F3CB62DEF4DC68837DAFB751BE593594AD82DF234C312103B3000103626F620200010C0001000200030004000500060000040001000203204545566171788E3875A077BCDF5BB5A8283862A4FD1D2EFD816929C18A2A5F140040408822A133C6209A9894736828D3572A67DC721E2C32116F17BBC36491C311DE3AC6601D4BB29152BB42A037F03D921FD1D76727DB997CD803D557972180E1CA0A4075209EE79372C28B69AB434ADC68A38E6359248A7045BF94BB69DA45F2C40E4E6737405220779987CE2DC496581CB584E481D7A41C443FBDED501CD7E560C05C74850F955B30E0250957F8AD31D90172521C680348C2A00BF6FA10A83C27089B6E520056798A595C9BFD13568C6BB48E3B54E897350D404087F6BFF69C018471BCAD986F0715EC913E4071DFE3A70DC97B5B7F7813A1FE3918A55B6DB3BD5B440C44CEFF855BBB8D0BCBD5395260E3D1C92619929BA1030420739C53E05F3511620B4D8B14F8175350C1B33DAFAE284453A6284D790B44CD3A");

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
