package org.bouncycastle.pqc.crypto.lms;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class LMSKeyGenTests
    extends TestCase
{
    public void testGeneratePrivateKey()
        throws Exception
    {
        //
        // This is based on the second set of vectors and the second signature.
        // We verify the correct private key is generated if the correct public key is
        // derived from it.
        //
        byte[] msg = Hex.decode("54686520656e756d65726174696f6e20\n" +
            "696e2074686520436f6e737469747574\n" +
            "696f6e2c206f66206365727461696e20\n" +
            "7269676874732c207368616c6c206e6f\n" +
            "7420626520636f6e7374727565642074\n" +
            "6f2064656e79206f7220646973706172\n" +
            "616765206f7468657273207265746169\n" +
            "6e6564206279207468652070656f706c\n" +
            "652e0a");

        // From vecot.
        byte[] seed = Hex.decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
        byte[] I = Hex.decode("215f83b7ccb9acbcd08db97b0d04dc2b");
        int level = 1; // This is the second level, we use this because it signs the message.

        // Generate the private key.
        LMSPrivateKeyParameters lmsPrivateKey = LMS.generateKeys(LMSigParameters.getParametersForType(5), LMOtsParameters.getParametersForType(4), level, I, seed);

        // This derives the public key.
        LMSPublicKeyParameters publicKey = lmsPrivateKey.getPublicKey();

        // From the vector.
        String pkEnc = "0000000500000004215f83b7ccb9acbcd08db97b0d04dc2ba1cd035833e0e90059603f26e07ad2aad152338e7a5e5984bcd5f7bb4eba40b7";

        // Test public key encoded matched vector.
        assertTrue(Arrays.areEqual(Hex.decode(pkEnc), publicKey.getEncoded()));

        //
        // Fast forward and burn off some OTS private keys until we get to key number 4.
        //
        lmsPrivateKey.extractKeyShard(3);

        LMSSignature signature = LMS.generateSign(lmsPrivateKey, msg);

        // The expected signature as encoded.
        String sigEnc = "00000004\n" +
            "00000004\n" +
            "0eb1ed54a2460d512388cad533138d24\n" +
            "0534e97b1e82d33bd927d201dfc24ebb\n" +
            "11b3649023696f85150b189e50c00e98\n" +
            "850ac343a77b3638319c347d7310269d\n" +
            "3b7714fa406b8c35b021d54d4fdada7b\n" +
            "9ce5d4ba5b06719e72aaf58c5aae7aca\n" +
            "057aa0e2e74e7dcfd17a0823429db629\n" +
            "65b7d563c57b4cec942cc865e29c1dad\n" +
            "83cac8b4d61aacc457f336e6a10b6632\n" +
            "3f5887bf3523dfcadee158503bfaa89d\n" +
            "c6bf59daa82afd2b5ebb2a9ca6572a60\n" +
            "67cee7c327e9039b3b6ea6a1edc7fdc3\n" +
            "df927aade10c1c9f2d5ff446450d2a39\n" +
            "98d0f9f6202b5e07c3f97d2458c69d3c\n" +
            "8190643978d7a7f4d64e97e3f1c4a08a\n" +
            "7c5bc03fd55682c017e2907eab07e5bb\n" +
            "2f190143475a6043d5e6d5263471f4ee\n" +
            "cf6e2575fbc6ff37edfa249d6cda1a09\n" +
            "f797fd5a3cd53a066700f45863f04b6c\n" +
            "8a58cfd341241e002d0d2c0217472bf1\n" +
            "8b636ae547c1771368d9f317835c9b0e\n" +
            "f430b3df4034f6af00d0da44f4af7800\n" +
            "bc7a5cf8a5abdb12dc718b559b74cab9\n" +
            "090e33cc58a955300981c420c4da8ffd\n" +
            "67df540890a062fe40dba8b2c1c548ce\n" +
            "d22473219c534911d48ccaabfb71bc71\n" +
            "862f4a24ebd376d288fd4e6fb06ed870\n" +
            "5787c5fedc813cd2697e5b1aac1ced45\n" +
            "767b14ce88409eaebb601a93559aae89\n" +
            "3e143d1c395bc326da821d79a9ed41dc\n" +
            "fbe549147f71c092f4f3ac522b5cc572\n" +
            "90706650487bae9bb5671ecc9ccc2ce5\n" +
            "1ead87ac01985268521222fb9057df7e\n" +
            "d41810b5ef0d4f7cc67368c90f573b1a\n" +
            "c2ce956c365ed38e893ce7b2fae15d36\n" +
            "85a3df2fa3d4cc098fa57dd60d2c9754\n" +
            "a8ade980ad0f93f6787075c3f680a2ba\n" +
            "1936a8c61d1af52ab7e21f416be09d2a\n" +
            "8d64c3d3d8582968c2839902229f85ae\n" +
            "e297e717c094c8df4a23bb5db658dd37\n" +
            "7bf0f4ff3ffd8fba5e383a48574802ed\n" +
            "545bbe7a6b4753533353d73706067640\n" +
            "135a7ce517279cd683039747d218647c\n" +
            "86e097b0daa2872d54b8f3e508598762\n" +
            "9547b830d8118161b65079fe7bc59a99\n" +
            "e9c3c7380e3e70b7138fe5d9be255150\n" +
            "2b698d09ae193972f27d40f38dea264a\n" +
            "0126e637d74ae4c92a6249fa103436d3\n" +
            "eb0d4029ac712bfc7a5eacbdd7518d6d\n" +
            "4fe903a5ae65527cd65bb0d4e9925ca2\n" +
            "4fd7214dc617c150544e423f450c99ce\n" +
            "51ac8005d33acd74f1bed3b17b7266a4\n" +
            "a3bb86da7eba80b101e15cb79de9a207\n" +
            "852cf91249ef480619ff2af8cabca831\n" +
            "25d1faa94cbb0a03a906f683b3f47a97\n" +
            "c871fd513e510a7a25f283b196075778\n" +
            "496152a91c2bf9da76ebe089f4654877\n" +
            "f2d586ae7149c406e663eadeb2b5c7e8\n" +
            "2429b9e8cb4834c83464f079995332e4\n" +
            "b3c8f5a72bb4b8c6f74b0d45dc6c1f79\n" +
            "952c0b7420df525e37c15377b5f09843\n" +
            "19c3993921e5ccd97e097592064530d3\n" +
            "3de3afad5733cbe7703c5296263f7734\n" +
            "2efbf5a04755b0b3c997c4328463e84c\n" +
            "aa2de3ffdcd297baaaacd7ae646e44b5\n" +
            "c0f16044df38fabd296a47b3a838a913\n" +
            "982fb2e370c078edb042c84db34ce36b\n" +
            "46ccb76460a690cc86c302457dd1cde1\n" +
            "97ec8075e82b393d542075134e2a17ee\n" +
            "70a5e187075d03ae3c853cff60729ba4\n" +
            "00000005\n" +
            "4de1f6965bdabc676c5a4dc7c35f97f8\n" +
            "2cb0e31c68d04f1dad96314ff09e6b3d\n" +
            "e96aeee300d1f68bf1bca9fc58e40323\n" +
            "36cd819aaf578744e50d1357a0e42867\n" +
            "04d341aa0a337b19fe4bc43c2e79964d\n" +
            "4f351089f2e0e41c7c43ae0d49e7f404\n" +
            "b0f75be80ea3af098c9752420a8ac0ea\n" +
            "2bbb1f4eeba05238aef0d8ce63f0c6e5\n" +
            "e4041d95398a6f7f3e0ee97cc1591849\n" +
            "d4ed236338b147abde9f51ef9fd4e1c1";


        // Check generated signature matches vector.
        assertTrue(Arrays.areEqual(Hex.decode(sigEnc), signature.getEncoded()));


        // Sanity test
        assertTrue(LMS.verifySignature(publicKey, signature, msg));


    }


}
