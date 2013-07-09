package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * basic test class for a block cipher, basically this just exercises the provider, and makes sure we
 * are behaving sensibly, correctness of the implementation is shown in the lightweight test classes.
 */
public class BlockCipherTest
    extends SimpleTest
{
    static String[] cipherTests1 =
    {
        "DES",
        "466da00648ef0e1f9617b1f002e225251a3248d09172f46b9617b1f002e225250112ecb3da61bc99",
        "DESede",
        "2f4bc6b30c893fa549d82c560d61cf3eb088aed020603de249d82c560d61cf3e529e95ecd8e05394",
        "SKIPJACK",
        "d4de46d52274dbb029f33b076043f8c40089f906751623de29f33b076043f8c4ac99b90f9396cb04",
        "Blowfish",
        "7870ebe7f6a52803eb9396ba6c5198216ce81d76d8d4c74beb9396ba6c5198211212473b05214e9f",
        "Twofish",
        "70336d9c9718a8a2ced1b19deed973a3c58af7ea71a69e7efc4df082dca581c0839e31468661bcfc57a14899ceeb0253",
        "RC2",
        "eb5b889bbcced12eb6b1a3da6a3d965bba66a5edfdd4c8a6b6b1a3da6a3d965b994a5b859e765797",
        "RC5",
        "220053543e3eca3bc9503a091ca67b08372560d8a4fdbee8c9503a091ca67b08a796d53bb8a4b7e0",
        "RC5-64",
        "e0b4a526ba3bc5f09199c3b1fe3737fe6d248cde70e565b0feea59ebfda375ae1946c386a48d8d8a74d7b1947ff6a788",
        "RC6",
        "44c97b67ca8486067f8b6c5b97632f3049e5e52c1d61fdd527dc3da39616540f19a3db39aac1ffd713795cd886cce0c0",
        "IDEA",
        "8c9fd56823ffdc523f6ccf7f614aa6173553e594fc7a21b53f6ccf7f614aa61740c54f7a66e95108",
        "TEA",
        "fcf45062104fda7c35712368b56dd4216a6ca998dc297b5435712368b56dd421208027ed2923cd0c",
        "XTEA",
        "4b427893d3d6aaded2afafabe25f7b233fb5589faa2b6389d2afafabe25f7b239d12979ac67e1c07",
        "Camellia",
        "3a68b4ad145bc2c76010669d68f2826359887afce763a78d9994143266adfaec8ba7ee562a1688ef9dfd7f897e5c44dc",
        "SEED",
        "d53d4ce1f48b9879420949467bfcbfbe2c6a7d4a8770bee0c71211def898d7c5024ce2007dd85accb3f69d906ae2164d",
        "Noekeon",
        "7e68ceb33aad9db04af6b878a16dd6c6b4f880d6c89027ba581884c10690bb6b3dbfd6ed5513e2c4f5670c3528023121",
        "DES/CBC/NoPadding",
        "60fa2f8fae5aa2a38e9ac77d0246726beb7511e4515feb12cf99f75cc6e0122a",
        "DESede/CBC/NoPadding",
        "4d3d7931875cf25593dc402298add8b914761e4936c9585ae22b2c1441169231",
        "SKIPJACK/CBC/NoPadding",
        "ceebcc2e5e2b847f9ed797b4930b95f115b9e6cf49c457fc2ea0df79ad5c8334",
        "Blowfish/CBC/NoPadding",
        "80823abbabc109733e7ebf3ce3344d67fc387c306b782086b452f7fbe8e844ce",
        "Twofish/CBC/NoPadding",
        "f819694251a00bdd403928745cd1d8a094de61f49ddf8e7692e9d81a83812943",
        "RC2/CBC/NoPadding",
        "a51facdb3933c9676795cd38cc3146fd4694722b468b1a979a399c77606abf99",
        "RC5/CBC/NoPadding",
        "9ee7517eab0280445f3a7c60c90c0f75029d65bca8b1af83ace5399d388c83c3",
        "RC6/CBC/NoPadding",
        "c44695633c07010f3a0d8f7ea046a642d4a96bf4e44f89fd91b46830bc95b130",
        "IDEA/CBC/NoPadding",
        "30cd990ebdae80fe12b6c6e4fcd1c064a27d985c276b3d7097351c8684e4c4d9",
        "DES/CBC/PKCS5Padding",
        "60fa2f8fae5aa2a38e9ac77d0246726beb7511e4515feb12cf99f75cc6e0122afdc70484fb9c0232",
        "DES/CBC/ISO10126Padding",
        "60fa2f8fae5aa2a38e9ac77d0246726beb7511e4515feb12cf99f75cc6e0122a980639850a2cc3e8",
        "DES/CBC/ISO7816-4Padding",
        "60fa2f8fae5aa2a38e9ac77d0246726beb7511e4515feb12cf99f75cc6e0122a1f80b9b0f1be49ac",
        "DES/CBC/X9.23Padding",
        "60fa2f8fae5aa2a38e9ac77d0246726beb7511e4515feb12cf99f75cc6e0122a980639850a2cc3e8",
        "DESede/CBC/PKCS7Padding",
        "4d3d7931875cf25593dc402298add8b914761e4936c9585ae22b2c1441169231a41e40695f1cff84",
        "SKIPJACK/CBC/PKCS7Padding",
        "ceebcc2e5e2b847f9ed797b4930b95f115b9e6cf49c457fc2ea0df79ad5c8334df7042de5db89c96",
        "Blowfish/CBC/PKCS7Padding",
        "80823abbabc109733e7ebf3ce3344d67fc387c306b782086b452f7fbe8e844cef986562ab1a675e8",
        "Twofish/CBC/PKCS7Padding",
        "f819694251a00bdd403928745cd1d8a094de61f49ddf8e7692e9d81a838129433e5f1343d6cdb0b41838619da1541f04",
        "RC2/CBC/PKCS7Padding",
        "a51facdb3933c9676795cd38cc3146fd4694722b468b1a979a399c77606abf9958435525f770f137",
        "RC5/CBC/PKCS7Padding",
        "9ee7517eab0280445f3a7c60c90c0f75029d65bca8b1af83ace5399d388c83c3edd95ff49be76651",
        "RC5-64/CBC/PKCS7Padding",
        "e479fd11f89dab22d2f3dd062b1d2abd5b5962553421a5c562dc7214c3b23b8e21949fda87f2f820e5f032c552c6ec78",
        "RC6/CBC/PKCS7Padding",
        "c44695633c07010f3a0d8f7ea046a642d4a96bf4e44f89fd91b46830bc95b130824b972c9019a69d2dd05ef2d36b37ac",
        "IDEA/CBC/PKCS7Padding",
        "30cd990ebdae80fe12b6c6e4fcd1c064a27d985c276b3d7097351c8684e4c4d9e584751325ef7c32",
        "IDEA/CBC/ISO10126Padding",
        "30cd990ebdae80fe12b6c6e4fcd1c064a27d985c276b3d7097351c8684e4c4d978b3fd73135f033b",
        "IDEA/CBC/X9.23Padding",
        "30cd990ebdae80fe12b6c6e4fcd1c064a27d985c276b3d7097351c8684e4c4d978b3fd73135f033b",
        "AES/CBC/PKCS7Padding",
        "cf87f4d8bb9d1abb36cdd9f44ead7d046db2f802d99e1ef0a5940f306079e08389a44c4a8cc1a47cbaee1128da55bbb7",
        "AES/CBC/ISO7816-4Padding",
        "cf87f4d8bb9d1abb36cdd9f44ead7d046db2f802d99e1ef0a5940f306079e08306d84876508a33efec701118d8eeaf6d",
        "Rijndael/CBC/PKCS7Padding",
        "cf87f4d8bb9d1abb36cdd9f44ead7d046db2f802d99e1ef0a5940f306079e08389a44c4a8cc1a47cbaee1128da55bbb7",
        "Serpent/CBC/PKCS7Padding",
        "f8940ca31aba8ce1e0693b1ae0b1e08daef6de03c80f019774280052f824ac44540bb8dd74dfad47f83f9c7ec268ca68",
        "CAST5/CBC/PKCS7Padding",
        "87b6dc0c5a1d23d42fa740b0548be0b298112000544610d889d6361994cf8e670a19d6af72d7289f",
        "CAST6/CBC/PKCS7Padding",
        "943445569cfdda174118e433828f84e137faee38cac5c827d87a3c9a5a46a07dd64e7ad8accd921f248eea627cd6826f",
        "DES/CBC/WithCTS",
        "60fa2f8fae5aa2a38e9ac77d0246726bcf99f75cc6e0122aeb7511e4515feb12",
        "IDEA/CBC/PKCS7Padding",
        "30cd990ebdae80fe12b6c6e4fcd1c064a27d985c276b3d7097351c8684e4c4d9e584751325ef7c32",
        "DES/CBC/ZeroBytePadding",
        "60fa2f8fae5aa2a38e9ac77d0246726beb7511e4515feb12cf99f75cc6e0122ad3b3f002c927f1fd",
        "DES/CTS/NoPadding", // official style
        "60fa2f8fae5aa2a38e9ac77d0246726bcf99f75cc6e0122aeb7511e4515feb12",
        "DESede/CTS/NoPadding",
        "4d3d7931875cf25593dc402298add8b9e22b2c144116923114761e4936c9585a",
        "SKIPJACK/CTS/NoPadding",
        "ceebcc2e5e2b847f9ed797b4930b95f12ea0df79ad5c833415b9e6cf49c457fc",
        "Blowfish/CTS/NoPadding",
        "80823abbabc109733e7ebf3ce3344d67b452f7fbe8e844cefc387c306b782086",
        "Twofish/CTS/NoPadding",
        "94de61f49ddf8e7692e9d81a83812943f819694251a00bdd403928745cd1d8a0",
        "AES/CTS/NoPadding",
        "6db2f802d99e1ef0a5940f306079e083cf87f4d8bb9d1abb36cdd9f44ead7d04",
        "Rijndael/CTS/NoPadding",
        "6db2f802d99e1ef0a5940f306079e083cf87f4d8bb9d1abb36cdd9f44ead7d04",
        "Serpent/CTS/NoPadding",
        "aef6de03c80f019774280052f824ac44f8940ca31aba8ce1e0693b1ae0b1e08d",
        "CAST5/CTS/NoPadding",
        "87b6dc0c5a1d23d42fa740b0548be0b289d6361994cf8e6798112000544610d8",
        "CAST6/CTS/NoPadding",
        "37faee38cac5c827d87a3c9a5a46a07d943445569cfdda174118e433828f84e1",
        "RC2/CTS/NoPadding",
        "a51facdb3933c9676795cd38cc3146fd9a399c77606abf994694722b468b1a97",
        "RC5/CTS/NoPadding",
        "9ee7517eab0280445f3a7c60c90c0f75ace5399d388c83c3029d65bca8b1af83",
        "RC6/CTS/NoPadding",
        "d4a96bf4e44f89fd91b46830bc95b130c44695633c07010f3a0d8f7ea046a642",
        "IDEA/CTS/NoPadding",
        "30cd990ebdae80fe12b6c6e4fcd1c06497351c8684e4c4d9a27d985c276b3d70",
        "DES/CBC/WithCTS",                  // older style
        "60fa2f8fae5aa2a38e9ac77d0246726bcf99f75cc6e0122aeb7511e4515feb12",
        "DESede/CBC/WithCTS",
        "4d3d7931875cf25593dc402298add8b9e22b2c144116923114761e4936c9585a",
        "SKIPJACK/CBC/WithCTS",
        "ceebcc2e5e2b847f9ed797b4930b95f12ea0df79ad5c833415b9e6cf49c457fc",
        "Blowfish/CBC/WithCTS",
        "80823abbabc109733e7ebf3ce3344d67b452f7fbe8e844cefc387c306b782086",
        "Twofish/CBC/WithCTS",
        "94de61f49ddf8e7692e9d81a83812943f819694251a00bdd403928745cd1d8a0",
        "AES/CBC/WithCTS",
        "6db2f802d99e1ef0a5940f306079e083cf87f4d8bb9d1abb36cdd9f44ead7d04",
        "Rijndael/CBC/WithCTS",
        "6db2f802d99e1ef0a5940f306079e083cf87f4d8bb9d1abb36cdd9f44ead7d04",
        "Serpent/CBC/WithCTS",
        "aef6de03c80f019774280052f824ac44f8940ca31aba8ce1e0693b1ae0b1e08d",
        "CAST5/CBC/WithCTS",
        "87b6dc0c5a1d23d42fa740b0548be0b289d6361994cf8e6798112000544610d8",
        "CAST6/CBC/WithCTS",
        "37faee38cac5c827d87a3c9a5a46a07d943445569cfdda174118e433828f84e1",
        "RC2/CBC/WithCTS",
        "a51facdb3933c9676795cd38cc3146fd9a399c77606abf994694722b468b1a97",
        "RC5/CBC/WithCTS",
        "9ee7517eab0280445f3a7c60c90c0f75ace5399d388c83c3029d65bca8b1af83",
        "RC6/CBC/WithCTS",
        "d4a96bf4e44f89fd91b46830bc95b130c44695633c07010f3a0d8f7ea046a642",
        "IDEA/CBC/WithCTS",
        "30cd990ebdae80fe12b6c6e4fcd1c06497351c8684e4c4d9a27d985c276b3d70",
        "DES/OFB/NoPadding",
        "537572e480c1714f5c9a4f3b874df824dc6681b1fd6c11982debcad91e3f78b7",
        "DESede/OFB/NoPadding",
        "481e9872acea7fcf8e29a453242da774e5f6a28f15f7723659a73e4ff4939f80",
        "SKIPJACK/OFB/NoPadding",
        "71143a124e3a0cde753b60fe9b200e559018b6a0fe0682659f7c13feb9df995c",
        "Blowfish/OFB/NoPadding",
        "6cd6f7c5d2c655556d7a9e98a1696d1875e9f1b2fc991e28a2d55b56861e80bd",
        "Twofish/OFB/NoPadding",
        "821c54b1b54ae113cf74595eefe10c83b61c9682fc81f92c52f39a3a693f88b8",
        "Threefish-256/OFB/NoPadding",
        "546ea995dd302f1efcb1f27d14bad468280a3a7994c2af75dfdf1e9fc5ef2373",
        "Threefish-512/OFB/NoPadding",
        "152df966484ecc2e9ddfc386559732f7f632e4008920804a1bde4efcf2e6e2f2",
        "Threefish-1024/OFB/NoPadding",
        "03953ac751a7377812c6e3e4d14b36c6953f9b390acaa892811c10001c9be454",
        "RC2/OFB/NoPadding",
        "0a07cb78537cb04c0c74e28a7b86b80f80acadf87d6ef32792f1a8cf74b39f74",
        "RC5/OFB/NoPadding",
        "c62b233df296283b918a2b4cc53a54fbf061850e781b97332ed1bd78b88d9670",
        "IDEA/OFB/NoPadding",
        "dd447da3cbdcf81f4053fb446596261cb00a3c49a66085485af5f7c10ba20dad",
        "DES/OFB8/NoPadding",
        "53cb5010d189f94cf584e5ff1c4a9d86443c45ddb6fa3c2d1a5dadfcdf01db8a",
        "DESede/OFB8/NoPadding",
        "482c0c1ccd0e6d218e1cffb0a295352c2357ffaa673f2257ef5c77b6c04f03b5",
        "SKIPJACK/OFB8/NoPadding",
        "719ea1b432b3d2c8011e5aa873f95978420022b5e2c9c1a1c1082cd1f4999da2",
        "Blowfish/OFB8/NoPadding",
        "6ca6078755b263f09787d830b6fda7b7748494634bdc73ab68540cf9f6b7eccf",
        "Twofish/OFB8/NoPadding",
        "825dcec234ad52253d6e064b0d769bc04b1142435933f4a510ffc20d70095a88",
        "Threefish-256/OFB8/NoPadding",
        "545fbd92313512127218262dd4394569aca96ba122e1432b661ecfc01af3a25c",
        "Threefish-512/OFB8/NoPadding",
        "15f6e7d215662c525ea982cab56409cf833157e1af06edd57a13c71487904fea",
        "Threefish-1024/OFB8/NoPadding",
        "03d80b67ff7139d9dd8b07280642f94074496e5fc37b1ba1f8593cdf64a1e4ca",
        "RC2/OFB8/NoPadding",
        "0aa26c6f6a820fe7d38da97085995ad62e2e293323a76300fcd4eb572810f7c6",
        "RC5/OFB8/NoPadding",
        "c601a9074dbd874f4d3293f6a32d93d9f0a4f5685d8597f0102fcc96d444f976",
        "IDEA/OFB8/NoPadding",
        "dd7897b6ced43d060a518bb38d570308b83b4de577eb208130daabf619e9b1fb",
        "DES/CFB/NoPadding",
        "537572e480c1714fec3c7424f88d4202219244c5ca8f5e4361d64f08fe747bb2",
        "DESede/CFB/NoPadding",
        "481e9872acea7fcfb75bb58670fe64c59123265139e357d161cd4ddb5eba042a",
        "SKIPJACK/CFB/NoPadding",
        "71143a124e3a0cde70a69ede4ceb14376b1e6a80bafde0a6330508dfa86a7c41",
        "Blowfish/CFB/NoPadding",
        "6cd6f7c5d2c6555561167fe9b10665102206869339122f1ed89efa4a985397f6",
        "Twofish/CFB/NoPadding",
        "821c54b1b54ae113cf74595eefe10c8308b7a438277de4f40948ac2d172d53d2",
        "Threefish-256/CFB/NoPadding",
        "546ea995dd302f1efcb1f27d14bad468280a3a7994c2af75dfdf1e9fc5ef2373",
        "Threefish-512/CFB/NoPadding",
        "152df966484ecc2e9ddfc386559732f7f632e4008920804a1bde4efcf2e6e2f2",
        "Threefish-1024/CFB/NoPadding",
        "03953ac751a7377812c6e3e4d14b36c6953f9b390acaa892811c10001c9be454",
        "RC2/CFB/NoPadding",
        "0a07cb78537cb04ca1401450d5cd411c7da7fa5b6baaa17bb2137bd95c9f26a5",
        "RC5/CFB/NoPadding",
        "c62b233df296283b989352bbebf616a19e11503ac737f9e0eaf19049cde05d34",
        "IDEA/CFB/NoPadding",
        "dd447da3cbdcf81fcbe4661dcbed88aed899f87585118384bd0565067fa6c13a",
        "DES/CFB8/NoPadding",
        "53cb0cdff712a825eb283b23c31e7323aa12495e7e751428b5c4eb89b28a25d4",
        "DESede/CFB8/NoPadding",
        "482cd5bf87ca4cee0b573d66a077231bfea93843ce2d1f948550a1d208e18279",
        "SKIPJACK/CFB8/NoPadding",
        "719eef3906bef23f7b63599285437d8e34183b165acf3e855b4e160d4f036508",
        "Blowfish/CFB8/NoPadding",
        "6ca63aaada9188d2410c07513cc0736b9888770768c25a5befc776beea5bdc4c",
        "Twofish/CFB8/NoPadding",
        "825d12af040721cf5ed4a4798647837ac5eb14d752aace28728aeb37b2010abd",
        "Threefish-256/CFB8/NoPadding",
        "545fbf0a4b925f399cf7540f1cc1cc6012e329ab2d4db0aa0dfa29ee2a2019d1",
        "Threefish-512/CFB8/NoPadding",
        "15f695964f20b95ed72afad75f905788839c53bed2ae5fdfdfb13e3241fd7f94",
        "Threefish-1024/CFB8/NoPadding",
        "03d897c89e740d2254f717b73315151d9a34c829e4162232b3cd5f5158ff367b",
        "RC2/CFB8/NoPadding",
        "0aa227f94be3a32ff927c5d25647ea41d7c2a1e94012fc7f2ad6767b9664bce5",
        "RC5/CFB8/NoPadding",
        "c601cf88725411f119965b9cd38d6c313b91128ed7c98c7604cc62d9b210be79",
        "IDEA/CFB8/NoPadding",
        "dd7839d2525420d10f95eec23dbaf3463302c445972a28c563c2635191bc19af",
        "IDEA/PGPCFB/NoPadding",
        "dd447da3cbdcf81fcbe4661dcbed88aed899f87585118384bd0565067fa6c13a",
        "IDEA/PGPCFBwithIv/NoPadding",
        "ed5adbac0e730cc0f00df7e4f6fef672ab042673106435faf3ecf3996a72a0e127b440ba9e5313501de3",
        "Twofish/ECB/TBCPadding",
        "70336d9c9718a8a2ced1b19deed973a3c58af7ea71a69e7efc4df082dca581c019d7daa58d02b89aab6e8c0d17202439",
        "RC2/ECB/TBCPadding",
        "eb5b889bbcced12eb6b1a3da6a3d965bba66a5edfdd4c8a6b6b1a3da6a3d965b6b5359ba5e69b179",
        "DES/CTR/NoPadding",
        "537572e480c1714fb47081d35eb18eaca9e0a5aee982f105438a0db6cece1f6d",
        "DESede/CTR/NoPadding",
        "481e9872acea7fcfa93b7d4e34ec7bab340c10faba2e43b879d40d38e07c422d",
        "SKIPJACK/CTR/NoPadding",
        "71143a124e3a0cdeee98a7b843baa05bd1d59faee8ec9b89880e070314a04cc2",
        "Blowfish/CTR/NoPadding",
        "6cd6f7c5d2c65555d2b31f8614f54ec654f5e7888d515008d59302c3edfcc6cb",
        "Twofish/CTR/NoPadding",
        "821c54b1b54ae113cf74595eefe10c83d09e95d4599190b9bbd5bc71dd703730",
        "Threefish-256/CTR/NoPadding",
        "546ea995dd302f1efcb1f27d14bad468280a3a7994c2af75dfdf1e9fc5ef2373",
        "Threefish-512/CTR/NoPadding",
        "152df966484ecc2e9ddfc386559732f7f632e4008920804a1bde4efcf2e6e2f2",
        "Threefish-1024/CTR/NoPadding",
        "03953ac751a7377812c6e3e4d14b36c6953f9b390acaa892811c10001c9be454",
        "RC2/CTR/NoPadding",
        "0a07cb78537cb04c8c5a0a39a15977a7eb19f3c48a42759c234868c391a99c63",
        "RC5/CTR/NoPadding",
        "c62b233df296283b97f17364d5f69a1ff91f46659cf9856caefd322a936203a7",
        "IDEA/CTR/NoPadding",
        "dd447da3cbdcf81f4694ab7715d79e3f90af5682e8c318b8f7dadbed6b5c9714",
    };

    static String[] cipherTests2 =
    {
        "DES/OFB64/NoPadding",
        "537572e480c1714f5c9a4f3b874df824dc6681b1fd6c11982debcad91e",
        "DES/CFB64/NoPadding",
        "537572e480c1714fec3c7424f88d4202219244c5ca8f5e4361d64f08fe",
        "DES/CTR/NoPadding",
        "537572e480c1714fb47081d35eb18eaca9e0a5aee982f105438a0db6ce",
        "DES/CTS/NoPadding",
        "60fa2f8fae5aa2a38e9ac77d0246726b32df660db51a710ceb7511e451"
    };

    static String[] cipherTestsLargeBlock =
    {
        "Threefish-256",
        "9f82b577cf4cca7a504e9f7a2cd7dbb4ef4ac167c716fca19ab1211f195f610f" +
            "9f82b577cf4cca7a504e9f7a2cd7dbb4ef4ac167c716fca19ab1211f195f610f" +
            "9f82b577cf4cca7a504e9f7a2cd7dbb4ef4ac167c716fca19ab1211f195f610f" +
            "9f82b577cf4cca7a504e9f7a2cd7dbb4ef4ac167c716fca19ab1211f195f610f" +
             "31533aa864e6a40edc3e24b36260d94374893dc2e479793292e29c18a6ee01a9",
        "Threefish-512",
        "35d0c46770ebb3bf62fadd48765db209df215d7cd18a8b18d11625e70067e1fa" +
            "bb98982312ce1fdfccae1a59408e1d5418b400a7bf0d1c4e9ea4afa4395886d7" +
            "35d0c46770ebb3bf62fadd48765db209df215d7cd18a8b18d11625e70067e1fa" +
            "bb98982312ce1fdfccae1a59408e1d5418b400a7bf0d1c4e9ea4afa4395886d7" +
            "ad7ec86b2137af1ddb64794d714c4e1d7b687b19fc9781ef887a0ad7f88e18fc" +
            "1baa6123ec8bc497e7eb7b5090cfd756fd5333425ed5a240cb96735dea9713d9",
        "Threefish-1024",
        "df6d789e301c6a5e22e0cff0b44666630d44ce774a41b628ebaff6adc86d9e66" +
            "af50a282a4313552bc9b861cb286ab569e2e23b1c97cdb5cb1fde1bacfba9bfb" +
            "de3b443218e16b6038537b3d803ff5dbd26b13c177a5bfb597ffccca142a5905" +
            "8c0f74623daa96bff95b716674701034e7947ce0541426fa5177bc1a519b23ba" +
            "462f1724989612e49ca5e92a0129ec7be576846fe2616664674e16a29ce8679c" +
            "0adda9034fbd652910c2ae5afacde10281ab18dbeeb83464dc21ff66b0d358ff" +
            "2328c73aca59e9095a7bca94acc79d10038eab6ef865545bcf73f4caeeba1844" +
            "6add98350c8276e5abfb8709bb6c01ef3297b862818a4996b744f375b9126e5c",
        "Threefish-256/CBC/NoPadding",
        "1c46830ef0a43a0869bf070a87f0d4e63f2458edfa5654bafd8520358dae8bf9" +
            "2a8c039d41e87bb65a907331dde317450d38aba6cb3885bfbe0aee148503e37b" +
            "973c5e8a16c4309f7a4229d9943ab403082b5836431b9d1646b619f368e057b3" +
            "0931ce1b791b641dd3e79f2b536897f3c537e3b4588dc03c3888f9bab3bc7a0e",
        "Threefish-512/CBC/NoPadding",
        "caee9b663eba4663de1cd6f17ffc51dc8b808c95f91e12a818ab31436985830b" +
            "3aa886a93e53849d34e713f36db52bac3557b137328434f41f825f3948a611c6" +
            "03efe066d8d6d57b15b04729632de0ce5636b8ccd28219ac17ef836734556e15" +
            "e90356111279412a814b660150323a416138b2b62942f2d0cd08ee0bb45b0dd7",
        "Threefish-1024/CBC/NoPadding",
        "7540a8fe54a1a1d117ba1f970a12002cf9e24477daef9439dfc43b79a88a9e87" +
            "b59be63aa448b4e02e8b9a6464419c35b0b3f97219e6c88ed5429d0f9ffb40bb" +
            "491f280f4281af177e254828f82e90d196c6bf9afa31926cf5bf0cc3dc81f28a" +
            "419544ef5907f3b8bf6179da37ff07134d9c6d147521e5c840d5086ec74c1003",
        "Threefish-256/CBC/PKCS7Padding",
        "1c46830ef0a43a0869bf070a87f0d4e63f2458edfa5654bafd8520358dae8bf9" +
            "2a8c039d41e87bb65a907331dde317450d38aba6cb3885bfbe0aee148503e37b" +
            "973c5e8a16c4309f7a4229d9943ab403082b5836431b9d1646b619f368e057b3" +
            "0931ce1b791b641dd3e79f2b536897f3c537e3b4588dc03c3888f9bab3bc7a0e" +
            "f96cb468a5cd39a003f976464a7d072c94cb72a3fe739f101aa7b5452bc3fbba",
        "Threefish-512/CBC/PKCS7Padding",
        "caee9b663eba4663de1cd6f17ffc51dc8b808c95f91e12a818ab31436985830b" +
            "3aa886a93e53849d34e713f36db52bac3557b137328434f41f825f3948a611c6" +
            "03efe066d8d6d57b15b04729632de0ce5636b8ccd28219ac17ef836734556e15" +
            "e90356111279412a814b660150323a416138b2b62942f2d0cd08ee0bb45b0dd7" +
            "03902162280012e59efa15c6beecfbf440a6a0c4474bbbb2f74a0ad31bcd398f" +
            "b24728c3605a4ced3c92c30a5e231113abafaf6f83a3867978e3cdd74091d09f",
        "Threefish-1024/CBC/PKCS7Padding",
        "7540a8fe54a1a1d117ba1f970a12002cf9e24477daef9439dfc43b79a88a9e87" +
            "b59be63aa448b4e02e8b9a6464419c35b0b3f97219e6c88ed5429d0f9ffb40bb" +
            "491f280f4281af177e254828f82e90d196c6bf9afa31926cf5bf0cc3dc81f28a" +
            "419544ef5907f3b8bf6179da37ff07134d9c6d147521e5c840d5086ec74c1003" +
            "4ddd16ad731ad9a32d0f196a72284f7a8df98918e3e22f1708662edeb1810d2b" +
            "bafd4200e849f3288b55634b37f99f0f7b2dd192a5944fc211ef9e37b67a829b" +
            "005a5ec609f736875fdf8946bd79c1daa6c44c9d6733a2223cf8b7e5203b1cfd" +
            "76995f67e570d9c403b2a2e3f3a89c63c7850ee8d47d4398ac377345a139dda4",
        "Threefish-256/CTS/NoPadding",
        "1c46830ef0a43a0869bf070a87f0d4e63f2458edfa5654bafd8520358dae8bf9" +
            "2a8c039d41e87bb65a907331dde317450d38aba6cb3885bfbe0aee148503e37b" +
            "0931ce1b791b641dd3e79f2b536897f3c537e3b4588dc03c3888f9bab3bc7a0e" +
            "973c5e8a16c4309f7a4229d9943ab403082b5836431b9d1646b619f368e057b3",
        "Threefish-512/CTS/NoPadding",
        "03efe066d8d6d57b15b04729632de0ce5636b8ccd28219ac17ef836734556e15" +
            "e90356111279412a814b660150323a416138b2b62942f2d0cd08ee0bb45b0dd7" +
            "caee9b663eba4663de1cd6f17ffc51dc8b808c95f91e12a818ab31436985830b" +
            "3aa886a93e53849d34e713f36db52bac3557b137328434f41f825f3948a611c6",
        "Threefish-1024/CTS/NoPadding",
        "7540a8fe54a1a1d117ba1f970a12002cf9e24477daef9439dfc43b79a88a9e87b59b" +
        "e63aa448b4e02e8b9a6464419c35b0b3f97219e6c88ed5429d0f9ffb40bb491f280f" +
        "4281af177e254828f82e90d196c6bf9afa31926cf5bf0cc3dc81f28a419544ef5907" +
        "f3b8bf6179da37ff07134d9c6d147521e5c840d5086ec74c1003",
        "Threefish-256/CBC/WithCTS",
        "1c46830ef0a43a0869bf070a87f0d4e63f2458edfa5654bafd8520358dae8bf9" +
            "2a8c039d41e87bb65a907331dde317450d38aba6cb3885bfbe0aee148503e37b" +
            "0931ce1b791b641dd3e79f2b536897f3c537e3b4588dc03c3888f9bab3bc7a0e" +
            "973c5e8a16c4309f7a4229d9943ab403082b5836431b9d1646b619f368e057b3",
        "Threefish-512/CBC/WithCTS",
        "03efe066d8d6d57b15b04729632de0ce5636b8ccd28219ac17ef836734556e15" +
            "e90356111279412a814b660150323a416138b2b62942f2d0cd08ee0bb45b0dd7" +
            "caee9b663eba4663de1cd6f17ffc51dc8b808c95f91e12a818ab31436985830b" +
            "3aa886a93e53849d34e713f36db52bac3557b137328434f41f825f3948a611c6",
        "Threefish-1024/CBC/WithCTS",
        "7540a8fe54a1a1d117ba1f970a12002cf9e24477daef9439dfc43b79a88a9e87b59b" +
        "e63aa448b4e02e8b9a6464419c35b0b3f97219e6c88ed5429d0f9ffb40bb491f280f" +
        "4281af177e254828f82e90d196c6bf9afa31926cf5bf0cc3dc81f28a419544ef5907" +
        "f3b8bf6179da37ff07134d9c6d147521e5c840d5086ec74c1003",
        "Threefish-256/ECB/TBCPadding",
        "9f82b577cf4cca7a504e9f7a2cd7dbb4ef4ac167c716fca19ab1211f195f610f" +
            "9f82b577cf4cca7a504e9f7a2cd7dbb4ef4ac167c716fca19ab1211f195f610f" +
            "9f82b577cf4cca7a504e9f7a2cd7dbb4ef4ac167c716fca19ab1211f195f610f" +
            "9f82b577cf4cca7a504e9f7a2cd7dbb4ef4ac167c716fca19ab1211f195f610f" +
            "89c4e79b90153a821bdd4efd5eb1e2cda89b6a91540a003eef03868472d8cfce",
        "Threefish-512/ECB/TBCPadding",
        "35d0c46770ebb3bf62fadd48765db209df215d7cd18a8b18d11625e70067e1fa" +
            "bb98982312ce1fdfccae1a59408e1d5418b400a7bf0d1c4e9ea4afa4395886d7" +
            "35d0c46770ebb3bf62fadd48765db209df215d7cd18a8b18d11625e70067e1fa" +
            "bb98982312ce1fdfccae1a59408e1d5418b400a7bf0d1c4e9ea4afa4395886d7" +
            "dd6bfa1006e4df51298e382ca397a2c398cdb4d65009dce77c5f0a31f9807218" +
            "a72372a8a0df3b1bacd5dbfb116ebbe314e0b0cd64fd2c8ae8a81491c2534a2a",
        "Threefish-1024/ECB/TBCPadding",
        "df6d789e301c6a5e22e0cff0b44666630d44ce774a41b628ebaff6adc86d9e66" +
            "af50a282a4313552bc9b861cb286ab569e2e23b1c97cdb5cb1fde1bacfba9bfb" +
            "de3b443218e16b6038537b3d803ff5dbd26b13c177a5bfb597ffccca142a5905" +
            "8c0f74623daa96bff95b716674701034e7947ce0541426fa5177bc1a519b23ba" +
            "7312262dc3a25984847d1b05cb624f5751946f136ee7bd0a9a4bbac5dd3bd213" +
            "702390d3a53d1a4132f59383cce4fe61e08cd3c73c570190d1c8b60940031ef7" +
            "42f6775b00fb0b4273a14b46a3fc0e760e02f75dc6100ca9c038c3f151e03145" +
            "92686fd8cccbee74d246a8c59ad80205c9f9aaeb100ea5812837ee8699753301",
    };

    static byte[]   input1 = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f");
    static byte[]   input2 = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c");
    static byte[]   inputLargeBlock = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f" +
                                                 "000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f" +
                                                 "000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f" +
                                                 "000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f");

    static RC2ParameterSpec rc2Spec = new RC2ParameterSpec(128, Hex.decode("0123456789abcdef"));
    static RC5ParameterSpec rc5Spec = new RC5ParameterSpec(16, 16, 32, Hex.decode("0123456789abcdef"));
    static RC5ParameterSpec rc564Spec = new RC5ParameterSpec(16, 16, 64, Hex.decode("0123456789abcdef0123456789abcdef"));

    /**
     * a fake random number generator - we just want to make sure the random numbers
     * aren't random so that we get the same output, while still getting to test the
     * key generation facilities.
     */
    private class FixedSecureRandom
        extends SecureRandom
    {
        byte[]  seed = {
                (byte)0xaa, (byte)0xfd, (byte)0x12, (byte)0xf6, (byte)0x59,
                (byte)0xca, (byte)0xe6, (byte)0x34, (byte)0x89, (byte)0xb4,
                (byte)0x79, (byte)0xe5, (byte)0x07, (byte)0x6d, (byte)0xde,
                (byte)0xc2, (byte)0xf0, (byte)0x6c, (byte)0xb5, (byte)0x8f
        };

        public void nextBytes(
            byte[]  bytes)
        {
            int offset = 0;

            while ((offset + seed.length) < bytes.length)
            {
                System.arraycopy(seed, 0, bytes, offset, seed.length);
                offset += seed.length;
            }

            System.arraycopy(seed, 0, bytes, offset, bytes.length - offset);
        }
    }

    public String getName()
    {
        return "BlockCipher";
    }

    public void test(
        String      algorithm,
        byte[]      input,
        byte[]      output)
    {
        Key                     key = null;
        KeyGenerator            keyGen;
        SecureRandom            rand;
        Cipher                  in = null;
        Cipher                  out = null;
        CipherInputStream       cIn;
        CipherOutputStream      cOut;
        ByteArrayInputStream    bIn;
        ByteArrayOutputStream   bOut;

        rand = new FixedSecureRandom();

        try
        {
            String  baseAlgorithm;
            int     index = algorithm.indexOf('/');

            if (index > 0)
            {
                baseAlgorithm = algorithm.substring(0, index);
            }
            else
            {
                baseAlgorithm = algorithm;
            }

            if (baseAlgorithm.equals("IDEA") & noIDEA())
            {
                return;
            }

            keyGen = KeyGenerator.getInstance(baseAlgorithm, "BC");
            if (!keyGen.getAlgorithm().equals(baseAlgorithm))
            {
                fail("wrong key generator returned!");
            }
            keyGen.init(rand);

            key = keyGen.generateKey();

            in = Cipher.getInstance(algorithm, "BC");
            out = Cipher.getInstance(algorithm, "BC");

            if (!in.getAlgorithm().startsWith(baseAlgorithm))
            {
                fail("wrong cipher returned!");
            }

            if (algorithm.startsWith("RC2"))
            {
                out.init(Cipher.ENCRYPT_MODE, key, rc2Spec, rand);
            }
            else if (algorithm.startsWith("RC5"))
            {
                if (algorithm.startsWith("RC5-64"))
                {
                    out.init(Cipher.ENCRYPT_MODE, key, rc564Spec, rand);
                }
                else
                {
                    out.init(Cipher.ENCRYPT_MODE, key, rc5Spec, rand);
                }
            }
            else
            {
                out.init(Cipher.ENCRYPT_MODE, key, rand);
            }
        }
        catch (Exception e)
        {
            fail("" + algorithm + " failed initialisation - " + e.toString(), e);
        }

        //
        // grab the iv if there is one
        //
        try
        {
            if (algorithm.startsWith("RC2"))
            {
                in.init(Cipher.DECRYPT_MODE, key, rc2Spec);
            }
            else if (algorithm.startsWith("RC5"))
            {
                if (algorithm.startsWith("RC5-64"))
                {
                    in.init(Cipher.DECRYPT_MODE, key, rc564Spec, rand);
                }
                else
                {
                    in.init(Cipher.DECRYPT_MODE, key, rc5Spec, rand);
                }
            }
            else
            {
                byte[]    iv;

                iv = out.getIV();
                if (iv != null)
                {
                    try
                    {
                        byte[]  nIv = new byte[iv.length - 1];

                        in.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nIv));
                        fail("failed to pick up short IV");
                    }
                    catch (InvalidAlgorithmParameterException e)
                    {
                        // ignore - this is what we want...
                    }

                    IvParameterSpec    spec;

                    spec = new IvParameterSpec(iv);

                    in.init(Cipher.DECRYPT_MODE, key, spec);
                }
                else
                {
                    in.init(Cipher.DECRYPT_MODE, key);
                }
            }
        }
        catch (Exception e)
        {
            fail("" + algorithm + " failed initialisation - " + e.toString());
        }

        //
        // encryption pass
        //
        bOut = new ByteArrayOutputStream();

        cOut = new CipherOutputStream(bOut, out);

        try
        {
            for (int i = 0; i != input.length / 2; i++)
            {
                cOut.write(input[i]);
            }
            cOut.write(input, input.length / 2, input.length - input.length / 2);
            cOut.close();
        }
        catch (IOException e)
        {
            fail("" + algorithm + " failed encryption - " + e.toString());
        }

        byte[]    bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output))
        {
            fail("" + algorithm + " failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // decryption pass
        //
        bIn = new ByteArrayInputStream(bytes);

        cIn = new CipherInputStream(bIn, in);

        try
        {
            DataInputStream dIn = new DataInputStream(cIn);

            bytes = new byte[input.length];

            for (int i = 0; i != input.length / 2; i++)
            {
                bytes[i] = (byte)dIn.read();
            }
            dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);
        }
        catch (Exception e)
        {
            fail("" + algorithm + " failed decryption - " + e.toString());
        }

        if (!areEqual(bytes, input))
        {
            fail("" + algorithm + " failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }
    }

    private boolean noIDEA()
    {
        try
        {
            Cipher.getInstance("IDEA", "BC");

            return false;
        }
        catch (Exception e)
        {
            return true;
        }
    }

    private void testExceptions()
    {
        SecretKeyFactory skF = null;
        
        try
        {
            skF = SecretKeyFactory.getInstance("DESede", "BC");
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }
        
        KeySpec ks = null;
        SecretKey secKey = null;
        byte[] bb = new byte[24];

        try
        {
            skF.getKeySpec(null, null);
            
            fail("failed exception test - no exception thrown");
        }
        catch (InvalidKeySpecException e)
        {
            // ignore okay
        }
        catch (Exception e)
        {
            fail("failed exception test.", e);
        }
        try
        {
            ks = (KeySpec)new DESedeKeySpec(bb);
            skF.getKeySpec(null, ks.getClass());
            
            fail("failed exception test - no exception thrown");
        }
        catch (InvalidKeySpecException e)
        {
            // ignore okay;
        }
        catch (Exception e)
        {
            fail("failed exception test.", e);
        }
        try
        {
            skF.getKeySpec(secKey, null);
        }
        catch (InvalidKeySpecException e)
        {
            // ignore okay
        }
        catch (Exception e)
        {
            fail("failed exception test.", e);
        }
        
        try
        {
            KeyGenerator kg = KeyGenerator.getInstance("DESede", "BC");
            try
            {
                kg.init(Integer.MIN_VALUE, new SecureRandom());
                
                fail("failed exception test - no exception thrown");
            }
            catch (InvalidParameterException e)
            {
                // ignore okay
            }
            catch (Exception e)
            {
                fail("failed exception test.", e);
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }

        try
        {
            skF = SecretKeyFactory.getInstance("DESede", "BC");

            try
            {
                skF.translateKey(null);
                
                fail("failed exception test - no exception thrown");
            }
            catch (InvalidKeyException e)
            {
                // ignore okay
            }
            catch (Exception e)
            {
                fail("failed exception test.", e);
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }
        
        try
        {
            byte[] rawDESKey = { (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143 };

            SecretKeySpec cipherKey = new SecretKeySpec(rawDESKey, "DES");

            Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding", "BC");
            
            try
            {
                // According specification engineInit(int opmode, Key key,
                // SecureRandom random) throws InvalidKeyException if this
                // cipher is being
                // initialized for decryption and requires algorithm parameters
                // that cannot be determined from the given key
                cipher.init(Cipher.DECRYPT_MODE, cipherKey, (SecureRandom)null);
                
                fail("failed exception test - no InvalidKeyException thrown");
            }
            catch (InvalidKeyException e)
            {
                // ignore
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }

        try
        {
            byte[] rawDESKey = { -128, -125, -123, -122, -119, -118 };

            SecretKeySpec cipherKey = new SecretKeySpec(rawDESKey, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding", "BC");
            try
            {
                // According specification engineInit(int opmode, Key key,
                // SecureRandom random) throws InvalidKeyException if the given
                // key is inappropriate for initializing this cipher
                cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
                
                fail("failed exception test - no InvalidKeyException thrown");
            }
            catch (InvalidKeyException e)
            {
                // ignore
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }

        try
        {
            byte[] rawDESKey = { -128, -125, -123, -122, -119, -118, -117, -115, -114 };

            SecretKeySpec cipherKey = new SecretKeySpec(rawDESKey, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding", "BC");
            try
            {
                // According specification engineInit(int opmode, Key key,
                // SecureRandom random) throws InvalidKeyException if the given
                // key is inappropriate for initializing this cipher
                cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
                
                fail("failed exception test - no InvalidKeyException thrown");
            }
            catch (InvalidKeyException e)
            {
                // ignore
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }
        

        try
        {
            byte[] rawDESKey = { (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143 };

            SecretKeySpec cipherKey = new SecretKeySpec(rawDESKey, "DES");
            Cipher ecipher = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
            ecipher.init(Cipher.ENCRYPT_MODE, cipherKey);

            byte[] cipherText = new byte[0];
            try
            {
                // According specification Method engineUpdate(byte[] input,
                // int inputOffset, int inputLen, byte[] output, int
                // outputOffset)
                // throws ShortBufferException - if the given output buffer is
                // too
                // small to hold the result
                ecipher.update(new byte[20], 0, 20, cipherText);
                
                fail("failed exception test - no ShortBufferException thrown");
            }
            catch (ShortBufferException e)
            {
                // ignore
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }

        try
        {
            byte[] rawDESKey = { (byte)128, (byte)131, (byte)133, (byte)134,
                    (byte)137, (byte)138, (byte)140, (byte)143 };

            SecretKeySpec cipherKey = new SecretKeySpec(rawDESKey, "DES");
            Cipher ecipher = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
            ecipher.init(Cipher.ENCRYPT_MODE, cipherKey);

            byte[] cipherText = new byte[0];
            try
            {
                // According specification Method enginedoFinal(byte[] input,
                // int inputOffset, int inputLen, byte[] output, int
                // outputOffset)
                // throws ShortBufferException - if the given output buffer is
                // too
                // small to hold the result
                ecipher.doFinal(new byte[20], 0, 20, cipherText);

                fail("failed exception test - no ShortBufferException thrown");
            }
            catch (ShortBufferException e)
            {
                // ignore
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }

        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance("DES", "BC");

            keyGen.init((SecureRandom)null);

            // According specification engineGenerateKey() doesn't throw any exceptions.

            SecretKey key = keyGen.generateKey();
            if (key == null)
            {
                fail("key is null!");
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }

        try
        {
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("DES", "BC");
            
            algParams.init(new IvParameterSpec(new byte[8]));

            // According specification engineGetEncoded() returns
            // the parameters in their primary encoding format. The primary
            // encoding
            // format for parameters is ASN.1, if an ASN.1 specification for
            // this type
            // of parameters exists.
            byte[] iv = algParams.getEncoded();
            
            if (iv.length != 10)
            {
                fail("parameters encoding wrong length - "  + iv.length);
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }

        try
        {
            try
            {
                AlgorithmParameters algParams = AlgorithmParameters.getInstance("DES", "BC");
    
                byte[] encoding = new byte[10];
                encoding[0] = 3;
                encoding[1] = 8;
    
                // According specification engineInit(byte[] params, String format)
                // throws
                // IOException on decoding errors, but BC throws ClassCastException.
                algParams.init(encoding, "ASN.1");
    
                fail("failed exception test - no IOException thrown");
            }
            catch (IOException e)
            {
                // okay
            }
            
            try
            {
                Cipher c = Cipher.getInstance("DES", "BC");
    
                Key k = new PublicKey()
                {

                    public String getAlgorithm()
                    {
                        return "STUB";
                    }

                    public String getFormat()
                    {
                        return null;
                    }

                    public byte[] getEncoded()
                    {
                        return null;
                    }
                    
                };
    
                c.init(Cipher.ENCRYPT_MODE, k);
    
                fail("failed exception test - no InvalidKeyException thrown for public key");
            }
            catch (InvalidKeyException e)
            {
                // okay
            }
            
            try
            {
                Cipher c = Cipher.getInstance("DES", "BC");
    
                Key k = new PrivateKey()
                {

                    public String getAlgorithm()
                    {
                        return "STUB";
                    }

                    public String getFormat()
                    {
                        return null;
                    }

                    public byte[] getEncoded()
                    {
                        return null;
                    }
                    
                };
    
                c.init(Cipher.DECRYPT_MODE, k);
    
                fail("failed exception test - no InvalidKeyException thrown for private key");
            }
            catch (InvalidKeyException e)
            {
                // okay
            }
        }
        catch (Exception e)
        {
            fail("unexpected exception.", e);
        }
    }
    
    public void performTest()
    {
        for (int i = 0; i != cipherTests1.length; i += 2)
        {
            test(cipherTests1[i], input1, Hex.decode(cipherTests1[i + 1]));
        }

        for (int i = 0; i != cipherTests2.length; i += 2)
        {
            test(cipherTests2[i], input2, Hex.decode(cipherTests2[i + 1]));
        }

        for (int i = 0; i != cipherTestsLargeBlock.length; i += 2)
        {
            test(cipherTestsLargeBlock[i], inputLargeBlock, Hex.decode(cipherTestsLargeBlock[i + 1]));
        }

        //
        // check for less than a block
        //
        try
        {
            Cipher c = Cipher.getInstance("AES/CTS/NoPadding", "BC");
            
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));
            
            c.doFinal(new byte[4]);
            
            fail("CTS failed to throw exception");
        }
        catch (Exception e)
        {
            if (!(e instanceof IllegalBlockSizeException))
            {
                fail("CTS exception test - " + e, e);
            }
        }
        
        testExceptions();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BlockCipherTest());
    }
}
