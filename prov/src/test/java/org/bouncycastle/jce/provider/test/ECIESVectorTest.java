package org.bouncycastle.jce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test for ECIES - Elliptic Curve Integrated Encryption Scheme
 */
public class ECIESVectorTest
    extends SimpleTest
{
    static byte[] message = Hex.decode("0102030405060708090a0b0c0d0e0f10111213141516");

    static byte[] derivation1 = Hex.decode("202122232425262728292a2b2c2d2e2f");
    static byte[] derivation2 = Hex.decode("202122232425262728292a2b2c2d2e2f404142434445464748");

    static byte[] encoding1 = Hex.decode("af");
    static byte[] encoding2 = Hex.decode("303132333435363738393a3b3c3d3e3f");
    static byte[] encoding3 = Hex.decode("101112131415161718191a1b1c1d1e1f303132333435363738393a3b3c3d3e3f");

    static byte[] p256_1_pub = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGVoxUX5AiyggqzcaXG3yG6cH6PKSX6fVOnCo5SKolfR8kwc6S8zmADXlpnjzMLNUVvGDL805VKIXNJHijq4+gw==");
    static byte[] p256_1_pri = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg+dn4oLSJcx5lxZhVxJCip13O/OblrNzNyCj2b9sNbQegCgYIKoZIzj0DAQehRANCAAQZWjFRfkCLKCCrNxpcbfIbpwfo8pJfp9U6cKjlIqiV9HyTBzpLzOYANeWmePMws1RW8YMvzTlUohc0keKOrj6D");
    static byte[] p256_1_eph = Hex.decode("35ee388194396b5febbddb7e3618eaaba44f3bae766dac70f75ae7b84b210948");

    static byte[] p256_1_no_params = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae43dfbe605c746ba0c546c0c25ba5a00304587fbed07a35ca06415cf6ad4d6a69d01122c99e2c854fe818f");

    static byte[] p256_1_with_params11 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4a57474b50621e97254c1f3b32635f694feb57e873a33c5d1948ee93ea5dc7577d42d7c2e41ab08f85835");
    static byte[] p256_1_with_params12 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4a57474b50621e97254c1f3b32635f694feb57e873a3394725300acb7855f71a149d3f51a2e6fbd7f5389");
    static byte[] p256_1_with_params13 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4a57474b50621e97254c1f3b32635f694feb57e873a33920872328f8d05ec561ba8c6e58d82b79c360078");
    static byte[] p256_1_with_params21 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4da4d2bb723cd2ca918d1835dc2716a767085facd5df4499a4f4b6726651fb5e88178f01d831d9e5be0c1");
    static byte[] p256_1_with_params22 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4da4d2bb723cd2ca918d1835dc2716a767085facd5df457c384a0e6402a5bb073120f08c706b49a4775d0");
    static byte[] p256_1_with_params23 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4da4d2bb723cd2ca918d1835dc2716a767085facd5df4039427c24c55a2627df0ebea00f9d1eded9dd64b");

    static byte[] p256_2_pub = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER4gx8nnRAkP+u76j0COZD81Cu9CTw3vczLnu1DG7ObI/VCzrDzJuswfzNWmxOFYXiXmZMAAkkEFA40nDSGOoqA==");
    static byte[] p256_2_pri = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgkflw6MQj4RbyuPFHoDE3i1dEaROS9uDSjGvrvPjqL7mgCgYIKoZIzj0DAQehRANCAARHiDHyedECQ/67vqPQI5kPzUK70JPDe9zMue7UMbs5sj9ULOsPMm6zB/M1abE4VheJeZkwACSQQUDjScNIY6io");
    static byte[] p256_2_eph = Hex.decode("0c37e1e0559a60d0b9c5b7b139a3f2df022b23abbd194bd95c8eff0aab1fd544");

    static byte[] p256_2_no_params = Hex.decode("04d1ef981f81edae5e2e517b498504105b636d950cc13a9e1e31c607d8f0adc00c2152f2abae4870274f8788c08be35a7908f5547416405f24818ef4e8e3ae8dacd99a5cadfe82652a18c6058fc5ef7ffca626235fdbf7e2537f494d049d6f4e53d3d3df489cefb31101e1");

    static byte[] p256_2_with_params11 = Hex.decode("04d1ef981f81edae5e2e517b498504105b636d950cc13a9e1e31c607d8f0adc00c2152f2abae4870274f8788c08be35a7908f5547416405f24818ef4e8e3ae8dace0e423753f63e054824edbc298a5645d7a4010cc7e65947090625dc0d750c50b2d563f264718d95818d4");
    static byte[] p256_2_with_params12 = Hex.decode("04d1ef981f81edae5e2e517b498504105b636d950cc13a9e1e31c607d8f0adc00c2152f2abae4870274f8788c08be35a7908f5547416405f24818ef4e8e3ae8dace0e423753f63e054824edbc298a5645d7a4010cc7e6502850f65c7a2c466444dea69d95a2df9a4b6cf2c");
    static byte[] p256_2_with_params13 = Hex.decode("04d1ef981f81edae5e2e517b498504105b636d950cc13a9e1e31c607d8f0adc00c2152f2abae4870274f8788c08be35a7908f5547416405f24818ef4e8e3ae8dace0e423753f63e054824edbc298a5645d7a4010cc7e651188a654e47322a60e53ea20a9e02f0e78bf8a32");
    static byte[] p256_2_with_params21 = Hex.decode("04d1ef981f81edae5e2e517b498504105b636d950cc13a9e1e31c607d8f0adc00c2152f2abae4870274f8788c08be35a7908f5547416405f24818ef4e8e3ae8dacdbdbe5e5f72245f4b5c28ee1ae21442868aef592d4047c8149babf4e7faffb5474bd6d84d6b9f1c9faf5");
    static byte[] p256_2_with_params22 = Hex.decode("04d1ef981f81edae5e2e517b498504105b636d950cc13a9e1e31c607d8f0adc00c2152f2abae4870274f8788c08be35a7908f5547416405f24818ef4e8e3ae8dacdbdbe5e5f72245f4b5c28ee1ae21442868aef592d40471190bd9b4bddd63983e4963378c9f55c703a7e6");
    static byte[] p256_2_with_params23 = Hex.decode("04d1ef981f81edae5e2e517b498504105b636d950cc13a9e1e31c607d8f0adc00c2152f2abae4870274f8788c08be35a7908f5547416405f24818ef4e8e3ae8dacdbdbe5e5f72245f4b5c28ee1ae21442868aef592d404ca4307e077a693c6410815c7985b0678a42cbd84");
    
    static byte[] p521_1_pub = Base64.decode("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBLNtLEbQBq2YGA2Q+eCwulIDggr1dCj8CqY/Yj/HuzicYGmVkNpr/gRfZHX4FRrh9HsGrS7tW+UA1pCQmn3p3aeEADiaXGIybDBsnuU20xntomQG/d/OHDkEaPee9nFNbi9Oha7BHTA/x2yyLMhQHeUlMgjz0DQqRxrwGJmvI85eNZpM=");
    static byte[] p521_1_pri = Base64.decode("MIH3AgEAMBAGByqGSM49AgEGBSuBBAAjBIHfMIHcAgEBBEIA1QAfnUvK1fAaENAArV0YnNGvnu2H1vGHNgsG3QV7p16gjd6UOgmGCZVM9SLlRH3fi9K1Xreyl4sQH3NeY+ZnInqgBwYFK4EEACOhgYkDgYYABAEs20sRtAGrZgYDZD54LC6UgOCCvV0KPwKpj9iP8e7OJxgaZWQ2mv+BF9kdfgVGuH0ewatLu1b5QDWkJCafendp4QAOJpcYjJsMGye5TbTGe2iZAb9384cOQRo9572cU1uL06FrsEdMD/HbLIsyFAd5SUyCPPQNCpHGvAYma8jzl41mkw==");
    static byte[] p521_1_eph = Hex.decode("d25c44819712555824360eef5afda947373ec462c2a0fd5bebbe0b0e4e40b4ebf483bc5b5eeb84542fc226dc2e5307ceec59fe7c557522b77589210b434295aabfc7");

    static byte[] p521_1_no_params = Hex.decode("04009d332615586356df7caaabb4ddd1c7902f35595c0a708acf570659061313e44a5d581b0e646e0c623b737327ed2a6fb7391ed76ee5fdceb9480f8b414e37be786301f7f6162afa812f45c15aba6887c6559b4c379c98fddd95af179c457a6a0e414cd921fd3b5736068f2ce6bec2fbf28e0e230784a38bf6f7b6e42672e52959db1b7ee2102423e67f5ee7f46e87a26370b7734548f3baee7729c5ff1c1638b93f068628320c7c56b7a68fb86d");

    static byte[] p521_1_with_params11 = Hex.decode("04009d332615586356df7caaabb4ddd1c7902f35595c0a708acf570659061313e44a5d581b0e646e0c623b737327ed2a6fb7391ed76ee5fdceb9480f8b414e37be786301f7f6162afa812f45c15aba6887c6559b4c379c98fddd95af179c457a6a0e414cd921fd3b5736068f2ce6bec2fbf28e0e230784a38bf6f7b6e42672e52959db1b7e49225382108fb5bdd6b4ad57fee63c2819d10c1bc7517bd0a5070c123d4e24d66f9f0bf21ec105629cb2");
    static byte[] p521_1_with_params12 = Hex.decode("04009d332615586356df7caaabb4ddd1c7902f35595c0a708acf570659061313e44a5d581b0e646e0c623b737327ed2a6fb7391ed76ee5fdceb9480f8b414e37be786301f7f6162afa812f45c15aba6887c6559b4c379c98fddd95af179c457a6a0e414cd921fd3b5736068f2ce6bec2fbf28e0e230784a38bf6f7b6e42672e52959db1b7e49225382108fb5bdd6b4ad57fee63c2819d10c1bc751a51c6c78d905b0b7702d2edf89d0cf30f0d21c93");
    static byte[] p521_1_with_params13 = Hex.decode("04009d332615586356df7caaabb4ddd1c7902f35595c0a708acf570659061313e44a5d581b0e646e0c623b737327ed2a6fb7391ed76ee5fdceb9480f8b414e37be786301f7f6162afa812f45c15aba6887c6559b4c379c98fddd95af179c457a6a0e414cd921fd3b5736068f2ce6bec2fbf28e0e230784a38bf6f7b6e42672e52959db1b7e49225382108fb5bdd6b4ad57fee63c2819d10c1bc7513a9fb7f21f78ef3467b54153b8e2998de5f46724");
    static byte[] p521_1_with_params21 = Hex.decode("04009d332615586356df7caaabb4ddd1c7902f35595c0a708acf570659061313e44a5d581b0e646e0c623b737327ed2a6fb7391ed76ee5fdceb9480f8b414e37be786301f7f6162afa812f45c15aba6887c6559b4c379c98fddd95af179c457a6a0e414cd921fd3b5736068f2ce6bec2fbf28e0e230784a38bf6f7b6e42672e52959db1b7e1e0e7ac9ade1646519a365ef578f0bbe3556a818c83a0ce6226db7a3f3964e7a18955f9150fb030dcb09");
    static byte[] p521_1_with_params22 = Hex.decode("04009d332615586356df7caaabb4ddd1c7902f35595c0a708acf570659061313e44a5d581b0e646e0c623b737327ed2a6fb7391ed76ee5fdceb9480f8b414e37be786301f7f6162afa812f45c15aba6887c6559b4c379c98fddd95af179c457a6a0e414cd921fd3b5736068f2ce6bec2fbf28e0e230784a38bf6f7b6e42672e52959db1b7e1e0e7ac9ade1646519a365ef578f0bbe3556a818c83ade9180b72d7d2e9218395ea7d83c00cf03c6b39d");
    static byte[] p521_1_with_params23 = Hex.decode("04009d332615586356df7caaabb4ddd1c7902f35595c0a708acf570659061313e44a5d581b0e646e0c623b737327ed2a6fb7391ed76ee5fdceb9480f8b414e37be786301f7f6162afa812f45c15aba6887c6559b4c379c98fddd95af179c457a6a0e414cd921fd3b5736068f2ce6bec2fbf28e0e230784a38bf6f7b6e42672e52959db1b7e1e0e7ac9ade1646519a365ef578f0bbe3556a818c83a605f2a4ef486f9215e546d618eb7624443ee1a7d");

    static byte[] p521_2_pub = Base64.decode("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQACXj0hmGm68PQxI12y5sKMn4mN6mIMOEn1l6PBOeGtk8QuJHt1AS3X5DcPorJTxhuhdcdDHA3if1utfAw9hl7tCIBQELwgw2Vo3gYkdbG7Hj6O9kf8WpqIEJ3UsC4S0hITMY1knO41BaO4UdO+nUiN+PZPRRSqFwm3C5v3fffLSGbpIQ=");
    static byte[] p521_2_pri = Base64.decode("MIH3AgEAMBAGByqGSM49AgEGBSuBBAAjBIHfMIHcAgEBBEIB6s6VR/8WgiOvSjHT/n5Y91wESyI9e4GABUNWMXMPhNspwb9++7fyanbeliHNz9K61SjDG7rLXs90K1iRvHPJwmygBwYFK4EEACOhgYkDgYYABAAJePSGYabrw9DEjXbLmwoyfiY3qYgw4SfWXo8E54a2TxC4ke3UBLdfkNw+islPGG6F1x0McDeJ/W618DD2GXu0IgFAQvCDDZWjeBiR1sbsePo72R/xamogQndSwLhLSEhMxjWSc7jUFo7hR076dSI349k9FFKoXCbcLm/d998tIZukhA==");
    static byte[] p521_2_eph = Hex.decode("c9ee178c7f200a51a0053931c697001205f8923fd04b538c3fd5df2be43a6f304581f57138906bba0be631f7e0fd2804d00b5cb053559f080c13c913358f6e1fcc6d");

    static byte[] p521_2_no_params = Hex.decode("0400ddfd813bbba275fec8896a140036c9ee2fee49793cadc0a4d976d1b7827357b846e1e5aa9326b449c6ab268e3b2d145894cc02d33d849c108db1f696db6e867c2c01d129fcc80937aeb2beff58ebc9e9777ba864546aed12d86c5e6a89767cf5321ec323283032278698642c238b3fda4a5d5e9ea2f0b91ef7d979fda529687931ace65922842dba0351c1cebde53ee4ba9afadbd3a03a88507046f62c7383f96142c09df58be5b0a661893d41");

    static byte[] p521_2_with_params11 = Hex.decode("0400ddfd813bbba275fec8896a140036c9ee2fee49793cadc0a4d976d1b7827357b846e1e5aa9326b449c6ab268e3b2d145894cc02d33d849c108db1f696db6e867c2c01d129fcc80937aeb2beff58ebc9e9777ba864546aed12d86c5e6a89767cf5321ec323283032278698642c238b3fda4a5d5e9ea2f0b91ef7d979fda529687931ace674ccf084d69e0bc9a728548d887a162ddf53a0002ed034b51a5406b831ce9ea713be7df54934b77dcc84");
    static byte[] p521_2_with_params12 = Hex.decode("0400ddfd813bbba275fec8896a140036c9ee2fee49793cadc0a4d976d1b7827357b846e1e5aa9326b449c6ab268e3b2d145894cc02d33d849c108db1f696db6e867c2c01d129fcc80937aeb2beff58ebc9e9777ba864546aed12d86c5e6a89767cf5321ec323283032278698642c238b3fda4a5d5e9ea2f0b91ef7d979fda529687931ace674ccf084d69e0bc9a728548d887a162ddf53a0002ed0767534663184e99c0958451ea417729e29e02a60");
    static byte[] p521_2_with_params13 = Hex.decode("0400ddfd813bbba275fec8896a140036c9ee2fee49793cadc0a4d976d1b7827357b846e1e5aa9326b449c6ab268e3b2d145894cc02d33d849c108db1f696db6e867c2c01d129fcc80937aeb2beff58ebc9e9777ba864546aed12d86c5e6a89767cf5321ec323283032278698642c238b3fda4a5d5e9ea2f0b91ef7d979fda529687931ace674ccf084d69e0bc9a728548d887a162ddf53a0002ed0517e1040bf7d57f2c8f9c3ce69e5a05a9a292700");
    static byte[] p521_2_with_params21 = Hex.decode("0400ddfd813bbba275fec8896a140036c9ee2fee49793cadc0a4d976d1b7827357b846e1e5aa9326b449c6ab268e3b2d145894cc02d33d849c108db1f696db6e867c2c01d129fcc80937aeb2beff58ebc9e9777ba864546aed12d86c5e6a89767cf5321ec323283032278698642c238b3fda4a5d5e9ea2f0b91ef7d979fda529687931ace68a9e28bb5d49c07d5f5f59a27311619103aea50e48ddc66e0f20686c8d0c329db510facc1c014f800920");
    static byte[] p521_2_with_params22 = Hex.decode("0400ddfd813bbba275fec8896a140036c9ee2fee49793cadc0a4d976d1b7827357b846e1e5aa9326b449c6ab268e3b2d145894cc02d33d849c108db1f696db6e867c2c01d129fcc80937aeb2beff58ebc9e9777ba864546aed12d86c5e6a89767cf5321ec323283032278698642c238b3fda4a5d5e9ea2f0b91ef7d979fda529687931ace68a9e28bb5d49c07d5f5f59a27311619103aea50e48ddbc970a66c80886782713e25ece75a23dec995121");
    static byte[] p521_2_with_params23 = Hex.decode("0400ddfd813bbba275fec8896a140036c9ee2fee49793cadc0a4d976d1b7827357b846e1e5aa9326b449c6ab268e3b2d145894cc02d33d849c108db1f696db6e867c2c01d129fcc80937aeb2beff58ebc9e9777ba864546aed12d86c5e6a89767cf5321ec323283032278698642c238b3fda4a5d5e9ea2f0b91ef7d979fda529687931ace68a9e28bb5d49c07d5f5f59a27311619103aea50e48dd7c3d8a51a95f88813d04a0c681355f6e86bb44e5");

    static byte[] old_p256_1_no_params = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae43dfbe605c746ba0c546c0c25ba5a00304587fbed07a3ebe44837c43b86025cc08e333b1631a8227b8d49");

    static byte[] old_p256_1_with_params11 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4a57474b50621e97254c1f3b32635f694feb57e873a332ce23d272262d47a528057eb5b0b11631707b28f");
    static byte[] old_p256_1_with_params12 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4a57474b50621e97254c1f3b32635f694feb57e873a3331e3e514868c771270632c9a9b852f2060d415da");
    static byte[] old_p256_1_with_params13 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4a57474b50621e97254c1f3b32635f694feb57e873a3353e10e6260e937bcdd244201a0de1d3941439076");
    static byte[] old_p256_1_with_params21 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4da4d2bb723cd2ca918d1835dc2716a767085facd5df4912a36ccc3c49de7d3d6b1fb312aeacf2d0b30e7");
    static byte[] old_p256_1_with_params22 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4da4d2bb723cd2ca918d1835dc2716a767085facd5df4171c056b90a3badd0bb689403ab214546b5f6411");
    static byte[] old_p256_1_with_params23 = Hex.decode("04bc8f4da6ea423c0698744b927ec71b67126d97ef9dd804c141a0dfcb466cc1c7df25539375ddb3ae7d08cc46fa2a78434c9f6123b108e39a5fe614729c3d8ae4da4d2bb723cd2ca918d1835dc2716a767085facd5df4ad1a6a561fe0582495cd14ac4494e4610ecddef1");

    ECIESVectorTest()
    {
    }

    public String getName()
    {
        return "ECIESVectorTest";
    }

    public void performTest()
        throws Exception
    {
        KeyFactory ecFact = KeyFactory.getInstance("EC", "BC");

        KeyPair keyPair = new KeyPair(ecFact.generatePublic(new X509EncodedKeySpec(p256_1_pub)), ecFact.generatePrivate(new PKCS8EncodedKeySpec(p256_1_pri)));

        doTestNoParams("ECIES with P-256 None", keyPair, "ECIES", p256_1_eph, p256_1_no_params);
        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "ECIES", p256_1_eph, new IESParameterSpec(derivation1, encoding1, 128), p256_1_with_params11);
        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "ECIES", p256_1_eph, new IESParameterSpec(derivation1, encoding2, 128), p256_1_with_params12);
        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "ECIES", p256_1_eph, new IESParameterSpec(derivation1, encoding3, 128), p256_1_with_params13);
        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "ECIES", p256_1_eph, new IESParameterSpec(derivation2, encoding1, 128), p256_1_with_params21);
        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "ECIES", p256_1_eph, new IESParameterSpec(derivation2, encoding2, 128), p256_1_with_params22);
        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "ECIES", p256_1_eph, new IESParameterSpec(derivation2, encoding3, 128), p256_1_with_params23);

        // no longer supported
//        doTestNoParams("ECIES with P-256 None", keyPair, "OldECIES", p256_1_eph, old_p256_1_no_params);
//        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "OldECIES", p256_1_eph, new IESParameterSpec(derivation1, encoding1, 128), old_p256_1_with_params11);
//        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "OldECIES", p256_1_eph, new IESParameterSpec(derivation1, encoding2, 128), old_p256_1_with_params12);
//        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "OldECIES", p256_1_eph, new IESParameterSpec(derivation1, encoding3, 128), old_p256_1_with_params13);
//        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "OldECIES", p256_1_eph, new IESParameterSpec(derivation2, encoding1, 128), old_p256_1_with_params21);
//        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "OldECIES", p256_1_eph, new IESParameterSpec(derivation2, encoding2, 128), old_p256_1_with_params22);
//        doTestWithParams("ECIES with P-256 KP1 P11", keyPair, "OldECIES", p256_1_eph, new IESParameterSpec(derivation2, encoding3, 128), old_p256_1_with_params23);

        keyPair = new KeyPair(ecFact.generatePublic(new X509EncodedKeySpec(p256_2_pub)), ecFact.generatePrivate(new PKCS8EncodedKeySpec(p256_2_pri)));

        doTestNoParams("ECIES with P-256 None", keyPair, "ECIES", p256_2_eph, p256_2_no_params);
        doTestWithParams("ECIES with P-256 KP2 P11", keyPair, "ECIES", p256_2_eph, new IESParameterSpec(derivation1, encoding1, 128), p256_2_with_params11);
        doTestWithParams("ECIES with P-256 KP2 P11", keyPair, "ECIES", p256_2_eph, new IESParameterSpec(derivation1, encoding2, 128), p256_2_with_params12);
        doTestWithParams("ECIES with P-256 KP2 P11", keyPair, "ECIES", p256_2_eph, new IESParameterSpec(derivation1, encoding3, 128), p256_2_with_params13);
        doTestWithParams("ECIES with P-256 KP2 P11", keyPair, "ECIES", p256_2_eph, new IESParameterSpec(derivation2, encoding1, 128), p256_2_with_params21);
        doTestWithParams("ECIES with P-256 KP2 P11", keyPair, "ECIES", p256_2_eph, new IESParameterSpec(derivation2, encoding2, 128), p256_2_with_params22);
        doTestWithParams("ECIES with P-256 KP2 P11", keyPair, "ECIES", p256_2_eph, new IESParameterSpec(derivation2, encoding3, 128), p256_2_with_params23);

        keyPair = new KeyPair(ecFact.generatePublic(new X509EncodedKeySpec(p521_1_pub)), ecFact.generatePrivate(new PKCS8EncodedKeySpec(p521_1_pri)));

        doTestNoParams("ECIES with P-521 None", keyPair, "ECIES", p521_1_eph, p521_1_no_params);
        doTestWithParams("ECIES with P-521 KP1 P11", keyPair, "ECIES", p521_1_eph, new IESParameterSpec(derivation1, encoding1, 128), p521_1_with_params11);
        doTestWithParams("ECIES with P-521 KP1 P11", keyPair, "ECIES", p521_1_eph, new IESParameterSpec(derivation1, encoding2, 128), p521_1_with_params12);
        doTestWithParams("ECIES with P-521 KP1 P11", keyPair, "ECIES", p521_1_eph, new IESParameterSpec(derivation1, encoding3, 128), p521_1_with_params13);
        doTestWithParams("ECIES with P-521 KP1 P11", keyPair, "ECIES", p521_1_eph, new IESParameterSpec(derivation2, encoding1, 128), p521_1_with_params21);
        doTestWithParams("ECIES with P-521 KP1 P11", keyPair, "ECIES", p521_1_eph, new IESParameterSpec(derivation2, encoding2, 128), p521_1_with_params22);
        doTestWithParams("ECIES with P-521 KP1 P11", keyPair, "ECIES", p521_1_eph, new IESParameterSpec(derivation2, encoding3, 128), p521_1_with_params23);

        keyPair = new KeyPair(ecFact.generatePublic(new X509EncodedKeySpec(p521_2_pub)), ecFact.generatePrivate(new PKCS8EncodedKeySpec(p521_2_pri)));

        doTestNoParams("ECIES with default", keyPair, "ECIES", p521_2_eph, p521_2_no_params);
        doTestWithParams("ECIES with P-521 KP2 P11", keyPair, "ECIES", p521_2_eph, new IESParameterSpec(derivation1, encoding1, 128), p521_2_with_params11);
        doTestWithParams("ECIES with P-521 KP2 P12", keyPair, "ECIES", p521_2_eph, new IESParameterSpec(derivation1, encoding2, 128), p521_2_with_params12);
        doTestWithParams("ECIES with P-521 KP2 P13", keyPair, "ECIES", p521_2_eph, new IESParameterSpec(derivation1, encoding3, 128), p521_2_with_params13);
        doTestWithParams("ECIES with P-521 KP2 P21", keyPair, "ECIES", p521_2_eph, new IESParameterSpec(derivation2, encoding1, 128), p521_2_with_params21);
        doTestWithParams("ECIES with P-521 KP2 P21", keyPair, "ECIES", p521_2_eph, new IESParameterSpec(derivation2, encoding2, 128), p521_2_with_params22);
        doTestWithParams("ECIES with P-521 KP2 P21", keyPair, "ECIES", p521_2_eph, new IESParameterSpec(derivation2, encoding3, 128), p521_2_with_params23);
    }

    public void doTestNoParams(
        String testname,
        KeyPair keyPair,
        String cipher,
        byte[] ephPrivateValue,
        byte[] expected)
        throws Exception
    {


        byte[] out1, out2;

        // Generate static key pair
        ECPublicKey   Pub = (ECPublicKey)keyPair.getPublic();
        ECPrivateKey  Priv = (ECPrivateKey)keyPair.getPrivate();

        Cipher c1 = Cipher.getInstance(cipher);
        Cipher c2 = Cipher.getInstance(cipher);

        // Testing with null parameters and DHAES mode off
        c1.init(Cipher.ENCRYPT_MODE, Pub, new FixedSecureRandom(ephPrivateValue));
        c2.init(Cipher.DECRYPT_MODE, Priv, new FixedSecureRandom(ephPrivateValue));
        out1 = c1.doFinal(message, 0, message.length);

        if (!areEqual(out1, expected))
        {
            fail(testname + " test failed encrypt with null parameters, DHAES mode false.");
        }

        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
        {
            fail(testname + " test failed decrypt with null parameters, DHAES mode false.");
        }
    }

    public void doTestWithParams(
        String testname,
        KeyPair keyPair,
        String cipher,
        byte[] ephPrivateValue,
        IESParameterSpec p,
        byte[] expected)
        throws Exception
    {
        byte[] out1, out2;

        // Generate static key pair
        ECPublicKey   Pub = (ECPublicKey)keyPair.getPublic();
        ECPrivateKey  Priv = (ECPrivateKey)keyPair.getPrivate();

        Cipher c1 = Cipher.getInstance(cipher);
        Cipher c2 = Cipher.getInstance(cipher);

        // Testing with given parameters and DHAES mode off
        c1.init(Cipher.ENCRYPT_MODE, Pub, p, new FixedSecureRandom(ephPrivateValue));
        c2.init(Cipher.DECRYPT_MODE, Priv, p, new FixedSecureRandom(ephPrivateValue));
        out1 = c1.doFinal(message, 0, message.length);

        if (!areEqual(out1, expected))
        {
            fail(testname + " test failed encrypt with non-null parameters, DHAES mode false.");
        }
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
        {
            fail(testname + " test failed decrypt with non-null parameters, DHAES mode false.");
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ECIESVectorTest());
    }
}
