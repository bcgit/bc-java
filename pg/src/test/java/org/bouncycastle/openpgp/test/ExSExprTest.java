package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Security;

import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.gpg.PGPSecretKeyParser;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.ExtendedPGPSecretKey;
import org.bouncycastle.openpgp.OpenedPGPKeyData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ExSExprTest
    extends SimpleTest
{

    static
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    byte[] dsaElgamalProtected = ("Created: 20211020T032227\n" +
        "Key: (protected-private-key (dsa (p #00A68CA640389B919C51552D9303E8F822\n" +
        " 8F3C3083DA2D1F366349F2B3D67C9ED2B764448D4EF0579B466CEAF08C9B8477763470\n" +
        " D3BED70784B015F40067F17352B3A4EAF74CBC709000ACD58D64A79332CD828505A1D8\n" +
        " C11A083DE64318093F41AC2004CBDB941B14881183D64467C5C24FFE30A979EF5678D9\n" +
        " 2995D7AC07F3AB#)(q #00DEBBC5AB44F5652BF5FF4FF69FB08199D9652299#)(g\n" +
        "  #4A55C07638DAF38D0A50E4BC53DABDA0B858E94AF923F6B827FCA17B074C598E284E\n" +
        " 1702E1037CCD0608653E8466150AD74071DB6882A6989EC470160F795F45B5BDB93A42\n" +
        " EECC70239615B06CC2B9DD8CDA6097F8A62FF5EB352E913489D579CC6FE01B8EB6E4CE\n" +
        " EF841B3A88021B2D401025BD6C4374812435B67DBD8D3CDD#)(y\n" +
        "  #01AEF2EFC956D068EB0C37EC6185BCB37FA1ADE2585EBBF9D9AC5133FAA864BAA12C\n" +
        " A6CDBB90205BE0952EE9A98A1FD05304DBA4EE82CD748EA3E555A263FD6B7D9AA88E03\n" +
        " EED6D7FF74C432F32469470F07776B52A2B78B58F86F42BE5783A46D6266FC61CFFDC3\n" +
        " D7E59749C69E96ABD393DF4B903101F4CDD6E79547F951B9#)(protected\n" +
        "  openpgp-s2k3-ocb-aes ((sha1 #CB4E8FD129B52F0C#\n" +
        "  \"43860992\")#431AC92BE18B28ED57E69D7B#)#9EDA98358105572FBE507A49A19AAF\n" +
        " A897DFE1E3251E5E1716D77E63930FE223E66F7258B9F080B9B2302075E60E0CBD#)(p\n" +
        " rotected-at \"20211020T032236\")))\n").getBytes();


    byte[] dsaElgamalOpen = ("Created: 20211020T050343\n" +
        "Key: (private-key (elg (p #0082AEA32A1F3A30E08B19F7019E53D7DBC9351C4736\n" +
        " 25ED916439DB0E1DA9EC8CA9FA481F7B8AAC0968AE87FEDB93F9D957B8B62FFDAF15AD\n" +
        " 1375791ED4AE1A201B6E81F2800E1A0A5F600774C940C1C7687E2BDA5F603357BD25D8\n" +
        " BEAFEDEEA547EB4DEF313BBD07385F8532C21FEA4656843207B3A50C375B5ABF9E9886\n" +
        " 0243#)(g #05#)(y #7CF2AF5A729AE8C79A151377B8D8CF6A5DC5CB6450E4C42F2A82\n" +
        " 256CAA9375A0437AA1E1A0B56987FF8C801918664CF77356E8CB7A37764F3CC2EBD7BB\n" +
        " 56FFBF0E8DA3B25C9D697E7F0F609E10F1F35A62002BF5DFC930675C1339272267EBDE\n" +
        " 6588E985D0F1AC44F8C59AC50213D3D618F25C8FDF6EB6DFAC7FBA598EEB7CEA#)(x\n" +
        "  #02222A119771B79D3FA0BF2276769DB90D21F88A836064AFA890212504E12CEA#)))\n").getBytes();
    byte[] ecEdwardsProtected = ("Created: 20211109T024829\n" +
        "Key: (protected-private-key (ecc (curve Ed25519)(flags eddsa)(q\n" +
        "  #40A1C6881D7F04E6189EDBA8D4905A826BF55CF356F6B9F9E7FCBCCF0268F57F75#)\n" +
        " (protected openpgp-s2k3-ocb-aes ((sha1 #496A268F9960EFC7#\n" +
        "  \"42743808\")#92F383D5A8B61D9BD4B0E4E8#)#FCBCDDA53BFA078B9EF1A327A2A24B\n" +
        " A85DD4717B0F1079EC913956960E5E7ADBE1B614F19D2638011F03981BE7CA83C8F764\n" +
        " CDB00543AD3D3DB31009#)(protected-at \"20211109T024837\")))\n").getBytes();

    byte[] ecEdwardsEd448Open = ("Created: 20211029T004049\n" +
        "Key: (private-key (ecc (curve Ed448)(q #6985146F9BC0D9674F5724D94AF629D\n" +
        " C80AB27EDE4C058A1A4A52256998ED38FFA8D58E2FFD13A32A2C42C9F5853C7F106A3C\n" +
        " 7AAB30A1A1600#)(d #DC9200016F520FD5F610969D60ADE368B1C618E3522EF481799\n" +
        " 76558AC1D81BD10F036ED25F8D65BBCCD51B6157988F04A2D2AE74BADF04BEC#)))\n").getBytes();

    byte[] ecEdwardsX448Open2 = ("Created: 20211029T004049\n" +
        "Key: (private-key (ecc (curve X448)(q #54EB068159D84174ED7D34905B2AFDB9\n" +
        " FFA33A3195EC6824DA0DDBB5EFD40180C6FEA18DBDE6C63D98D332DC484CE7B6C33B79\n" +
        " 7AB1531E94#)(d #EB3F7BBFFFFD099D5EC4718232B578AF0199E5A2548C5CF2B2D248\n" +
        " 6F47D16E624346FC8181B34427AC8567FADE46C150C3D39DC36953D4B6#)))\n").getBytes();


    byte[] ecEdwardsOpen = ("Created: 20211021T022038\n" +
        "Key: (private-key (ecc (curve Curve25519)(flags djb-tweak)(q\n" +
        "  #406511B647E8EA9BDB94042D8BD2BD80A6A0FAB628AAE95F6BE2F5D7D7467D6B43#)\n" +
        " (d #6619ED1696419F57F61E978C2A80220E82E1E41D84D51690497DFD5A54142168#)\n" +
        " ))\n").getBytes();


    byte[] ecEd25591Open = ("Created: 20211029T004805\n" +
        "Key: (private-key (ecc (curve Curve25519)(flags djb-tweak)(q\n" +
        "  #40244B2EB3EB676165F0495AF7A9217FB2D1308ABA72246C12756BBF9AA54AF429#)\n" +
        " (d #6546DC28F5B830EBEA4FF29BCC1F7FF8A62903F71D901BA800B6352C88485F90#)\n" +
        " ))\n").getBytes();

    byte[] ecEd25591Open2 = ("Created: 20211029T004805\n" +
        "Key: (private-key (ecc (curve Ed25519)(flags eddsa)(q\n" +
        "  #4019C37A2D6179A29B7D48D0DC16498615BF5906FB610312FDE72CCB9C05DDE892#)\n" +
        " (d #56399E28956FAA43AEDDE4C7778EA6EEDEC0EA0A166C4C108162472043483A8F#)\n" +
        " ))\n").getBytes();


    byte[] p384Protected = ("Created: 20211021T023233\n" +
        "Key: (protected-private-key (ecc (curve \"NIST P-384\")(q\n" +
        "  #04CE6089B366EFB0E4238CC43CBC6631708F122AEFF3408B9C14C14E9A2918D0BD18\n" +
        " D800FD90D6FB4142387913E14F78CA232B91A6C87BFE2841778A99D96EB292E6311E81\n" +
        " FEA3D40CE62F4B9641A481846C119AFDE08AE91DC7B7F705280FF077#)(protected\n" +
        "  openpgp-s2k3-ocb-aes ((sha1 #E570C25E5DE65DD7#\n" +
        "  \"43860992\")#83D43BA89B7E7EA2EF758E52#)#CD30B49842A95DD0D18C2D8550CC59\n" +
        " 8187FE6DE7386418A319F7311197FE4344EE29ACC0B77D2EDF19E268DBB2130F82353B\n" +
        " 319D39306CDA53C6D9F883141738B522E35F6F9CD346B4B187578C#)(protected-at\n" +
        "  \"20211021T023240\")))\n").getBytes();
    byte[] p384Open = ("Created: 20211021T235533\n" +
        "Key: (private-key (ecc (curve \"NIST P-384\")(q\n" +
        "  #041F93DB4628A4CC6F5DB1C3CFE952E4EF58C91511BCCDBA2A354975B827EE0D8B38\n" +
        " E4396A28A6FE69F8685B12663C20D055580B5024CC4B15EECAA5BBF82F4170B382F903\n" +
        " C7456DAB72DCC939CDC7B9382B884D61717F8CC51BAB86AE79FEEA51#)(d\n" +
        "  #5356E5F3BAAF9E38AF2A52CBFAEC8E33456E6D60249403A1FA657954DAE088AA9AA7\n" +
        " 9C2AA85CEEA28FE48491CE223F84#)))\n").getBytes();
    byte[] p256Protected = ("Created: 20211022T000103\n" +
        "Key: (protected-private-key (ecc (curve \"NIST P-256\")(q\n" +
        "  #048B510552811D0BE5B6324D7D3FF4CA9CC4B779A875CB7289AE2EDA601E212E3F78\n" +
        " 9A8F58A7BD6D7554BCEBA9D5F59CC2FD99C7865FF47AA951878128837A6299#)(prote\n" +
        " cted openpgp-s2k3-ocb-aes ((sha1 #43AA7C9708083061#\n" +
        "  \"43860992\")#C246761F0A03FE624368BDBC#)#2C1D62FA0C79319653A4053C5ACAA1\n" +
        " B1EB657029F2A94F35D09CD1514A099203B46CDF1AEECA99AE6898B5489DE85DDA55A7\n" +
        " 9D8FD94539ECCCB95D23A6#)(protected-at \"20211022T000110\")))\n").getBytes();
    byte[] p256Open = ("Created: 20211022T000612\n" +
        "Key: (private-key (ecc (curve \"NIST P-256\")(q\n" +
        "  #04BED3C592DF62319CCE10FCA2C0E9840ECB52414D7022709836302494B1C400390D\n" +
        " CD8BF233BA3E8C022941DC89D03689C1F6674F3750680BD91179AD2426D61C#)(d\n" +
        "  #0DBDCE2F36E215C673FA92F0BBF2763D25F425D1B237F4FDE1978B4D0F85CC34#)))\n").getBytes();
    byte[] p512Protected = ("Created: 20211022T000339\n" +
        "Key: (protected-private-key (ecc (curve \"NIST P-521\")(q\n" +
        "  #0401FEEAF9AAC8318ED84DE64C55DE585DDF177F808120DE2776EE6C6D0A1FF040C9\n" +
        " 5EA9B0A4BC3AAEB85E742144D9BCDD35AFA69ADB5930A7B3A8DC9A9B7749425D300085\n" +
        " 0EF2CF9220E8B822E2A2C6DBBFE5B9C8517C5976FA0FC7B02578F7EEEC856DE41A4B35\n" +
        " F822077A9457063B16E80EA81B3042CB2AEBCD00D13BBF3AB47C08AF24#)(protected\n" +
        "  openpgp-s2k3-ocb-aes ((sha1 #604AAC546D10A025#\n" +
        "  \"43860992\")#0857DCDD546CAE15B3432002#)#3364FD6B626BB8209CFDBCA4CEE5B7\n" +
        " DE60E01552930F2126ADB81AEF49CA424EDBF2FCC8E8B399A6E0A4A2CD8E3A49B4B817\n" +
        " 105379AACF3408FF829E9D2FEA9ACA694F714DF03CC4D9A9EDAF01CBBD6C8F2BA63539\n" +
        " 5B009A3ABAA6FD273C#)(protected-at \"20211022T000350\")))\n").getBytes();
    byte[] p512Open = ("Created: 20211022T000752\n" +
        "Key: (private-key (ecc (curve \"NIST P-521\")(q\n" +
        "  #04013167CAEB3E78C668216C92573F4D365DDF93DD5E97482EFC1CC580D9BDC4B403\n" +
        " 7F6E8D863CE6473E6A1EAB6FF8CFCAEDDA60C4BD654277A21E665D3492F61CFAE8001C\n" +
        " 5CDB9FBDEF2E8DEB8DB643C4F58AA695B0B8E2DE9A4892B265CCAF195DF57CDC5A9D7C\n" +
        " 51530F2133430DC267205FBAC6AEDB6948181336E54D0D962C92AF8779#)(d\n" +
        "  #00CE5378021EFC005426E45E8FFEB8E9FAE3585B9833D482D54EAE1BECBDFF39BA0A\n" +
        " 01C645518AAD689595414486EEC8ACAB563CBA0497525082D4984725B4900290#)))\n").getBytes();
    byte[] brainPool256Protected = ("Created: 20211022T002206\n" +
        "Key: (protected-private-key (ecc (curve brainpoolP256r1)(q\n" +
        "  #041E919B53AC0FAE4859D3A340E9D3F9477A3A6EF21096E19EECB3F720914A1C0939\n" +
        " 679E2968E7465AA145EF654EC5CD317532541E1020017975E74571A23ABC88#)(prote\n" +
        " cted openpgp-s2k3-ocb-aes ((sha1 #B154CE967502E323#\n" +
        "  \"43860992\")#3A8D9610A7E3C00417B506FB#)#C73934FC18C45810AC823794545D5A\n" +
        " EC3508FD242DE859F5807F61C1F6916FC7E6EF49D62C1A0783789142D7B77E5204D664\n" +
        " ABF93ED68DE4AC99A3D5#)(protected-at \"20211022T002215\")))\n").getBytes();
    byte[] brainPool256Open = ("Created: 20211022T002337\n" +
        "Key: (private-key (ecc (curve brainpoolP256r1)(q\n" +
        "  #0438E90AD5F8812757543FB28B6DC6D833DC407F7DE64A70033FFAA71BD76AB7943F\n" +
        " E548B5A0BC5DBFCD1BA204B078A9896F1B8AC077766E0663F33A925F97FCCC#)(d\n" +
        "  #5A3E1A99AFF85107E0958F3A1F984D9CACC980BFCD6F083D24B49B3E1DF7DFEE#)))\n").getBytes();
    byte[] brainPool384Protected = ("Created: 20211022T002549\n" +
        "Key: (protected-private-key (ecc (curve brainpoolP384r1)(q\n" +
        "  #0424C8ACB05DBF96CCA1F7BD243DA45C81D8FF0C6FF18AFEA72EC4F24FCFBE322A1A\n" +
        " 7CA0E0908D30350E31681F751285B40053D78EC9E580E406AB42C76ECD647FD9273691\n" +
        " 82FB0D80A06DE522578B89538B30CD57609B57CE6D5E98282536ADAD#)(protected\n" +
        "  openpgp-s2k3-ocb-aes ((sha1 #5C5C1885A62FD64A#\n" +
        "  \"43860992\")#C673B0BDE04C5FDA51C368AA#)#E3CF929075B4DAAC16A232624EC136\n" +
        " ECA5363581B6155A7F584F3340C438DC6293ED5330ED05BB44F7840CBBFF49ACF9FA99\n" +
        " 610AE0935829B730B33D9E77C42CF912CE0BAC9CF695CB4F7E69#)(protected-at\n" +
        "  \"20211022T002556\")))\n").getBytes();
    byte[] brainPool384Open = ("Created: 20211022T002735\n" +
        "Key: (private-key (ecc (curve brainpoolP384r1)(q\n" +
        "  #046370CBBD9CD285F5E155C7DAD470E7730226F2CBCE4B751408D28A0F3FE933B17E\n" +
        " 9F9E0BB96978893B231E9301148F3D38FC94C058DA13A9885149783F7DCA317B06F154\n" +
        " 39F511C37F6D1BED320D9862F4DC325AD6FDABA37719C09F0C3E2217#)(d\n" +
        "  #4A5A04339009AAB1F7BE9F30B04C93B08289D656E1FE507AB7D41C283C31DF720E26\n" +
        " BB6ABF5F2B75AD6A1EEB537F898A#)))\n").getBytes();
    byte[] brainPool512Protected = ("Created: 20211022T003008\n" +
        "Key: (protected-private-key (ecc (curve brainpoolP512r1)(q\n" +
        "  #04742D2A32C685E25022D2CC1A6A10C76DE496236083A57215D9F59ACDA4D2779B10\n" +
        " C70D0C0AB7F920BC715268CBEEDA77ACA2A179DB924A7E2DDB2E54E45370510D1D3B79\n" +
        " 3A967F3CE9C8B53D50C3F92E92AF854EBF5DDCAFCC558EAB8B664028A898EEFBA1FD75\n" +
        " B93A05AF72F5712B4A231792A44FDAF27D1FEB8B849DF1FA62#)(protected\n" +
        "  openpgp-s2k3-ocb-aes ((sha1 #50D17783DE9AF6A4#\n" +
        "  \"43860992\")#3272F7788411E5A84182DC01#)#37BBC2E54B23C183182BBDBC8CA6C1\n" +
        " 8A7C62E98D35D326D193F82E01077F52F051A772449A6846580536FBB0DEB398832FF3\n" +
        " B181A4F34A8069A6382908B6C69ED74AED8C5F3D5E84EE8A374B282CBC1DDE0E17F450\n" +
        " 3A8662C43475AD#)(protected-at \"20211022T003014\")))\n").getBytes();
    byte[] brainPool512Open = ("Created: 20211022T003257\n" +
        "Key: (private-key (ecc (curve brainpoolP512r1)(q\n" +
        "  #04239AB457E9ABE5C45D53FA9B3B9EBCC54BC1720B5BA4EBF0BE192F1B3EC86E6C5B\n" +
        " 13F81CEB54844458852908BAB437E6048F2A23CDF4F6B3BF2B298D57BD54C4099CC92A\n" +
        " 3E14DAEA1EA9BC5565D79824F891614D81874EE1E3DAEDFD3A98FFCC0E1F577F8C5981\n" +
        " 785C6C60B32F8F0CCBD60A4B26246C04AB795F58EEB10672F7#)(d\n" +
        "  #158A0452C0D58F9C24F7E0C18CC44716FC9DD74DA0CEEB150FDE410BE90CE87D7C4A\n" +
        " E6578CDB5460683A1ECF80518BB297EA649C7C8593EF1995F53F4BE71DBD#)))\n").getBytes();
    private final byte[] showedRSA = ("Token: D2760001240102000005000011730000 OPENPGP.1 Token: FF020001008A77C1 PIV.9C Key:" +
        " (shadowed-private-key (rsa (n #00AA1AD2A55FD8C8FDE9E1941772D9CC903FA43B268CB1B5A1BAFDC900" +
        " 2961D8AEA153424DC851EF13B83AC64FBE365C59DC1BD3E83017C90D4365B4 83E02859FC13DB5842A00E9694" +
        "80DB96CE6F7D1C03600392B8E08EF0C01FC7 19F9F9086B25AD39B4F1C2A2DF3E2BE317110CFFF21D4A1145550" +
        "8FE407997 601260816C8422297C0637BB291C3A079B9CB38A92CE9E551F80AA0EBF4F0E 72C3F250461E4D31F" +
        "23A7087857FC8438324A013634563D34EFDDCBF2EA80D F9662C9CCD4BEF2522D8BDFED24CEF78DC6B30931740" +
        "7EAC576D889F88ADA0 8C4FFB480981FB68C5C6CA27503381D41018E6CDC52AAAE46B166BDC10637A E186A02B" +
        "A2497FDC5D1221#) (e #00010001#) (shadowed t1-v1 (#D2760001240102000005000011730000# OPENPGP.1) )))").getBytes();
    private final byte[] openRsa = Strings.toUTF8ByteArray("Created: 20211014T044624\n" +
        "Key: (private-key (rsa (n #00ED5B77E0107AFC1D066B4010E9B951451974E9B49E\n" +
        " 6741E0CF742427EB14587D1250DC52F7F820E9587B3714681702C5BC4BFDBE06DCE886\n" +
        " F87DF730857A045FF9A72195E04B23E742136CBFE3FA363AF5788BAE55E3BD02A54E2B\n" +
        " 3A52FB2B32B48FECD8780D07E2298983031AB97ED6C0A47A73778C5B2AF3BF93C7CFEF\n" +
        " 1325974A850096F3A73559A5B3DBF63A3246D94D4B6696D08CBFDC8678A8969E00EB17\n" +
        " 2EBC47AF31C61BC412D843F1DDE2BA95404734982687463296DC033901A030A1D5B3BC\n" +
        " 2CF00F3B1F825903E8FD47E390B82A4236EF2DA3502DE0EF6E56D00512578FA3E7C746\n" +
        " 89FAB557B4E47CD736BC1B0756775B06CBB19CFF429843923E6D05447E5ADEA30DED61\n" +
        " 24D1FD9C5FC8DEA2706624CFEB2B63DB0713CDCC3FA071B7256BBC497A3EA50D9E0B4E\n" +
        " AD15F982291D032B4999AC10D22F5C1B2BCACDCE8F4F66497087A11430A5167D8ABAE0\n" +
        " C76919356BD5B460026080502BF1279807398FCB64E03E42772B823C78A8B67DBA9EAF\n" +
        " B6C4F0CFBD09BD7068A7D47873#)(e #010001#)(d\n" +
        "  #197102750BE482D2D6F5F6AA0418B9B35465345FB3283CE6CC95C057B45A3BEF3C0A\n" +
        " B01DB1E29B747CE81D769C7EF5971DA06F9447715FA332A373341F8FD2998EF84675FA\n" +
        " D2A85DDE0BEDA38130E2A5DDDB36985085D6A3F54AB456236ADF587CAE28A43DF4A247\n" +
        " 05A36DB2E42719DCB44D6CFFFA17C5F5E151443FD89E8C48D7E1EEF0FF3D22A114A384\n" +
        " 41D6D9FF659A092F99D1748D2C4B864661F10857EF85A3F173D03D8A39E901B418A450\n" +
        " DF95419B8ADBAD00AEE34157964194D7586F692FC73FCF70B3B56A934ACCCDE0D74F02\n" +
        " FF01760AFC84CCCAD66C1A1BFFEA4C63747D1612B5EB25198F62C5F7BEA7A52674482D\n" +
        " 1B77A5CC1F9963D969C3B266798D166B652769CFFCACA28886E03F1BF7ECAE04B7D1B0\n" +
        " 7FC907D1FC156DE2E4898CFE9F08876D9E24E744CE01DBAB1170F3F59E41AC2383AAC0\n" +
        " 41A10DD394C08D1F44F987F386BE32A4AB805B1EDBA85CDDADA542DDEE2FC1FCBDFB1C\n" +
        " 0809046CB4C7B24B2EBC3EA51F015AB0A39499820F06E6B7D32EE870E8651C30A282B1\n" +
        " #)(p #00F2E626FF576CCB9684AE2698FD7ACA63543D8D28B2E75D6B7BB48C6F2A3C3A\n" +
        " 7BF484F5E0DEAEBA6C59B1114C696C26C5FFE318E213EAB8CD3AB252B0DBB69A5FD642\n" +
        " 17A55AFE5B899CE16E21E1CE7D655B7248C672BB2D1A4FF23B1E807C9361DDFAB82090\n" +
        " 6E82B634EE9E607BDAD32039E1E19C3B15FC4FC1EFC356814A3992D476B0F6E8E98A6F\n" +
        " 9CB77FEDAA7F6F56B134FAB3EB0FD8D7D2FF22E2FFE890338AF666401BD0732BA236E6\n" +
        " 69C20F5F9C2F31487647CF8589D483DFDFC98FF3BD#)(q\n" +
        "  #00FA28CC48F1C61B80B5D1CA48C8DA6B9FFAA9891D6F6E90EDF607B71278C03E4174\n" +
        " 48380CC1477786572A5BA43A772A37397B4DC362B4E495B999D0A494599A154DC556AA\n" +
        " A8D852E8AF5FB26B0EF8EFABA1C6CFF0883AC70092F6CD6B5FD9834A964DDA41D93BFF\n" +
        " 464344DC89CE6951F1BF39CCD9B60630101BB8A4F89307EECFAB43AAACCF7E824B0C39\n" +
        " EC647898CFB5CC9C8BD33087D144334C471ABCCAC525EF5AA425D8388EB6AB72900D0B\n" +
        " F04BBD076F819F242A026BC630615B2758C7EF#)(u\n" +
        "  #613BFCE8D7910CE3C4B9CFBADE79563290A834B67C68C616C8177F6937FC522E4204\n" +
        " 5C80769FDF35DBA3BE23CC623EFFEEA4B74B72F6A46EC2A876EC37D9CB65FEDEDB05AF\n" +
        " 62F69A62A911D60DB3C8E7D2B9C6122F9ACF4E39FABF1E7F83EF119A70ED9B02F5FAA9\n" +
        " 6ACFEA7E735E008F77E7F829FC6B669C72665D7E2E21DE85C66840E76FA200F832980B\n" +
        " 587BCE3AE6F748A85EF2E2BDFDCAAFF52E27752159A80E00B5B241AB45839820520F2F\n" +
        " A8B62E956F307061CB26915408CF2F014824#)))\n");
    private final byte[] protectedRSA = Strings.toUTF8ByteArray("Created: 20211017T225532\n" +
        "Key: (protected-private-key (rsa (n #00BDA748AF09EC7503A3F201E4F59ECAA4\n" +
        " C52E84FEA5E4D7B99069C3751F19C5D0180193CA2E4516B5A9ED263989E007040C1C1D\n" +
        " 53F2D8B7844AEFF77FE28C920ACE0C0F5A77A95536871DD03878BA1997FAE6368E133B\n" +
        " 5CCCB13B4500F99FD211CB6EF42FAF548BB9BEDAA399A0085F85F9CE3268A03276C31E\n" +
        " 33313F1826A9DB#)(e #010001#)(protected openpgp-s2k3-ocb-aes ((sha1\n" +
        "  #0D1568A73CF5F7C6# \"43860992\")#E5DF4BA755F1AC410C4F32FA#)#CFF9000F22E\n" +
        " 0948B2D3BB1E78EEDB42D2361C3A444C94D02E17CDBC928B0AA21275B391820944B684\n" +
        " 757088F76D6CB262768FBB1B06067FECB04E02C5A1A6C2CF18896A30166D6231CB3179\n" +
        " FD0567D03C207C04EAE6523F77302ABDBF8294D90D197B875BCEBB564CCD0DE264D8BA\n" +
        " C921DA23A21C4F7D2DD12A2E4EF20ECFEB2DABD273A2270B2AC386ECF2DCDE90D5FDDB\n" +
        " 00261814082A710A0347C57F7326E18FBE5E4D0F67B6912A903A58984E244D8A487921\n" +
        " 2712200205123AE58E7CB2457518611678C086F319CF7BED4A675E79CA8BC9DB810025\n" +
        " C5EEA8BD0D980787003992A72C005DAEC32604767ADF91AF180DB58260B21A1996240F\n" +
        " E6225B066EA9A8979E590B1BC85F44796903A2738B7871F52F4F27032AC86B25F38E07\n" +
        " 4E12CEB9ECBCD6995D03DA57710EC54A6E60B79283389BD2869FF7B7C65623C59E0B40\n" +
        " 621802DEDA97B167C806B45E0CB3A2CE4C60CD7D7FCE763F7B57EDC226AF7F05B07234\n" +
        " 32C910DD00AD4FD29FE159AEB19E084E9AC76CE#)(protected-at\n" +
        "  \"20211017T225546\")))\n");

    byte[] theKey = ("Created: 20211022T050720\n" +
        "Key: (private-key (elg (p #009015DEBF6AA2B801EB39EEABC20914FDBD26D8A40B\n" +
        " 6343D99F3328CEF0B76748DDC23840C0D404BE9AFF61590816D630513C5D7D73359DBE\n" +
        " E6FD0E79D5204C518113941AFACA4D8FD608AD659C4EC9DC5ABDF884C0DA7067CB7084\n" +
        " 161D9CDB06D6057DC6FE21C8213FC18F070CD2F53249E22F00B99EE315CB1191848C92\n" +
        " 43C05A453BF2CC3D20A0EA0AE097B9034A7FCA79C279D67EB82CFFD50E54630E73D020\n" +
        " C7248B1EEF6225FA82067CF3DCB40F0614F87949E917E3208CA354A22EC10B65DC1065\n" +
        " 59BEE3DE9B4C03CC65DA8C00F0DA8D19F08CB070BE65D9BF1986A680CAA3CC9A109756\n" +
        " C7F36F48D9902A4D51EE05577C309797F68A3917B28506554E32324226EA3CDF372CD5\n" +
        " 0BD86BA12AACB00EE962D93A621826A225B7C35C65A036DCB7820CAD7C904D1DD6F976\n" +
        " 2ADE5E7B528AC162C5DC0C3A833A6BE3465E97D835CA862BD7ECDF8A6AE2645D607BD8\n" +
        " 067C110C437C9FCC83A7A113DBB12CAD522FCA8E068054D0AF84B0EA45DCA11D3FE875\n" +
        " 1A5A25A84CCE04132FEAB7B993#)(g #06#)(y #5F298179167DF1A10F0260CC2C1916\n" +
        " B0F72AFE7FC173049B28AFEDA196D730FC8667D3E4F11EB51EF9965ADE15D0218C72B0\n" +
        " 64E6501E20BD9013CF2B6EC4350D7666F3E7ABBFE7C982664FDE1B70FDE24C9BDE80AA\n" +
        " 974D46F4723F111B0F6402848694D45FADBD38A5FAF3A17CDF1C8BEC35C6E83841A37A\n" +
        " 68D1B18CE2D5A30DBEDBC660D2074A3C4F4BA8DD724CF3FDB3C0CF21B5BF26AD24D5AE\n" +
        " CFED47001EBAA9231D756AC75A18BB2DF2F86ABD52BABBAD9E9A53890126B990773595\n" +
        " BBE9E9CB8E7505260C07725C3036339C5C1A40B0AF62C534F1E049FC130C78856FD070\n" +
        " 69CFFD1316FD853CABEF72C8DAF268EC0C3F7404085C0336A86C3BB5AC5B4414AA42AE\n" +
        " 26B24A0D87B1AE494766E3D4A14FFCB287E59260AE5EB952F31ADC01DF4F947EFFAF0E\n" +
        " 1F999A3C3F8E8ABAD24B3B56DC140970F22384C8821481E128F6B18D779F27D9492B88\n" +
        " A0EBB72CCB13AB07038448ADDF4A3D00F62E3EC2724730CC052C0C9385469CA364C9FD\n" +
        " 5BAAE4CCBF8635DD034B3FBEBBC2E656DB77A6#)(x\n" +
        "  #0CE0A6B334E053051076D64AFB091C1B585758BC03B1D66A3BEE0C0487707DBE8CBF\n" +
        " B4FD7A5640C3536243CC298017781127B9#)))\n").getBytes();

    byte[] dsaOpen = ("Created: 20211022T050720\n" +
        "Key: (private-key (dsa (p #0081DDB6787FFD16BF29C91BB29F4F1F61E24965E3AC\n" +
        " 9203C2346D3DF81B999D4E8CC3BD955BAB0C72DE8912B6A5E1D976A3AAE38AD79DDA33\n" +
        " A09805E5A326B1B994C48776CA7D66F2774C23D13E2BF6A320BFCF1CBC2FB818C360CC\n" +
        " A250F417218A92735EC3BDEF19BA2E7297BF78E6146C28766EE0B05F3A5FB370FEA57E\n" +
        " 4EF782F765543B70E851EDD2B75F725033F1ABCBA2B07F4458E675D4667D74F39B8C84\n" +
        " C950C353A3CB01641A258675C9760FEFF56C6492F9C14D6442CEB554407CE65620772F\n" +
        " B60655A644CC73168A71103EE0BDC8C02940DA11327D339F7C6E8422A029FE7C139849\n" +
        " BDCDC0A2F24B5B54D90BC566AAEF7F7FBB6B21EB44A8F1138B#)(q\n" +
        "  #0085744A0AA8FC1D7C00E9C9E83011ACFEBFD2BA84F85EB70A66D708675023D295#)\n" +
        " (g #2ACAC7E7B4D911CFDFA271306C4E13BA3F9867546970A2D02F7E23751C35FBE4A6\n" +
        " 8AEE9109AA992D9030A1DA739B7915971AE29692D4D773F6A7C86AA68B447991F860A1\n" +
        " D3B9F22E3BB31C6F299ACD50283F1DD9A14771A84B1FD2233F70FBCAE11A24C82C89F9\n" +
        " 638F57BAB2F0F19DE299EFE8B927B00E5D12E337AD6B9B0CE260BBD0CE7C55BBEC2DC9\n" +
        " 61C7310774A23A0AA8CE2B84A8592356E19AD1243EF56C07CD9C04B943C4461938450A\n" +
        " 68C4774A052AB3AF331E95522E6115BBBA7ADB7F0A2D610CB706F070E83D8BC932D736\n" +
        " 8B74A1335BEA0BFCD44BDE8D6AEC52D104B218A6D12CF876D7CE074EF086CF421092FF\n" +
        " BF48225CA7D7A0FA21C1CEBF5F#)(y #6C9DC144DAB49C6B217C89883692E42F970CB2\n" +
        " A70C5ED7797A0B991D731786AA5F024B19B99F5AB928E1180CFEC864B3D36457070B3B\n" +
        " 0B7D91A5516F526993566536613D860B39765A84E64D5E5BBA2C39AA07BBA4C55B8D6A\n" +
        " 6606AA9A5EAC407C641436E66CDD01D2182441B5A54A68203EB2DC8816369F1A372685\n" +
        " 5D705775D3D20F9FCB052157EAF0801EAA688660C9AA1BEEEDCA6836D5270DA4D2A752\n" +
        " EB86900799407F30EDE9221D0628D7E2EA5261A6A08823CF3D74DD86A70C70F09B9D85\n" +
        " 5D9D09A793524FB910B361DD2C76851C500B9E8AAFE21AE4213FCD548198A678771748\n" +
        " FFD0A95F2A440B2DA437E1820C2F93078C603F34ABB261D6DAB601#)(x\n" +
        "  #7C4BD40471E53B922B3EAE5BD5BA1F23D17972D14DAC6619F549459745353091#)))\n").getBytes();

    byte[] dsaProtected = ("Created: 20211022T053140\n" +
        "Key: (protected-private-key (dsa (p #00CD7275234699FE0D25FDBEE69DA2AA80\n" +
        " AAAB15906FACFC8F4EB5A9BAE23D22E5649199C119FB72951BD0FA717F51CFD7B904FD\n" +
        " BB1F0D0660938199976DA4447F54E91E2CC4B21F4BB162644EA43A3F27F7CAFF7D6355\n" +
        " 16E8640558E222EF20B55E8AF2AFD33D571092CE5C090E57DA3452484BC04398E24613\n" +
        " D593113F1F5CE7CA3229F5DFAFC1EFC47B725505E46A0EB9CC45FACFBEA6ECC6CA694E\n" +
        " D3781E011C48C66BBB6C1BA35DD810EF24CF7B92D9E9BCB0B0E19053CFA073AD2D9957\n" +
        " 270B3C55D60824F93EECBF8AF393F07C05BEA38636DFC6B6152424FAF5C0287435C145\n" +
        " B021E235AA30E2B063695EE01D6C696EAA381517E50A440D8AA00164B423#)(q\n" +
        "  #00A4F8D3DC79F1F8388B9FF3F3A484568A76337BF968F05C207F5AF8E84F4B83C1#)\n" +
        " (g #32EC716A63D63CB69E17A678B9BC70686EA24AF4F96F46683E09ACF7EDE9839ADB\n" +
        " 914E61A38D151B28B65533362100B1D9D2948FD8617136FF82C8B61DF5A400B3D2A3E3\n" +
        " 2CEAF2B7DAEBF30D24CA3E681AC551F01EC366EECCDF1481B092E3534728D73211D962\n" +
        " 09069E8FA34395C94828D77F0FEF8E6DEFEA3687ED6267EB028007B84840E383E8B14C\n" +
        " AB93109FA414458E56F5BDAF7AB37ECB3E3FA8EDAED60B7323D3329FB3EA4E460FFA63\n" +
        " B9EC9836530B16710A0EA3A750BF646A48DA65E4144A9A7964513BF998755612791DC5\n" +
        " F840FAE54D34C44A62C1BE884774870BC6D0505FE5EE3F4B222194740E4CC639785E56\n" +
        " B93E17DCACBFE63703DE201DB3#)(y #1B1DAAA76ACF531DBC172304E6523C16B3E701\n" +
        " 2B8B3F0D37AFD9B2C8F63A2155F2CAAE34ADF7A8B068AB266AEE5A5598DD9BE116FA96\n" +
        " F855AA7AD74F780407F74255DC035339C28E1833E93D872EE73DE350E3E0B8AB1E9709\n" +
        " B835E58E6A5491383612A52EB4A3616C29418C0BE108739CC3D59BCF3B0299B283FEA6\n" +
        " 7E21A1909C2E02CD1BFE200F0B6EEE0BB8E4252B8F78711AD05C7056CE673ED81BE265\n" +
        " 60C0768AEC8121D5EB21EE6A8338CC35E306931D1B3516767E345B9C25DF7454C36C61\n" +
        " 739B193BC4998A47A4E5A4956FF525F322DA67B9DC6CFA468ADEBC82EBEEB7F35C4982\n" +
        " A2D347ED4ECB8605387161F03175A9D73659A34D97910B26F8027F#)(protected\n" +
        "  openpgp-s2k3-ocb-aes ((sha1 #4F333DA86C1E7E55#\n" +
        "  \"43860992\")#D8BD10519B004263EC2E35D4#)#57553ACF88CB775B65AAE3FAEB2480\n" +
        " F40BA80AFEA74DD1B9E59847B440733B3A83B062EAD3FDBF67996BA240B8504800C276\n" +
        " AAF1DE797066443807DDCE#)(protected-at \"20211022T053148\")))\n").getBytes();

    public static void main(String[] args)
        throws Exception
    {
        runTest(new ExSExprTest());
    }

    
    public String getName()
    {
        return "Extended SExpression Tests";
    }


    public void testECNistCurves()
        throws Exception
    {
        byte[][] examples = {p384Protected, p384Open, p256Protected, p256Open, p512Protected, p512Open};
        for (int i = 0; i != examples.length; i++)
        {
            byte[] data = examples[i];
            ByteArrayInputStream bin = new ByteArrayInputStream(data);
            JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();

            OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

            ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);

            JcePBESecretKeyDecryptorBuilder f = new JcePBESecretKeyDecryptorBuilder();
            PGPKeyPair pair = secretKey.extractKeyPair(null);
            validateEcKey(pair);
            bin.close();

        }
    }

    public void testBrainPoolCurves()
        throws Exception
    {

        byte[][] examples = {brainPool256Open, brainPool256Protected, brainPool384Open, brainPool384Protected, brainPool512Open, brainPool512Protected};
        for (int i = 0; i != examples.length; i++)
        {
            byte[] data = examples[i];
            ByteArrayInputStream bin = new ByteArrayInputStream(data);
            isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));

            JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();

            OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

            ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);

            JcePBESecretKeyDecryptorBuilder f = new JcePBESecretKeyDecryptorBuilder();
            PGPKeyPair pair = secretKey.extractKeyPair(null);
            validateEcKey(pair);
            bin.close();

        }
    }

    public void testECEdwardsOpen()
        throws Exception
    {
        ByteArrayInputStream bin = new ByteArrayInputStream(ecEdwardsEd448Open);
        isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));

        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();

        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

        ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);


        PGPKeyPair pair = secretKey.extractKeyPair(null);
        validateEdKey(pair);
    }

    public void testECEdwardsProtected()
        throws Exception
    {
        ByteArrayInputStream bin = new ByteArrayInputStream(ecEdwardsProtected);
        isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));

        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();

        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

        ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);

        PGPKeyPair pair = secretKey.extractKeyPair(null);
        validateEdKey(pair);
    }

    public void testDSAElgamalOpen()
        throws Exception
    {

        byte[][] examples = {dsaElgamalOpen, dsaOpen};
        for (int i = 0; i != examples.length; i++)
        {
            byte[] key = examples[i];
            ByteArrayInputStream bin = new ByteArrayInputStream(key);
            isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));

            JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();

            OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

            ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);

            PGPKeyPair pair = secretKey.extractKeyPair(null);
            validateDSAKey(pair);
        }
    }

    public void testDSAProtected()
        throws Exception
    {
        byte[][] examples = {dsaProtected, dsaElgamalProtected};
        for (int i = 0; i != examples.length; i++)
        {
            byte[] key = examples[i];
            ByteArrayInputStream bin = new ByteArrayInputStream(key);
            isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));

            JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();

            OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

            ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
                null,
                digBuild.build(),
                new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
                new JcaKeyFingerprintCalculator(), 10);

            PGPKeyPair pair = secretKey.extractKeyPair(null);
            validateDSAKey(pair);
        }
    }

    public void testRSAOpen()
        throws Exception
    {
        ByteArrayInputStream bin = new ByteArrayInputStream(openRsa);
        isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));

        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();

        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

        ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);


        PGPKeyPair pair = secretKey.extractKeyPair(null);

        validateRSAKey(pair);


    }

    public void testProtectedRSA()
        throws Exception
    {
        ByteArrayInputStream bin = new ByteArrayInputStream(protectedRSA);
        isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));

        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();
        digBuild.setProvider("BC");

        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

        ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);

        PGPKeyPair pair = secretKey.extractKeyPair(null);

        validateRSAKey(pair);

    }

    public void testShadowedRSA()
        throws Exception
    {
        ByteArrayInputStream bin = new ByteArrayInputStream(showedRSA);
        isTrue(PGPSecretKeyParser.isExtendedSExpression(bin));

        JcaPGPDigestCalculatorProviderBuilder digBuild = new JcaPGPDigestCalculatorProviderBuilder();
        digBuild.setProvider("BC");

        OpenedPGPKeyData openedPGPKeyData = PGPSecretKeyParser.parse(bin, 10);

        ExtendedPGPSecretKey secretKey = (ExtendedPGPSecretKey)openedPGPKeyData.getKeyData(
            null,
            digBuild.build(),
            new JcePBEProtectionRemoverFactory("foobar".toCharArray(), digBuild.build()),
            new JcaKeyFingerprintCalculator(), 10);

        RSAPublicBCPGKey pub = (RSAPublicBCPGKey)secretKey.getPublicKey().getPublicKeyPacket().getKey();

        isTrue(areEqual(Hex.decode("00AA1AD2A55FD8C8FDE9E1941772D9CC903FA43B268CB1B5A1BAFDC900" +
            "2961D8AEA153424DC851EF13B83AC64FBE365C59DC1BD3E83017C90D4365B483E02859FC13DB5842A00E9694" +
            "80DB96CE6F7D1C03600392B8E08EF0C01FC719F9F9086B25AD39B4F1C2A2DF3E2BE317110CFFF21D4A1145550" +
            "8FE407997601260816C8422297C0637BB291C3A079B9CB38A92CE9E551F80AA0EBF4F0E72C3F250461E4D31F" +
            "23A7087857FC8438324A013634563D34EFDDCBF2EA80DF9662C9CCD4BEF2522D8BDFED24CEF78DC6B30931740" +
            "7EAC576D889F88ADA08C4FFB480981FB68C5C6CA27503381D41018E6CDC52AAAE46B166BDC10637A E186A02B" +
            "A2497FDC5D1221"), pub.getModulus().toByteArray()));

        isTrue(areEqual(Hex.decode("010001"), pub.getPublicExponent().toByteArray()));
    }

    
    public void performTest()
        throws Exception
    {

        testDSAElgamalOpen();
        testBrainPoolCurves();
        testECNistCurves();
        testECEdwardsOpen();
        testECEdwardsProtected();
        testDSAProtected();
        testRSAOpen();
        testProtectedRSA();
        testShadowedRSA();

    }

    public void validateDSAKey(PGPKeyPair keyPair)
    {

        if (keyPair.getPrivateKey().getPrivateKeyDataPacket() instanceof ElGamalSecretBCPGKey)
        {
            ElGamalSecretBCPGKey priv = (ElGamalSecretBCPGKey)keyPair.getPrivateKey().getPrivateKeyDataPacket();
            ElGamalPublicBCPGKey pub = (ElGamalPublicBCPGKey)keyPair.getPublicKey().getPublicKeyPacket().getKey();

            if (!pub.getG().modPow(priv.getX(), pub.getP()).equals(pub.getY()))
            {
                throw new IllegalArgumentException("DSA public key not consistent with DSA private key");
            }
        }
        else
        {
            DSASecretBCPGKey priv = (DSASecretBCPGKey)keyPair.getPrivateKey().getPrivateKeyDataPacket();
            DSAPublicBCPGKey pub = (DSAPublicBCPGKey)keyPair.getPublicKey().getPublicKeyPacket().getKey();

            if (!pub.getG().modPow(priv.getX(), pub.getP()).equals(pub.getY()))
            {
                throw new IllegalArgumentException("DSA public key not consistent with DSA private key");
            }
        }
    }

    public void validateEdKey(PGPKeyPair keyPair)
        throws Exception
    {

        BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

        AsymmetricKeyParameter privKey = keyConverter.getPrivateKey(keyPair.getPrivateKey());
        AsymmetricKeyParameter pubKey = keyConverter.getPublicKey(keyPair.getPublicKey());

        Signer signer;

        if (privKey instanceof Ed25519PrivateKeyParameters)
        {
            signer = new Ed25519Signer();
        }
        else
        {
            signer = new Ed448Signer(new byte[0]);
        }

        byte[] signThis = new byte[32];

        signer.init(true, privKey);
        signer.update(signThis, 0, signThis.length);
        byte[] sig = signer.generateSignature();

        signer.init(false, pubKey);
        signer.update(signThis, 0, signThis.length);
        isTrue(signer.verifySignature(sig));

    }

    public void validateEcKey(PGPKeyPair keyPair)
        throws Exception
    {

        BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)keyConverter.getPrivateKey(keyPair.getPrivateKey());
        ECPublicKeyParameters pub = (ECPublicKeyParameters)keyConverter.getPublicKey(keyPair.getPublicKey());


        if (!(priv.getParameters().getCurve().equals(pub.getParameters().getCurve())
            || !priv.getParameters().getG().equals(pub.getParameters().getG())
            || !priv.getParameters().getN().equals(pub.getParameters().getN())
            || priv.getParameters().getH().equals(pub.getParameters().getH())))
        {
            throw new IllegalArgumentException("EC keys do not have the same domain parameters");
        }

        ECDomainParameters spec = priv.getParameters();

        if (!spec.getG().multiply(priv.getD()).normalize().equals(pub.getQ()))
        {
            throw new IllegalArgumentException("EC public key not consistent with EC private key");
        }


    }

    public void validateRSAKey(PGPKeyPair keyPair)
    {
        RSASecretBCPGKey priv = (RSASecretBCPGKey)keyPair.getPrivateKey().getPrivateKeyDataPacket();
        RSAPublicBCPGKey pub = (RSAPublicBCPGKey)keyPair.getPublicKey().getPublicKeyPacket().getKey();
        if (!priv.getModulus().equals(pub.getModulus()))
        {
            throw new IllegalArgumentException("RSA keys do not have the same modulus");
        }
        BigInteger val = BigInteger.valueOf(2);
        if (!val.modPow(priv.getPrivateExponent(), priv.getModulus()).modPow(pub.getPublicExponent(), priv.getModulus()).equals(val))
        {
            throw new IllegalArgumentException("RSA public key not consistent with RSA private key");
        }
    }


}
