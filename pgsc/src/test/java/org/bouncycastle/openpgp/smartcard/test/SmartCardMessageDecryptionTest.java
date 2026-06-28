package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.OpenPGPSmartCardManager;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorOpenPGPSmartCard;
import org.bouncycastle.openpgp.smartcard.simulator.SimulatorSmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeySmartCardBackend;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestInstanceProvider;
import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestProperties;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class SmartCardMessageDecryptionTest
    extends AbstractOpenPGPSmartCardTest
{
    public SmartCardMessageDecryptionTest(OpenPGPSmartCardManager manager,
                                          SmartCardTestProperties properties)
    {
        super(manager, properties);
    }

    @Override
    public String getName()
    {
        return "SmartCardMessageDecryptionTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testX25519Key();
        testLegacyX25519Key();

        testFixedRSA2048Key();

        testRSA2048Key();
        testRSA3072Key();
        testRSA4096Key();

        testNISTP256ECDHKey();
        testNISTP384ECDHKey();
        testNISTP521ECDHKey();

        testBrainpoolP256r1ECDHKey();
        testBrainpoolP384r1ECDHKey();
        testBrainpoolP512r1ECDHKey();
    }

    private void testFixedRSA2048Key()
        throws IOException, PGPException, CardException
    {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: 03D6 5E27 0344 A9DD EABC  E33D B698 B8A3 78E7 BFE9\n" +
                "Comment: Alice <alice@example.org>\n" +
                "\n" +
                "lQOYBGp0UV4BCAC55vu0Xxq+9P/VMO+SsfdYfsRWhAzJsaPdi+OOS9ajtpxMsWrh\n" +
                "aEi6kStftkiKuH9FTPlZMeFiSBWpi5mWAVm0pYdQKT7J4XMSp0kr5MX+uy1Caw4d\n" +
                "jJQ8h5M/36xGN+qPNxHhvy29DBg50YDRiA+a+Hfp4iUTOWQbgNtv6wLsmlz153Kd\n" +
                "gEAwwcyiEz0QJXYi2JH7cU1yZd0rcYM55cMH11xqml8jXfavPa5YDWdQT9wvSL6i\n" +
                "b91W7n97QCO2zBm9u/oPQvZ839PjdstPD+VRJhi2aej3t/oq9xvY1xsBIOVqmWKa\n" +
                "qFUwXjaEpJbJn5lT1oXrZeAVyqkIjbQ3ASL7ABEBAAEAB/oDMmSrsmL8W6w2l1PX\n" +
                "WvYc8Hkh3710jnh569jq7oTvZcmETBzBaZCunKZ5S+IteIS/xVYYYZI1pXWx57Op\n" +
                "b7aCM8KC72KkCBt5e6T3e0SoX8GkfcDNY0h9TfuLQqZswrNm6RSGpEn+EUItZFvp\n" +
                "voQ+Lv2o6PmoPflpu6qKXyk6tllXZZKqyFrncNGkxCLFkmSOAFx0QD13TusNF/uw\n" +
                "Oc4w5vNTzmXylGWUHYao47UyiRxxqf5/EfbQU5bfghow4YxWRoqvSOu8vs/EGXf7\n" +
                "sHquIzkHuU1Xw7sbh3P1nyJipAPP8we01iEB8n+8rvfZkiScsORg3TlxQWELMJLX\n" +
                "7IbhBADUPk+Yz1onIVy/c79oOEUHzLqwQw5UjHX3yQacN76fsXKAtKKhYSrBHw86\n" +
                "3hGub8LTq0bKKeA5VymH9IlvK7y3odfuzjFYDOTCpbE4kRT+9xM8+HmSznEvSg+9\n" +
                "gw1Mtk+QYIB8UkIgKEoZ/2aK05TCh5iCa+lbndd/yiFu1BJD0QQA4DpzuBsl8SC4\n" +
                "n8m/1V0taB0e6fxf2z5wYdxj6QFb+D688OQkUaOu+JH5k2kXMBOXCFbunFJLhX6n\n" +
                "2JyGng8YMU+1fKRseXzNv3yjtXXeMdpvua5qwZa/NkMiFv4WIJKBuecm1YD/V8S6\n" +
                "AP5hlqDcr4nMpjGp4M9xnd7hBP1P6QsD/iqSGSmzOpOUY8hz38j73qKzAgK3gx3k\n" +
                "dVndhH0fyxKfX0SpW6nhISpAiuEyRmfWY8dA9+TQzrc2uw0/plGD0aywL2Bj+j0n\n" +
                "VqfIFacXtzQvPBX/34M9l88Y6nKMWWI1FNVKJGglpu6xUm5zzUYyj11vSzbXll1Z\n" +
                "3JxQ5G6aRLEeTHLCwJkEHwEKAEMWoQQD1l4nA0Sp3eq84z22mLijeOe/6QWCanRR\n" +
                "XgIeCQYVDgwKCQgFFgABAgMECwkIBwcnCQIIAgcCApsBBQkJZgGAAAoJELaYuKN4\n" +
                "57/p+wQH/iSyJCP0GaL/qVtdMr8Rx5z4ncKNpz1R0FS6Dw4zaB8tUs4UwSWxqSiP\n" +
                "zchCu/Y2HIwfq/QgwLkRkSFKonTpV/JPSqUjsJthMSOK0ZrXPyUPraFvcb3WpiOV\n" +
                "S/yEJhP8bOaobyhKc79gmVMw5EI+xAEMhQzyNQ9jEDgwXWdI+GhwTMWTvy9YQUei\n" +
                "LxS+FTUGLvTNxsIKB2fIeYan6gXhpfMDCA4wXmut4EzbHpq5nJYRHfDEdg4uKpBG\n" +
                "YrqTrHVVS0fqgNtHsshFuAxee2QRTxEJ2+Cil2+6prTKSGIgOGzPjdIkSJvFcL49\n" +
                "erbXW5uf67Ul7OIVC4dYz0RucdliYK60GUFsaWNlIDxhbGljZUBleGFtcGxlLm9y\n" +
                "Zz7CwHMEEwEKAB0WoQQD1l4nA0Sp3eq84z22mLijeOe/6QWCanRRXgAKCRC2mLij\n" +
                "eOe/6eVaB/4sDvJ6cBPQY/FVIRUfuFb2Nl7nKd3YFp05dlp0YXnuNVKi2eAHwU/d\n" +
                "U8OOcV0hhVslmKkuVSiVvHJnuVIAabkwzdgBvE+xI6UMzbY5KeCwEQiPFC/0aIfH\n" +
                "ltoANc+9n5FQlf2h6+d/xEOoO3SP042hyEz740J7tair+jhht2px+KM4PxxA3HnL\n" +
                "2p0CiVZDVGaXbiyE+drUFJsLJu0Ym+iWXfr/Hp3leD446oGqAoYaJul3AeSbiSBA\n" +
                "J/LpE+IqR1WyGdLaQ8g9LbsHPWRtydgDaVJ8R652WdILjraj2612WrUVGLzc+wsH\n" +
                "nPo8O4tozRX4IJImQCdWLax40ONgjSalnQOYBGp0UV4BCAC0LIclK0OIZRLHG3jC\n" +
                "PJ8MAVPC3W4snvru5tYCxqkzOmoNh7VP+nohCMpuvc7crVGJTLR8HwS+2kq+ZDAD\n" +
                "qLRiNVhCOL8hQC6k7fQO2sJ1gjSrc03ZUklMbAX5z93jrXpHKa/pXXywnwL3plWZ\n" +
                "5hbAciTOkmaCd9UQBXhs6W4DxkHclLxzOqaI0NWc6GBpgaA0YcoRmFmUWP2I27vx\n" +
                "f9H79lyQoTAOvj8+9GiYZlSaLjJt3djkPD1dpNSoHO8oKNoDluy12+rZeH7XJ5i0\n" +
                "txdSQCMI/loYKDWNnjPdmUqTTtXW+R/yH2LJB4WT2BQoPawDWAKyfOorA4SJ2kGb\n" +
                "rVgTABEBAAEAB/4z8dSCyE7fj3hS9B4kLdMS5H0QJMPjVHB3GREhWsIkVVaHERWa\n" +
                "edXlGUI3nDx8DfIAeh9c25qEJa4/5uWa4HQlDkkkSnT8MqNgBISFFdfThhcGSSds\n" +
                "HNeqE0jDxYSs4/JpeuDPEJdm2mlCGe/6/0WW9TGcZsPsIH1KcbFPARupNW8mSyNE\n" +
                "Bt07Q4r0MZL3PJ0lTS7Xthe3JR+nFtkSQxXYFcX0nFMLv1k7tCuXVstuPXSi8AL1\n" +
                "ohRcDLh+l8j8SV4TgXfi9S09OpNoMN6sgYsrhuQ8sL3J0xsnQKbu6DOaK9+fMfEY\n" +
                "lrCImpqo83yaF4t6u5AxKUhlYGLdBJef89NhBADUZT4H7/DpUJbHURmuDtVFxbd8\n" +
                "0HG40kzqS9EQVuL6eExMXivCpWuoCvwuJzzSu51AGHzB6je4odYsPGp88SFJ7nEb\n" +
                "N73FIpFSgVc/EmIaNn7NxNRYIQsAkM2mVJNm4uQihEj+/TEjp3ApiXr6AIkEaKHL\n" +
                "5S9GAtIw/JFDreNocwQA2SnVwmDABkKWhjUlfuQlcQa4ZASiskYFxxO84IZHx8Lq\n" +
                "dDXCxqn3Ryl9qSnleXtuKVR7p19LluTp4Id+4nr1gsCPrW7mxun6aSqOIbL3lIDI\n" +
                "KHxpp2x7pmaSx+V6nrab5j7kZYHQsCANNFWqpFNtEWrpHk1vi++n7+aiUWczieED\n" +
                "/12LLbtrvGKWhyksgCT3DxRFctRQhfI8jge7Bx+7Wv7jZfzaKShtD3Artei5aGh3\n" +
                "FKjk3NwvSgksjNzSFng6UB6V7mH8ADG+G0bDIytUSSBOg3FtO/bbzWsN26ENSTEj\n" +
                "Rwf0rGo9cF5rreV9RHVbODqr4MMNIE5sWOlUU8OTnRcoN2rCwawEGAEKAVYWoQQD\n" +
                "1l4nA0Sp3eq84z22mLijeOe/6QWCanRRXgKbAsB0oAQZAQoAHRahBEzEcgMTMJIv\n" +
                "U9XXkg5V4dGVg8vxBYJqdFFeAAoJEA5V4dGVg8vx+oIH/1lfLjvdAWypCNAtDLIh\n" +
                "79uieQMErFM/SyPh2LriiGxagBFmIiQ0K3QCl9tLMM0QBeJ79bPfZIHbpSCjcx91\n" +
                "5n/t/SOFRVOgoYPPzhPasElmqxSX+miAksJiXkm9cZt3NPoZBQ3M4JWF/kYH9nO/\n" +
                "N8xeYo6sgc/79v6RgytwuoKIW2H51A0zC5BVxajaY3GA4ZPl73BZCsGX2KtIH5g1\n" +
                "eugd/hGb1joKVDfdwUiuIX05h57xRvHOvEuNkVU1+JvhO493RE8fdlAxeUa2pKjX\n" +
                "N6nJZDtKGaWlAienpMftCuza4eIzgVdo//82ex55RAzIVvMAV3qPvxnDAASqSDgL\n" +
                "PgkACgkQtpi4o3jnv+l80wf5AZMP2vup6thgHDInWlOYjJEpJMnjv/szaC3fDfu5\n" +
                "Nz0uCrNW6wkkvNoI7D38KLpnZZ19Hu9fmQYMPHLfdTbqDNzyOSIiF7yxzp49hC7r\n" +
                "RGNWke5qBLc9gdY703uHQwC8dmsQOnQiqlpOQjCXIVFeZiv33Aml2kTe8Ucric61\n" +
                "eTRx8G7luXvZgWkZJ3Cs3J/BRQyD+UonQnu5YuIjjHaCWoiUsziWmao4bvjbPgQH\n" +
                "Y2HDXsH10jG9lrjFsj3+NNxBpttaeDfSyhM86Yz0ufbwezdVkL7WPdcYiRGDJ0h8\n" +
                "NGh9IxyYUoD34MP9my/BVhOcGP6UzWENTpJykG5+PKT2n50DmARqdFFeAQgAtAzI\n" +
                "LpfxzX1Qcbx+qQ4ibNgJvP/Y7yTmZsqDMtbDdpjpR62xxZLDSMxy3AW0eK0XIBl0\n" +
                "vVW6JoTFukQ4tKkr0HvYlh6owsgCQrQ2Y3/J1tpMIk1WU8YmMCmQyJAJ1y7DFlQz\n" +
                "xNAgXxPJTQXaVzx0ddLRJTwFZTphgFeW33oy5eUa1hA5dl70tXpJzRre0iPEgK39\n" +
                "HeTOdEv9OpffopbZaHgd9B1dL5EUWKN9/ZOfPZlOc0sRtt8A4N3Ow9OdSOur+m8V\n" +
                "EkO2RVD+KB1qlhWcLh677x8rQCKnyNxzw/KxRKstEhA6fUYLTbiI6nGlZ1AxQUyY\n" +
                "pp25tNoqFJmlY/wewwARAQABAAf/T8dmH/clpmbDcVITUXc427+yOPOovPY9vQg4\n" +
                "sBsnSvKgUylsnt3T9/rXXhSNDfesSoXdC1PkAtNMBafa9HoNNvjZVFNLddtH3SSb\n" +
                "AOWLms7pcz2PZdlj7G1OgQAJzDYlLUysD6Yk4dwTkzRntcXM2LRMBdKdlWgT8dld\n" +
                "ubIcwW5O7IvRhzo/89YzCkp6RKopvHCj6Au/6TjpG7tlOdGxW6RFavHC7XRuasDh\n" +
                "WMD1TfI4H0N2VKNbA9UXHGkUofcwUGuojZQI1d5Vvw4TcpKApbiG+yopk05XZE6i\n" +
                "IBdbXJKSyfCX/VVTBmU1Fbou2iQTUf+o0r/b6XJhNmvpl5122QQAxrg0sjGvI8AE\n" +
                "9ZpL5I5H0ExrmuFvBA03vQG6/p3gYl23ywd2i0dZk2Mbl+jbk9L5UMbiUq3bQJAC\n" +
                "dmswSVUgedThk+t2uaZY0aRpreUs3w3NAuPweB7x7QuVYSNItiJ+vKqd5U50nQnF\n" +
                "d62EiXk3H7O13ymHPQg9ruIBPJI8lQ0EAOfy6xrp7AauXe7bea4zoms/Fyy+vfTi\n" +
                "yrUGXuTMaEtbayDQXEH0ABJR70nsHGlCw7GrNsF8L6XXLmGHHyT9kmuMoqUVF/O+\n" +
                "kEHoJCsg+aL3zzVkbDxeapS4YDhhBNu9xZUwBw4DnkUW8XDl511tl3bl56nRyIqS\n" +
                "7/FZCiZe2i8PBACTKCOCJA8ImaAymY9NMywC3537mZb5k3HGRKt4vUHZTZwXZeg8\n" +
                "UcwW0V2dzHcCx7aOK/hHvBjd7ZnWXuxl4Wc+/dU0wUW4YBIB9mMc7iIr97Yl6dWq\n" +
                "qT5B/DT6pMvm6zYCf0Y9b4IATWz4gwMra+pGJPjSUNFVON+V3p7hQooeDUNBwsB2\n" +
                "BBgBCgAgFqEEA9ZeJwNEqd3qvOM9tpi4o3jnv+kFgmp0UV4CmwwACgkQtpi4o3jn\n" +
                "v+mDpwgAoJeHv+XYOONdBrX6tue8Klp1GIyOgJyjpw1SwWov1L0PwxKssHcFLjJp\n" +
                "qEySrhQ6ueAgC1gq6X4iTBP9idyX9Z5QewNHLYf0RT4+MrDgA47B6hvFHxaytUVH\n" +
                "X3Z8hEHkMJd2AAytXP4P+9Y3aQSFmVStIqMkxO8surxBLHtQUPyV+0cViC6KtkRM\n" +
                "8gt5Fi04ZJVQgBnd1aAdxvG5agKFBE4MIQACKSUcQRcCHcFIBuUYR+ytzyZ/bXx1\n" +
                "7VnYFi+NgOuUYlN9ZDydZtPMv2vWMmjHNZiH0cMPqb1KrNKyw8iPzIwvhWcoa8iD\n" +
                "jJnZpryKw+5pvbfrQpj7JOJXGpPrUQ==\n" +
                "=kcdi\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcBaBhUEcgalz/7ROpoInJb86FgstKCBcyIBCACdqsPIREKZ9UjkwYdG/FKLRchy\n" +
                "6yhnChWLc8g1qlaGG29vomiu2+sc5dqZzZ2GOwENBvVUTiMCW2X+/j4vWPJ435RU\n" +
                "NFrc89mG7U+XZ8tAXiRDbvKKadUlj5a77vL4mIDMETT7NKHAfYstC1Aqz2sicOaP\n" +
                "PxUG6nONG5CAztAUgEtCoMjv7dHnw+8NB7uGbjreznbFFSnwuDL0vus6jtj37YPR\n" +
                "8ojGTVP5V09b2brV3jO1jmhmJfK205StLSsTf+76F2X8aWfKv2QVerRDvkXULikm\n" +
                "355rXCgQ8nTaP9RKeE53KHbWpjDDdavs8ClYpJtybHnvYsgBTq76Wpc2myDi0sCu\n" +
                "AgkCAHpvOyXGD1AJridQ/6dQK86R1rfqDybcdHC2mJhb5x1OuABqGhCq7V3U3avs\n" +
                "fLbKJ4IC03rjx0q731so9ock4T6uvqStjMFEA4pZFpgtvQzSkSrq4lovSX3LeDpG\n" +
                "9meXTTA5D7NgfkxuEte85Ofx3n0Unacetws1D5UGZeO2n/ty5T1AiROACyHc4d3U\n" +
                "5Ayx+3BhAY296EJD3Sh8Ti2yMo7W5vsu/koT+2qryfuVoZhej5++7UpXR6kgQ5O6\n" +
                "HJHTVcQh7JDYTnOrkho4Cq0Yvmyaqs2A9ZG2Q/B6viyLw6/Jm5HVo/uFMVyAfzf8\n" +
                "BHySf7375akGbXaTRnCQDFsaDX76CvLSXTD5RJn5godgOZZqG+jfUER4vfiQrNVL\n" +
                "mIfyJl7brAvaatd6i8U0kYXXB8E+Moul7ldqAjtjQvpIe1gpAZnnOG95hV0jIqPe\n" +
                "5SzBdRKVVn2p9FuyFdRnIR5Ha3eDPEDnju9zJ3fy\n" +
                "-----END PGP MESSAGE-----";
        // Expect pEnc: 272122ec0b4fd60ecca9533b10bc26a9f9e9f2a2a416b53c383e414127bfcce27173aeb22966c5dd6779301eef78185bffee42a9773026e964143755065ca3ed74dbe576bd1577c13b1c3ca8e2a0e0d6498459aa38f94a61ba3a4dfb396314e1314043c5dfb0e7023a1262d838573e8e6d35b0acbb9115d11c6c54b4d216857de9e6e82003a12850b1ad82343de05d99340c87ed1e77c3f4fcd14a4626a9c3ecce97e3480369e915f047a3b39cfc6010101baaffbc6289d48adca16f9a59d5c5d1d4f709d1e17d14682b7acef8cc3f4c56d4f2c75e7516a28e300543b5608bdbc9614fc15e34539307fe26505d2970585ab59967973e1baff95f17624d2989a15dc904ede6ea5223430d72cec747865ddfa5919caaccb0e11775f780279ad82162e3f43c7c5c9595b3cd788e35e8473d2adc50f843f3ce58896ef2c662336e4e7a0a7baca45eb0848c2b466c988fb2de1db926aad749049a4b26cfc400e3fe17c79a1e3c9c4121e1505f53710fa608880ba23dd621a654b5213323b7ecbc79b7
        // Expect decSessionKey: fd8eea5fb08fb7d070da66a41a12237845a2ab84014956c7fdcc3df02e0db6591072

        BcOpenPGPApi api = new BcOpenPGPApi();
        OpenPGPKey key = api.readKeyOrCertificate()
                .parseKey(KEY);
        testDecryptWithExternalKey(key, MSG);
    }

    private void testRSA2048Key()
        throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with 2048-bit RSA key");
        OpenPGPKey rsaKey = api.generateKey(4)
                .compositeRSAKey(2048, "Alice <alice@example.org>")
                .build();
        testEncryptionAndDecryptionWithExternalKey(rsaKey);
    }

    private void testRSA3072Key()
        throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with 3072-bit RSA key");
        OpenPGPKey rsaKey = api.generateKey(4)
                .compositeRSAKey(3072, "Alice <alice@example.org>")
                .build();
        testEncryptionAndDecryptionWithExternalKey(rsaKey);
    }

    private void testRSA4096Key()
        throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with 4096-bit RSA key");
        OpenPGPKey rsaKey = api.generateKey(4)
                .compositeRSAKey(4096, "Alice <alice@example.org>")
                .build();
        testEncryptionAndDecryptionWithExternalKey(rsaKey);
    }

    private void testNISTP256ECDHKey()
        throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with NIST-P256 ECDH key");
        OpenPGPKey ecdhKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP256ECDHKeyPair)
                .build();
        testEncryptionAndDecryptionWithExternalKey(ecdhKey);
    }

    private void testNISTP384ECDHKey()
        throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with NIST-P384 ECDH key");
        OpenPGPKey ecdhKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP384ECDHKeyPair)
                .build();
        testEncryptionAndDecryptionWithExternalKey(ecdhKey);
    }

    private void testNISTP521ECDHKey()
        throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with NIST-P521 ECDH key");
        OpenPGPKey ecdhKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateNistP521ECDHKeyPair)
                .build();
        testEncryptionAndDecryptionWithExternalKey(ecdhKey);
    }

    private void testBrainpoolP256r1ECDHKey()
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with Brainpool-P256r1 ECDH key");
        OpenPGPKey ecdhKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateBrainpoolP256r1ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateBrainpoolP256r1ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateBrainpoolP256r1ECDHKeyPair)
                .build();
        testEncryptionAndDecryptionWithExternalKey(ecdhKey);
    }

    private void testBrainpoolP384r1ECDHKey()
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with Brainpool-P384r1 ECDH key");
        OpenPGPKey ecdhKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateBrainpoolP384r1ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateBrainpoolP384r1ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateBrainpoolP384r1ECDHKeyPair)
                .build();
        testEncryptionAndDecryptionWithExternalKey(ecdhKey);
    }

    private void testBrainpoolP512r1ECDHKey()
            throws CardException, PGPException, IOException
    {
        // -DM System.out.println
        System.out.println("Test decryption with Brainpool-P512r1 ECDH key");
        OpenPGPKey ecdhKey = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateBrainpoolP512r1ECDSAKeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateBrainpoolP512r1ECDSAKeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateBrainpoolP512r1ECDHKeyPair)
                .build();
        testEncryptionAndDecryptionWithExternalKey(ecdhKey);
    }

    private void testLegacyX25519Key()
        throws PGPException, IOException, CardException
    {
        // -DM System.out.println
        System.out.println("Test decryption with legacy X25519 key");
        OpenPGPKey x25519Key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateLegacyX25519KeyPair)
                .build();
        testEncryptionAndDecryptionWithExternalKey(x25519Key);
    }

    private void testX25519Key()
        throws PGPException, IOException, CardException
    {
        // -DM System.out.println
        System.out.println("Test decryption with X25519 key");
        OpenPGPKey x25519Key = api.generateKey(4)
                .withPrimaryKey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd25519KeyPair)
                .addSigningSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey((KeyPairGeneratorCallback) PGPKeyPairGenerator::generateX25519KeyPair)
                .build();
        testEncryptionAndDecryptionWithExternalKey(x25519Key);
    }

    private void testEncryptionAndDecryptionWithExternalKey(OpenPGPKey softwareKey)
        throws PGPException, IOException, CardException
    {
        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        // -DM System.out.println
        System.out.println("Test on " + card.getCardType() + " " + card.getVersion() + " (" + card.getBackend().getName() + ")");
        card.reset();
        // -DM System.out.println
        System.out.println(softwareKey.toAsciiArmoredString());

        char[] adminPin = properties.getAdminPin();

        OpenPGPKey externalKey = toExternalKey(softwareKey, null);

        // Upload keys to card
        OpenPGPKey.OpenPGPSecretKey decryptionKey = softwareKey.getSecretKey(softwareKey.getEncryptionKeys().get(0));
        card.uploadDecryptionKey(decryptionKey.unlock(), adminPin);

        // Generate encrypted message
        byte[] plaintext = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = api.signAndOrEncryptMessage()
                .addEncryptionCertificate(softwareKey.toCertificate())
                .open(bOut);
        mOut.write(plaintext);
        mOut.close();

        // -DM System.out.println
        System.out.println(bOut);

        // Decrypt message using card
        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addDecryptionKey(externalKey, properties.getUserPin())
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .process(bIn);
        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, bOut);
        mIn.close();

        isTrue("Decrypted plaintext mismatch",
                Arrays.areEqual(plaintext, bOut.toByteArray()));
    }

    private void testDecryptWithExternalKey(OpenPGPKey softwareKey, String message)
        throws CardException, IOException, PGPException
    {
        OpenPGPSmartCard card = manager.findSmartCard(properties.getSerialNumber());
        // -DM System.out.println
        System.out.println("Decrypt on " + card.getCardType() + " " + card.getVersion()  + " (" + card.getBackend().getName() + ")");
        card.reset();
        // -DM System.out.println
        System.out.println(softwareKey.toAsciiArmoredString());

        char[] adminPin = properties.getAdminPin();

        OpenPGPKey externalKey = toExternalKey(softwareKey, null);

        // Upload keys to card
        OpenPGPKey.OpenPGPSecretKey decryptionKey = softwareKey.getSecretKey(softwareKey.getEncryptionKeys().get(0));
        card.uploadDecryptionKey(decryptionKey.unlock(), adminPin);

        // Decrypt message using card
        ByteArrayInputStream bIn = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addDecryptionKey(externalKey, properties.getUserPin())
                .addPublicKeyDataDecryptorFactoryProvider(manager)
                .process(bIn);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Streams.pipeAll(mIn, bOut);
        mIn.close();
    }

    public static void main(String[] args)
        throws CardException
    {
        SmartCardTestProperties p;
        OpenPGPSmartCardManager m;

        // BCYK
        try
        {
            p = new YubikeyTestProperties();
            m = YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager(p, YubikeySmartCardBackend.bcImpl());
            runTest(new SmartCardMessageDecryptionTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SmartCardMessageDecryptionTest on BC Yubikey.");
        }

        // JCYK
        try
        {
            p = new YubikeyTestProperties();
            m = YubikeyTestInstanceProvider.prepareOneYubikeySmartCardManager(p, YubikeySmartCardBackend.jceImpl());
            runTest(new SmartCardMessageDecryptionTest(m, p));
        }
        catch (YubikeyTestInstanceProvider.YubikeySetupException e)
        {
            // -DM System.out.println
            System.out.println("Skipping run of SmartCardMessageDecryptionTest on JCE Yubikey.");
        }

        SimulatorSmartCardBackend sim = new SimulatorSmartCardBackend();
        sim.addSmartCard(new SimulatorOpenPGPSmartCard(sim, 1312));
        m = new OpenPGPSmartCardManager()
                .addBackend(sim);
        p = new SmartCardTestProperties(1312);
        runTest(new SmartCardMessageDecryptionTest(m, p));
    }
}
