package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BCPGOutputStreamTest extends SimpleTest {

    private void testForceNewPacketFormat() throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.CURRENT);

        new UserIDPacket("Alice").encode(pOut);
        new UserIDPacket("Bob").encode(pOut);

        pOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        BCPGInputStream pIn = new BCPGInputStream(bIn);

        isTrue(pIn.readPacket().hasNewPacketFormat());
        isTrue(pIn.readPacket().hasNewPacketFormat());
    }

    private void testForceOldPacketFormat() throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.LEGACY);

        new UserIDPacket("Alice").encode(pOut);
        new UserIDPacket("Bob").encode(pOut);

        pOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        BCPGInputStream pIn = new BCPGInputStream(bIn);

        isTrue(!pIn.readPacket().hasNewPacketFormat());
        isTrue(!pIn.readPacket().hasNewPacketFormat());
    }

    private void testRoundTripPacketFormat() throws IOException {
        List<UserIDPacket> oldPackets = new ArrayList<>();
        ByteArrayInputStream obIn = new ByteArrayInputStream(Hex.decode("b405416c696365b403426f62"));
        BCPGInputStream opIn = new BCPGInputStream(obIn);
        oldPackets.add((UserIDPacket) opIn.readPacket());
        oldPackets.add((UserIDPacket) opIn.readPacket());

        List<UserIDPacket> newPackets = new ArrayList<>();
        ByteArrayInputStream nbIn = new ByteArrayInputStream(Hex.decode("cd05416c696365cd03426f62"));
        BCPGInputStream npIn = new BCPGInputStream(nbIn);
        newPackets.add((UserIDPacket) npIn.readPacket());
        newPackets.add((UserIDPacket) npIn.readPacket());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.ROUNDTRIP);

        // Write New, Old, Old, New
        pOut.writePacket(newPackets.get(0));
        pOut.writePacket(oldPackets.get(0));
        pOut.writePacket(oldPackets.get(1));
        pOut.writePacket(newPackets.get(1));
        pOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        BCPGInputStream pIn = new BCPGInputStream(bIn);

        // Test New, Old, Old, New
        isTrue(pIn.readPacket().hasNewPacketFormat());
        isTrue(!pIn.readPacket().hasNewPacketFormat());
        isTrue(!pIn.readPacket().hasNewPacketFormat());
        isTrue(pIn.readPacket().hasNewPacketFormat());
    }

    private void testRoundtripMixedPacketFormats() throws IOException {
        // Certificate with mixed new and old packet formats
        // The primary key + sigs use new format
        // The signing subkey + sigs use old format
        // The encryption subkey + sigs use new format again
        String encodedCert = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: BCPG v@RELEASE_NAME@\n" +
                "\n" +
                "xcTGBGYvuZUBDACyFv3LQiubgHM4eJUFnsLEei8/l4bGKdVx8hRu6N5rfcjZt3RM\n" +
                "UGUi+HQDnRbUvJ5B/7qDB7Ia7bpRf7BrYmho5vqNtjpxUPs3Mct1TjqCm2yLC9zH\n" +
                "+qHmGSPX4dLtSKKpXc4iBMGtFknhXKnoUovv7XZDecIIDbJhaqoFptRfqFc30SRj\n" +
                "ktQcyXutcIYlhaPQ/JtJlNWfmo0+NTEjfpDOZovCzAi769QnljntkiKXxQzBihzb\n" +
                "f1Ou7NzJ17m/7pJXBOTKKXboMFDc1ct6f2s2lomEhCYRPRC6eITWpXK/G7e503xS\n" +
                "eaMnd29BrmbEnw6QgCjafu72t8rgD6jbj3+kaRR85AevLWrfefo9ofhUMl0DDKc+\n" +
                "bhNQAMRZY9vlRdEo0pNLL9kIMzl10HL9viRXxCwp4d1chH0qLQdy8W13WrjhS0Fw\n" +
                "GlEkcTt2Z/4kGmYeLvBfQqfz62owIR47otX8JU+QdTmP89SyZRyuHVwB+Pgg32oC\n" +
                "1fSJUVHRCb6f1z0AEQEAAf4JAwJgAx2GH4oiN2CgjB+JAKrjlbrfjhLDN+w14SeC\n" +
                "vGpP40Ay/bUFYgfvkVA3CQFMYJ4fCKluhu2cHAhzCrGCAKs42ZvkKzHuDohzEjGG\n" +
                "N9IkA4y/Gv2tTewhtMALxbHtS7CCX6IBqC292mupm7ND4aULhLM4xqXKXUny543V\n" +
                "hPJEuKL8D5CLRqFJPtrw/791izbdr6J+rKxYwscL5NiUJQFLVsK59+7sJvSvBK9N\n" +
                "DIiFT+hRSJjb6rBrXWZK0bUCsaCLHL0k8PLPdBdzZ3YJqcaIFRd0Sq7l7Ck7RxXh\n" +
                "L8tf8Swcr1UafMMYbyMJW5VtJxZStV1OgdWVatrbkW5GINlZ7pp63kIOY2GbK99H\n" +
                "Q4mAQV1EpAlItF4QqkOunyGqw6aN5x9+Hoyr0O17428604wsptZstNT0wz3qGJJ/\n" +
                "ye3I9xveEMhRwv1ZB3MsiiBLj5kEa2l4W6O3g/6Sdu75MGhalyi5+r41SgKkxMWI\n" +
                "OCTZMWCNZ1ZR9Ehlsg5uOtNUc9RkAn9BAfBzDwBMMa8wzHKsNiaiR2Tonpm1+miB\n" +
                "TtBU7RUw5CEAcGbnYmLvlxVwe7CTVezYIQIroCCqY738Y5mpOSB0UhT1JAORPCJJ\n" +
                "PCWRGQ9UDm0xK/dFbbRNTJqYM2GZKOM5esnKQlxJ1t9+VoQ+mPLOPHnkmUXU8Rq8\n" +
                "9c3bLogW/dsCm0j8lfV0sKsAXfuD3spHPoJwQOFwZ4kDeFjJlRTusNSgXQsRF/x4\n" +
                "Wvwt+jmxRwenkeVunigqZVOhctf8ozkncpCV8tTLp8X2VrlJNx5XoggFzOwEWxJa\n" +
                "mMx1gvsAlsEiTCK5g6xocULxKfBfJogUrBXZk0GUJriJzB470QMnQ49a4gGFh4w7\n" +
                "Wh2/FiRRMIGTTXPFHSQ92kaWoqO1jDhM7c6HrxEETS7NrWi6TLvfYxrCZ9GlYanK\n" +
                "MPDa75lVpuE95M1+dRShX13LJpSlOq8Eius/kP9W54sCT4DTIvlz08QdcaNpRN/9\n" +
                "ZZGJw6gMttshvvl1eOKOjD3iW110qJtxh/W4OxgDL7R+JKKYfjc9lWMIhfy1sOQK\n" +
                "cmXZVP6HVK5y+xwW8h8MTqjUznYo1Lfu6icmBm7q0/P2lSkBSQ76kSL4exgtYr4k\n" +
                "XRj483ipnlUr8ue53ALXOC46NIj8wE2+LDg1rAt3AWru1fOGFMU4bol7ytBoBKmz\n" +
                "Cvv/6hxDZGSR43n+FLWMd40hRjneeM+0oy/6vvU0Rsa3FdL7m+/Rui8CC4JoG/Kc\n" +
                "xl3uj0OgfHvHYPjLoXOPUdPNIptwfCQ9xvEfWWJA4hcyRdToy1gjYINSmJDIhYgL\n" +
                "yyFlm2GlHMKDo71TEODRwNHy61Jdikx43c0ZQWxpY2UgPGFsaWNlQGV4YW1wbGUu\n" +
                "Y29tPsLA+QQTAQoAIwUCZi+5lwKbAQIeARYhBLSFPwVS++7sNFWR0nm9t4YHzlXs\n" +
                "AAoJEHm9t4YHzlXs7soL/jtmG5E6helkBjFLZqBfXJUxIniEtOxT0GrePTfA7lde\n" +
                "0hKDh3Wjh0+RmfnuatopWW1DRKmhnS0uAIwIewIH7rzhHG+i9OHAwZ6R61ptEKmH\n" +
                "WL5JeqTNq3bLD6U6VgfrFq1DNxtfTWTPwTzSIBuGVLJjRFEqq5olH4dD6xImO7Lk\n" +
                "t3KJ9Du8IdmLsoEcw0tMhd5cSbh2gE1F1CnmSufDts2coTv7B/lQTAhOFQQedMFa\n" +
                "N/mKJ/v+DvRjB9nV+rYqeqweTLJ2AJcmnmDTiue74CgP2o84Cf7JEAZ83vy2hHLq\n" +
                "KGvsYbQoE1oSt7vU9otGotSutrFZww8LmnkJCQwHPrNWC21CKoo/7bGo4ToDaVOw\n" +
                "FEC9l2pusMaN6y9ztsq2Wz3mlQppe0kizMmkA+WM34Lu0EI3DGQvqIcIMKEg242B\n" +
                "e8gV2qN7t/zMvLM34A4sDD7L1e8dKKnru0MY73TaMAw+kbRuM/DrQpT4PI1cvD4j\n" +
                "xN/rVB0g4JIuVElygMLA950FhgRmL7mVAQwA2WGMqveX3ssz5tdKIP6q8krGSwsF\n" +
                "CR7qBGVac5XiYaNzg6YJX+r8CiSAT+mN55t7TN9C7kND9zlssLJidKuXs87Bgwjl\n" +
                "gmuO0AL9VFKTx2IkEVovwwKvozJd9vt79IKY6wJ4eqbElaBfNy2uov4kuOxcEEuY\n" +
                "n7UQttW6Pp0JFP1lb+hZ524r05wYb7LGdPyz1vNPeYEg48PkcNU6Z9DXfU80JVp8\n" +
                "Cy0XNxHm31ML/DgLJHIVZ0dstA2KZnWxhlKNNfdmYakGEU5QISGViReybcc3kwco\n" +
                "v5agauCUWNFvLM7NYI7S1m5A0r6hWM/CtQwUgb0PIT97nEbYmIB+su+6RTLvOkMM\n" +
                "3465MxjBVwwiWFpZcHiUP3q5Eelr1V75rOwII3HKSC1tfZwjWxyzdBpPZDpMIxHT\n" +
                "9ldJnlLzIvUOR2pSusqnGrCeurGqNxT/b9lEifoHcDNiyo+Qj4WsOjp+I9sBkfYP\n" +
                "G3Hbx/OmKvkSY4a+L53iY2H1xjAfYwySI5KBABEBAAH+CQMCYAMdhh+KIjdg8Sop\n" +
                "plGYPDvXQ3N1JgtYiGXjOuvsEIuxqmY4CwtFATtqjphFPe+6GL4zS16vcGlAPwgI\n" +
                "h0+aZQxPHKJcUx997zm9PFrOjnSInFraAdIvpBay+5DlicGJuARZ/8ZhNZ7qxbIT\n" +
                "vi5ZVRnrPef6SO5E1zeSFodMV5FZE1fZNTeSq2AOQ/tIkMPsjK/BpKSTLSebkwii\n" +
                "G3IgQEB6albQsfpKTqSCgDS9o0/b5/q+KMYtHoS0XwoE46df1wfjirz6zNY6VShd\n" +
                "3MaJ+Jb1GzsRCTTedKHHnF/fU49uWs7LNRZT1PhSMBH/scL1w2u8bmdvW0i8PJaN\n" +
                "bbdX/Zs2sVxfACfeUSkF6GAmqnc1+6RnZSxMjSqk/1uPhtuSUa1NsJ9UlxHIQcDp\n" +
                "NGlQCrabUdhmjfZWtXCIcINXj0JPfMTNIxLC4YBSUvV+y//UEzq+LYT0tnOXeU6O\n" +
                "/JCzhEoGhPvboFfv8p3fPVvvLFseONZuX3d9WzbAQiCpCXlP4+Ro0OFw32JGTZLq\n" +
                "mi6eiJceAJ4sza4V/DeaDovJ62RJHzJOtb8+cOFyo+/8m46YMF07X2AwdjE8Az69\n" +
                "td1N79S9eqtYjV1VWrrf94fpeUGV4UD1ugt/UalGbGm4IQFTGZGb0vinImLoM7ts\n" +
                "84BneaosoYh/62bA5OzIF9xqHjFQ9XiNjwODFpiIZl3twL7DVDWf9Paq9ki1mv2D\n" +
                "pan8sJtsZYj0j0D+V9nDk5LSBiMnb+qaagq/Wt648eqaxGP1gb5B/w9rrYiF0/TX\n" +
                "H5q/qzHxh9j8sPEAM3R7Y9+IL1RgF0/3VgBx52/eJxVvb9FUZOoF7cvrESAFDqSo\n" +
                "p3/pN07kMN3fHNIFpQGbsC6ECmEatPnANJH0InDnPERTGasiCtshdzx8bTLIdh95\n" +
                "3hTJuv6ML8+PP9Jp4eLiAkinW+leBEyFgpYMFBdSifQ5R/jU7n/6IcW/4u5t66if\n" +
                "RFnE0N2hpMUQPTl5hZH5TY9AU55MZCLzvDbYW/cXmIuBuRNVfaLIWSKp8UxFwZfk\n" +
                "zki8N+EUPeB1dPaFapuArvpmSAl7uLzNYAb7X4Tf29VBlz2zRhh2dMAOtzX+55YX\n" +
                "nNE2gEiGP1FAA00l/nIKWIHf0u6zMO0jj6soSwsan9VfoyK9jc7qDObPrW0v0lsK\n" +
                "0CknbavMkrS+DdhTWAzYhvdSUZV80H/lRUwrTyCpaiRuuDu+kZOScTH1JsFkDEix\n" +
                "NypeMhSIh5Izzf0njazQSxzoI6XcEJLukFPONvZ0oTsXF1j0IITFboWjQpuUJ/kg\n" +
                "ZGBuBlllk2gD7t3H8r1zRiKkHaw9Nr4Fr4r5wNJVfVKrnQkuQBJneP2JA1UEGAEK\n" +
                "Ab8FAmYvuZcCmwIWIQS0hT8FUvvu7DRVkdJ5vbeGB85V7MDdIAQZAQoABgUCZi+5\n" +
                "lwAKCRDVw7vf0dE2sN77DACUd5X+RFI264quxxPZlO/jmcu3PfoeGtWL4ILMZ8Lj\n" +
                "4NyoqctmRthZzEvvyzmg/IQOPJlIru18aJKZQgrKkQzytbd+BL8GfsTXh7XwICcu\n" +
                "xS9pzMMKi29rU8ViwK+4blAjxGcPRrniJYBn7NWAlumjpUVCzoIpjcphpiCKTZlz\n" +
                "m2W4iWGSPzemDmOzEEWERafu3O08yS5n9zl2wrdOjClNC4Pmlyy8PH8b42mgMr4e\n" +
                "nP8CoTpzdFQbzSg/A3pfYgK+TLtVI9KZO4V/OIK6jppKUDg0ZA+GDUYC4mtjgHgQ\n" +
                "Qaj0OiAHxti1bYA/VgoBLI3D/AW5JNJ0XGUXO++qwR5rNa6Sgs2DATvBw6mLbiVV\n" +
                "pYBuDTnFRtXURm1pkD8Z+jSKz5eq7fEnO8GhnW+4ftPztXpucl85jtAHTqPFaiET\n" +
                "jDwrdmHNqvMdu0KQfd+D1bU8KSf2v/9h7LS/fyfxDxYgX15O4crtQV1Obq6yLbbA\n" +
                "G0YwRknIaPbq9qZx8iXue+kACgkQeb23hgfOVewMmgwAnJl4g0sX89VFz1OtMLJj\n" +
                "Ui2QvPCpMkhsrgbaLS3q+wSZIUTZWzTzcZhDajNs3f/KjL2Dm5UxkHD29DuUv++r\n" +
                "YPsVpWkk8wtD8/Am4CF1b5ibXboBrouAuju64pqrHjrM8/1WeZatYqkjShk5DqA2\n" +
                "PlgpHFxoRB/0QnUwp6kpu2Tr3CTrcn0tyyqbcwTr5pw5oBLWcWgc8LMIFV2zdnHa\n" +
                "bGvsew9puss1oh5Fs58XYg0Gdf/J/qelWgxbx/b4GHy5wxvb5BkbNMz7hWquZNsc\n" +
                "DRuCOwRwlhCY13rTDUwwonU/PMPwP9I6pU5LBx+xRt3p8CeE4f00ANdxbS6JI5iA\n" +
                "zqUsKIlUlwH+AO9VtRqiAJsVwaJVm/GOWJVeIKiz8M/jgiW0NCVJb01RW+3WVaY5\n" +
                "kpLKqE1V0xq4mxw16mjBguUx3HdR5rh3ZZJ0TfXGGDAhLQC7PXe3oQyN1NbbH2Vx\n" +
                "jVKueQsGPX2022pepiJXXtAzGIBR0eUOfylpewuerFwEx8TGBGYvuZUBDADjCLaD\n" +
                "w3L65khVSjpsu8jr9B72xbx/EIlXEKr2KXa1lvf0yadxKB5/KytXWffQ8lEMmdi9\n" +
                "p86+LIWIh7wx+mhh2g64um2yJiuS+HRTWWA69nb6/1Tl5G2VyT81AVQ5JAcNyIIS\n" +
                "RuWvzZoQDNf0sImT0o7dAK4KLtofGMy/rIaNebE2Qu4dks5aBjIV2/bPoIMrSuJF\n" +
                "UK5UsUOPx5jlYk5gpgyPcl30YgLf0Bizp4RJSCpIjjDJ6WvKBxlRChdfbP52vawI\n" +
                "IEcMGnWMVFvVd8I57v6HDtbQTgF8BepwgsWHnTGtoIkVnKc/nlM3LtNiJUY3z915\n" +
                "TZGRbYcuqWZhMbnJoQLRgQXh6/E4FzxDxaKoXpYXuPDxCTfNxeqU3hrRZUfKOdjw\n" +
                "+BS5rSicvbGaqgyz29518bG04hzrmWORoJExozWTOoE+kTU5+o7DmS7qtd+z63lL\n" +
                "bjqLhFALPl9qbwVlFlFo6X6jmlo8THVkX5lLI1+Qaq2g3G1YYCoXDMoGbk8AEQEA\n" +
                "Af4JAwJgAx2GH4oiN2BJ7FHcEtvbKapzj3N2OwxYHmWymAAjgPe10Ne2W7FFi4Qy\n" +
                "sj0Ss9NbWV5Nw4NqnE6syOFNVeLs5t7BdTqXs3NxOTJo0iS+lpL5OgUcMSWu2hN7\n" +
                "jDbeXEBZFSQ7epetVDAetYsKLZBHpsI19aamUEnRZicKATjVQud9pHhC9BTFp62i\n" +
                "D4a2IuxQcweuw5D8brKH9WfXYXlNzjoZdsqvWRWy77/6s2hg9V7lo65C/p8C0DB7\n" +
                "blJwptt9j/vTlzTyavV60rRma3VeMgQw5sn0b2lqWvmLRgpjmCv2AdD9A6rYU/4+\n" +
                "f+sknWq5c/gaoWAMWNg+vgRpZUT9C5ZlT86QUuz0DO7ySoy0gy9Z3BID+JDcXP/b\n" +
                "BYftC7XQut+nnWGD+Pr2E0YvrTQLw0ISCzKyCI9iZh0gvwv9bKdYOUSEhOM9zlk+\n" +
                "gt3hFJvVXvLbFUHEbh0Oep0AcCzFKzBrTYBeJ8Z8vvgNfie9zMtY3EAV4tBU2MVB\n" +
                "3JqgRJ9Qam/ZGJ47GIbkRnqrbCmL44U3Qvl9to4g96gmrQXfdJUAtpntewuuDguJ\n" +
                "MgKYUTv9TupYErHoTFlV61czXEwITE6y3TuePgWp4sY+BXGWyFc4puS+KNB+y+GC\n" +
                "hJdchAyJcVhsV2e7ElC2URVmGpDkW23qcRMFlu7QMaENI5itKEinKIPQokITO0l+\n" +
                "I13oJ4KlMEgfofNQ4rWdoqir7AqaQ+HXTV0l8iQQJPuAwXYnSe4xjuHuBssJ92Qk\n" +
                "B6H+7IGDvXwMikQzOkeZVrsL0f1Pg1DIPMgt5l4qleZ4aL0cDqBQHh3JLtXWQ4jp\n" +
                "ffYWxxCXILO10WYbqAaG4eXr/vsCb/TfADiF07azQMgWrhk3NSSoVRRjQgIntCAR\n" +
                "u9C2x6FcyeF4ND0eIciWH6+pby0xC9bg5XlKlgeMN/BoXnj/k34ZgoHbe6NmjhT2\n" +
                "bpgXrQQl4QPBS67jr2lU6NunmOwoHwX+epwIIKW8bcjvOTs0XEGVCJleIyUf88m6\n" +
                "bpV4WUmIk4I8ROztJRzxZpNB8HgZb9XzbOcXccUl8sjTOyMlQTIAl/qUIomJ8snH\n" +
                "lzEhoWYWzWUrEe42CVld++xhLQkgR/V484ch+vDi9EjmKCRVWVdOnHda9fHe5o8n\n" +
                "TQzMdG8Fvy2XrFQAeCdNkD+itwV1OIva9j9KQHadS9MVl5PYzy/ezwIrK9siXAXu\n" +
                "4YiaSTL4TPwjWppQCJJv8mQskNP72tc8TELA225MtsPcSPiCT1aLUUKQmpQstEeQ\n" +
                "S6Cv+uggbDXqWfow2mx5w4bJXLxpe09vm5rqBT6Scg2e4e3yRNiYGFXX2QsNVRui\n" +
                "nLCJLAUtpUJXBcLA9gQYAQoAIAUCZi+5lwKbDBYhBLSFPwVS++7sNFWR0nm9t4YH\n" +
                "zlXsAAoJEHm9t4YHzlXsaFsL/16ktY2/knugZ8bN1df/QzdDE30wWakcDqAZhEMb\n" +
                "+MyazHM08ipXFkvNsz0r7Y6DXqvOTvRlzXc7csk3Np/rrFFwpkckHXz1JkrQwAtD\n" +
                "rIMcmzqm25u7rKti0NfsacQI1mie+wFyrApvXTBF2av9Fn1ch07A4f6JTfD62KAo\n" +
                "ccBKAr38LVBwwGJZh6WqOazgoO8B4ia1MveHgOCsf3SurigXt1iMCCqWvvpQUil9\n" +
                "3hU8x1SNy0TajFwXSeAMTAyoWVlC7ceixVr9dPLgRuMbsfHYsBAMw9wHSSNVyqvl\n" +
                "vhB4X/j3bIFhl3iqj1P7Km33yVbk30KtKHuPFpHMJBu8CZ4/JcPnfGK35aTgfV9N\n" +
                "W9V5u+mtWKReL8Ii0/jQ53PGJ7I1m8uzLB83mmRYY2hoqxdzWTXB57oDJbPwZRSx\n" +
                "5puZWZ4WbmsHSaPe0gMIQH3ItcnWuB2sxhkpXSnOtXIK44lqcQwq69ygHEP11W85\n" +
                "3hRZb5W+1RCWcuPc/oWxMuwiBw==\n" +
                "=7IAh\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

        ByteArrayInputStream bIn = new ByteArrayInputStream(encodedCert.getBytes());
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objectFactory.nextObject();

        // ROUNDTRIP
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.ROUNDTRIP);
        secretKeys.encode(pOut);
        pOut.close();
        aOut.close();

        isEquals(encodedCert, bOut.toString());

        // NEW PACKET FORMAT
        bOut = new ByteArrayOutputStream();
        aOut = new ArmoredOutputStream(bOut);
        pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        secretKeys.encode(pOut);
        pOut.close();
        aOut.close();

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        Packet packet;
        while ((packet = pIn.readPacket()) != null) {
            isTrue(packet.hasNewPacketFormat());
        }

        // OLD PACKET FORMAT
        bOut = new ByteArrayOutputStream();
        aOut = new ArmoredOutputStream(bOut);
        pOut = new BCPGOutputStream(aOut, PacketFormat.LEGACY);
        secretKeys.encode(pOut);
        pOut.close();
        aOut.close();

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        while ((packet = pIn.readPacket()) != null) {
            isTrue(!packet.hasNewPacketFormat());
        }
    }

    @Override
    public String getName() {
        return "BCPGOutputStreamTest";
    }

    @Override
    public void performTest() throws Exception {
        testForceOldPacketFormat();
        testForceNewPacketFormat();
        testRoundTripPacketFormat();
        testRoundtripMixedPacketFormats();
    }

    public static void main(String[] args) {
        runTest(new BCPGOutputStreamTest());
    }
}
