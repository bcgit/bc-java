package org.bouncycastle.oer.test;


import java.io.ByteArrayInputStream;

import junit.framework.TestCase;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncrypted;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.util.encoders.Hex;

public class TestFromVector extends TestCase
{

    public void testFoo() throws Exception {
        byte[] item = Hex.decode("03820101826cc2023b5115003e8083996da81b76fbdcaae0289abddfaf2b7198\n" +
            "456dbe5495e58c7c61e32a2c2610ca49a6e39470e44e37f302da99da444426f3\n" +
            "68211d919a06c57b574647b97ccc5180eaf3a6736b866446b150131382011c1e\n" +
            "56af1083537123946957844cc5906698a777dddc317966a3920e16cfad39c697\n" +
            "7f28156bd849b57e33b2a9abd1caa8a08520084214b865a355f6d274c3a64694\n" +
            "b81b605b729c2a6fbe88c561e591a055713698d40cabe196b1c96fefccc05f97\n" +
            "7beef6ce3528950c0e05f1c43749fd06114641c0442d0c952eb2eb0fa6b6f0b3\n" +
            "142c6a7e170c2520edf79076c0b6000d4216af50a72955a28e48b0d5ba14b05e\n" +
            "3ed4e5220c8bcc207070f6738b3b6ecabe056584b971df2a515bccd129bb614d\n" +
            "2666a461542fa4c4d25a67a91bacda14fba0310cb937fa9d5d3351f17272eef2\n" +
            "b6e492c3d7a02df81befed05139ce58a9c7f5d2f24f8acd99c4f8a8adbdd6a53\n" +
            "5f89a8a406430d3a335caa563b35bbb0733379d58f9056d017fdd7");

        OERInputStream in = new OERInputStream(new ByteArrayInputStream(item));

        EtsiTs103097DataEncrypted data = EtsiTs103097DataEncrypted.getInstance(in.parse(IEEE1609dot2.Ieee1609Dot2Data.build()));

        System.out.println();

    }
}
