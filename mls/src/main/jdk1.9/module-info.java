module org.bouncycastle.mls
{
    provides java.security.Provider with org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
    
    requires java.logging;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.util;
    requires org.bouncycastle.pkix;

    exports org.bouncycastle.mls;
    exports org.bouncycastle.mls.client;
    exports org.bouncycastle.mls.protocol;
    exports org.bouncycastle.mls.codec;
    exports org.bouncycastle.mls.crypto;
    exports org.bouncycastle.mls.crypto.bc;
}
