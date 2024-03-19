module org.bouncycastle.mls
{
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
