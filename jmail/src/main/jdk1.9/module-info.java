module org.bouncycastle.mail
{
    requires org.bouncycastle.provider;
    requires transitive org.bouncycastle.pkix;
    requires jakarta.mail;
    requires jakarta.activation;

    exports org.bouncycastle.mail.smime;
    exports org.bouncycastle.mail.smime.examples;
    exports org.bouncycastle.mail.smime.handlers;
    exports org.bouncycastle.mail.smime.util;
    exports org.bouncycastle.mail.smime.validator;
}
