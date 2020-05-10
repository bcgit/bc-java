package org.bouncycastle.mail.smime;

import javax.activation.CommandInfo;
import javax.activation.MailcapCommandMap;

class MailcapUtil
{
    static MailcapCommandMap addCommands(MailcapCommandMap mc)
    {
        CommandInfo[] commands = mc.getAllCommands("application/pkcs7-signature");
        boolean bcFound = false;
        for (int i = 0; i != commands.length; i++)
        {
            if ("org.bouncycastle.mail.smime.handlers.pkcs7_signature".equals(commands[i].getCommandClass()))
            {
                bcFound = true;
                break;
            }
        }

        // only call add if we're not there already.
        if (!bcFound)
        {
            mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
            mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
            mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
            mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
            mc.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
        }

        return mc;
    }
}
