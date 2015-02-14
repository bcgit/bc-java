package org.bouncycastle.crypto.generators;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Password hashing scheme BCrypt,
 * designed by Niels Provos and David Mazières, using the
 * String format and the Base64 encoding
 * of the reference implementation on OpenBSD
 */
public class OpenBSDBCrypt
{
    private static final byte[] encodingTable = // the Bcrypts encoding table for OpenBSD
        {
            (byte)'.', (byte)'/', (byte)'A', (byte)'B', (byte)'C', (byte)'D',
            (byte)'E', (byte)'F', (byte)'G', (byte)'H', (byte)'I', (byte)'J',
            (byte)'K', (byte)'L', (byte)'M', (byte)'N', (byte)'O', (byte)'P',
            (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U', (byte)'V',
            (byte)'W', (byte)'X', (byte)'Y', (byte)'Z', (byte)'a', (byte)'b',
            (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g', (byte)'h',
            (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
            (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t',
            (byte)'u', (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z',
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5',
            (byte)'6', (byte)'7', (byte)'8', (byte)'9'
        };
    /*
     * set up the decoding table.
     */
    private static final byte[] decodingTable = new byte[128];
    private static final String version = "2a"; // previous version was not UTF-8

    static
    {
        for (int i = 0; i < decodingTable.length; i++)
        {
            decodingTable[i] = (byte)0xff;
        }

        for (int i = 0; i < encodingTable.length; i++)
        {
            decodingTable[encodingTable[i]] = (byte)i;
        }
    }

    public OpenBSDBCrypt()
    {

    }

    /**
     * Creates a 60 character Bcrypt String, including
     * version, cost factor, salt and hash, separated by '$'
     *
     * @param cost     the cost factor, treated as an exponent of 2
     * @param salt     a 16 byte salt
     * @param password the password
     * @return a 60 character Bcrypt String
     */
    private static String createBcryptString(
        byte[] password,
        byte[] salt,
        int cost)
    {
        StringBuffer sb = new StringBuffer(60);
        sb.append('$');
        sb.append(version);
        sb.append('$');
        sb.append(cost < 10 ? ("0" + cost) : Integer.toString(cost));
        sb.append('$');
        sb.append(encodeData(salt));

        byte[] key = BCrypt.generate(password, salt, cost);

        sb.append(encodeData(key));

        return sb.toString();
    }

    /**
     * Creates a 60 character Bcrypt String, including
     * version, cost factor, salt and hash, separated by '$'
     *
     * @param cost     the cost factor, treated as an exponent of 2
     * @param salt     a 16 byte salt
     * @param password the password
     * @return a 60 character Bcrypt String
     */
    public static String generate(
        char[] password,
        byte[] salt,
        int cost)
    {
        if (password == null)
        {
            throw new IllegalArgumentException("Password required.");
        }
        if (salt == null)
        {
            throw new IllegalArgumentException("Salt required.");
        }
        else if (salt.length != 16)
        {
            throw new DataLengthException("16 byte salt required: " + salt.length);
        }
        if (cost < 4 || cost > 31) // Minimum rounds: 16, maximum 2^31
        {
            throw new IllegalArgumentException("Invalid cost factor.");
        }

        byte[] psw = Strings.toUTF8ByteArray(password);

        // 0 termination:

        byte[] tmp = new byte[psw.length >= 72 ? 72 : psw.length + 1];

        if (tmp.length > psw.length)
        {
            System.arraycopy(psw, 0, tmp, 0, psw.length);
        }
        else
        {
            System.arraycopy(psw, 0, tmp, 0, tmp.length);
        }

        Arrays.fill(psw, (byte)0);

        String rv = createBcryptString(tmp, salt, cost);

        Arrays.fill(tmp, (byte)0);

        return rv;
    }

    /**
     * Checks if a password corresponds to a 60 character Bcrypt String
     *
     * @param bcryptString a 60 character Bcrypt String, including
     *                     version, cost factor, salt and hash,
     *                     separated by '$'
     * @param password     the password as an array of chars
     * @return true if the password corresponds to the
     * Bcrypt String, otherwise false
     */
    public static boolean checkPassword(
        String bcryptString,
        char[] password)
    {
        // validate bcryptString:
        if (bcryptString.length() != 60)
        {
            throw new DataLengthException("Bcrypt String length: "
                + bcryptString.length() + ", 60 required.");
        }
        if (bcryptString.charAt(0) != '$'
            || bcryptString.charAt(3) != '$'
            || bcryptString.charAt(6) != '$')
        {
            throw new IllegalArgumentException("Invalid Bcrypt String format.");
        }
        if (!bcryptString.substring(1, 3).equals(version))
        {
            throw new IllegalArgumentException("Wrong Bcrypt version, 2a expected.");
        }
        int cost = 0;
        try
        {
            cost = Integer.parseInt(bcryptString.substring(4, 6));
        }
        catch (NumberFormatException nfe)
        {
            throw new IllegalArgumentException("Invalid cost factor:"
                + bcryptString.substring(4, 6));
        }
        if (cost < 4 || cost > 31)
        {
            throw new IllegalArgumentException("Invalid cost factor: "
                + cost + ", 4 < cost < 31 expected.");
        }
        // check password:
        if (password == null)
        {
            throw new IllegalArgumentException("Missing password.");
        }
        byte[] salt = decodeSaltString(
            bcryptString.substring(bcryptString.lastIndexOf('$') + 1,
                bcryptString.length() - 31));

        String newBcryptString = generate(password, salt, cost);

        return bcryptString.equals(newBcryptString);
    }

    /*
     * encode the input data producing a Bcrypt base 64 String.
     *
     * @param 	a byte representation of the salt or the password
     * @return 	the Bcrypt base64 String
     */
    private static String encodeData(
        byte[] data)

    {
        if (data.length != 24 && data.length != 16) // 192 bit key or 128 bit salt expected
        {
            throw new DataLengthException("Invalid length: " + data.length + ", 24 for key or 16 for salt expected");
        }
        boolean salt = false;
        if (data.length == 16)//salt
        {
            salt = true;
            byte[] tmp = new byte[18];// zero padding
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }
        else // key
        {
            data[data.length - 1] = (byte)0;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int len = data.length;

        int a1, a2, a3;
        int i;
        for (i = 0; i < len; i += 3)
        {
            a1 = data[i] & 0xff;
            a2 = data[i + 1] & 0xff;
            a3 = data[i + 2] & 0xff;

            out.write(encodingTable[(a1 >>> 2) & 0x3f]);
            out.write(encodingTable[((a1 << 4) | (a2 >>> 4)) & 0x3f]);
            out.write(encodingTable[((a2 << 2) | (a3 >>> 6)) & 0x3f]);
            out.write(encodingTable[a3 & 0x3f]);
        }

        String result = Strings.fromByteArray(out.toByteArray());
        if (salt == true)// truncate padding
        {
            return result.substring(0, 22);
        }
        else
        {
            return result.substring(0, result.length() - 1);
        }
    }


    /*
     * decodes the bcrypt base 64 encoded SaltString
     *
     * @param 		a 22 character Bcrypt base 64 encoded String 
     * @return 		the 16 byte salt
     * @exception 	DataLengthException if the length 
     * 				of parameter is not 22
     * @exception 	InvalidArgumentException if the parameter
     * 				contains a value other than from Bcrypts base 64 encoding table
     */
    private static byte[] decodeSaltString(
        String saltString)
    {
        char[] saltChars = saltString.toCharArray();

        ByteArrayOutputStream out = new ByteArrayOutputStream(16);
        byte b1, b2, b3, b4;

        if (saltChars.length != 22)// bcrypt salt must be 22 (16 bytes)
        {
            throw new DataLengthException("Invalid base64 salt length: " + saltChars.length + " , 22 required.");
        }

        // check String for invalid characters:
        for (int i = 0; i < saltChars.length; i++)
        {
            int value = saltChars[i];
            if (value > 122 || value < 46 || (value > 57 && value < 65))
            {
                throw new IllegalArgumentException("Salt string contains invalid character: " + value);
            }
        }

        // Padding: add two '\u0000'
        char[] tmp = new char[22 + 2];
        System.arraycopy(saltChars, 0, tmp, 0, saltChars.length);
        saltChars = tmp;

        int len = saltChars.length;

        for (int i = 0; i < len; i += 4)
        {
            b1 = decodingTable[saltChars[i]];
            b2 = decodingTable[saltChars[i + 1]];
            b3 = decodingTable[saltChars[i + 2]];
            b4 = decodingTable[saltChars[i + 3]];

            out.write((b1 << 2) | (b2 >> 4));
            out.write((b2 << 4) | (b3 >> 2));
            out.write((b3 << 6) | b4);
        }

        byte[] saltBytes = out.toByteArray();

        // truncate:
        byte[] tmpSalt = new byte[16];
        System.arraycopy(saltBytes, 0, tmpSalt, 0, tmpSalt.length);
        saltBytes = tmpSalt;

        return saltBytes;
    }
}