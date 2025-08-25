package org.bouncycastle.bcpg.attr;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.bcpg.UserAttributeSubpacketTags;

/**
 * User-Attribute Subpacket used to encode an image, e.g. the user's avatar.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.12.1">
 *     RFC4880 - Image Attribute Subpacket</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-the-image-attribute-subpack">
 *     RFC9580 - Image Attribute Subpacket</a>
 */
public class ImageAttribute 
    extends UserAttributeSubpacket
{
    public static final int JPEG = 1;

    private static final byte[] ZEROES = new byte[12];

    private int     hdrLength;
    private int     version;
    private int     encoding;
    private byte[]  imageData;

    public ImageAttribute(
        byte[]    data)
    {
        this(false, data);
    }

    public ImageAttribute(
        boolean   forceLongLength,
        byte[]    data)
    {
        super(UserAttributeSubpacketTags.IMAGE_ATTRIBUTE, forceLongLength, data);
        if (data.length < 4)
        {
            throw new IllegalArgumentException("Malformed ImageAttribute. Data length too short: " + data.length);
        }
        
        hdrLength = ((data[1] & 0xff) << 8) | (data[0] & 0xff);
        if (data.length < hdrLength)
        {
            throw new IllegalArgumentException("Malformed ImageAttribute. Header length exceeds data length.");
        }
        version = data[2] & 0xff;
        encoding = data[3] & 0xff;
        
        imageData = new byte[data.length - hdrLength];
        System.arraycopy(data, hdrLength, imageData, 0, imageData.length);
    }

    public ImageAttribute(
        int imageType,
        byte[] imageData)
    {
        this(toByteArray(imageType, imageData));
    }

    private static byte[] toByteArray(int imageType, byte[] imageData)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            bOut.write(0x10); bOut.write(0x00); bOut.write(0x01);
            bOut.write(imageType);
            bOut.write(ZEROES);
            bOut.write(imageData);
        }
        catch (IOException e)
        {
            throw new RuntimeException("unable to encode to byte array!");
        }

        return bOut.toByteArray();
    }

    public int version()
    {
        return version;
    }
    
    public int getEncoding()
    {
        return encoding;
    }
    
    public byte[] getImageData()
    {
        return imageData;
    }
}
