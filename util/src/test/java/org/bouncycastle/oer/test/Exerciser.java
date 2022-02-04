package org.bouncycastle.oer.test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;

public class Exerciser
{

    private static Method buildMethod;


    public static void main(String args)
        throws Exception
    {

        buildMethod = OERDefinition.Builder.class.getMethod("build");


        List<Class> templateClassess = new ArrayList<Class>();
        templateClassess.add(IEEE1609dot2.class);

        //
        // Template classes have static methods of OERDefinition.Builder type
        //

        for (Class clasz : templateClassess)
        {
            for (Field f : extractBuilders(clasz))
            {
                Element rootElement = rootElement(f);

            }
        }


    }




    private static Element rootElement(Field f)
        throws Exception
    {
        OERDefinition.Builder builder = (OERDefinition.Builder)f.get(null);
        Element rootElement = (Element)buildMethod.invoke(builder);
        return rootElement;
    }


    private static List<Field> extractBuilders(Class clazz)
    {
        List<Field> builders = new ArrayList<Field>();
        for (Field f : clazz.getFields())
        {
            if (f.getType() == OERDefinition.Builder.class)
            {
                builders.add(f);
            }
        }
        return builders;
    }

}
