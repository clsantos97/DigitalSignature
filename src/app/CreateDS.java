package app;

import java.io.*;
import java.security.*;

/**
 *
 * @author Carlos Santos
 */
public class CreateDS {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {

            // Generate public and private key
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, random);
            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey priv = pair.getPrivate();
            PublicKey pub = pair.getPublic();
            Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
            dsa.initSign(priv);
            FileInputStream fis = new FileInputStream("ds/sample.obj");
            BufferedInputStream bufin = new BufferedInputStream(fis);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = bufin.read(buffer)) >= 0) {
                dsa.update(buffer, 0, len);
            };
            bufin.close();
            byte[] realSig = dsa.sign();
            byte[] publickey = pub.getEncoded();
            //GUARDAR LA FIRMA Y LA CLAVE PUBLICA EN FICHEROS
            FileOutputStream fos = new FileOutputStream("ds/signature.obj");
            fos.write(realSig);
            fos.close();
            fos = new FileOutputStream("ds/publicKey.obj");
            fos.write(publickey);
            fos.close();
            System.out.println("Digital signature created.");
        } catch (Exception e) {
            System.out.println("Se ha producido un error: " + e.toString());
        }
    }

}
