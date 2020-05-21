package com.jk;

import doubleca.security.provider.DoubleCA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Sm2Test3 {
    public static void main(String[] args) {
        try {
          //  final BouncyCastleProvider bc = new BouncyCastleProvider();
            Security.addProvider(new DoubleCA());
            String publicKey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEu9wESJetGCf/MtjA7/dZuncEmSvEXc4Wod2JTmTJ0TEYZdFTgGIZTOoyVU3X8Zd+RZfvH9u80VmRH77Vwh+J8w==";
            String privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgEkwtaawtIbBQ6eKfJztxqUcJIPg9fs6qgYTgrXMU7p2hRANCAAS73ARIl60YJ/8y2MDv91m6dwSZK8Rdzhah3YlOZMnRMRhl0VOAYhlM6jJVTdfxl35Fl+8f27zRWZEfvtXCH4nz";
            byte[] encPub = Base64.decode(publicKey);
            byte[] encPriv = Base64.decode(privateKey);
            //KeyFactory keyFact = KeyFactory.getInstance("EC", bc);
            KeyFactory factory = KeyFactory.getInstance("SM2");
            // 根据采用的编码结构反序列化公私钥
            PublicKey pub = factory.generatePublic(new X509EncodedKeySpec(encPub));
            PrivateKey priv = factory.generatePrivate(new PKCS8EncodedKeySpec(encPriv));
            String content = "你好";
            byte[] plainText = content.getBytes(StandardCharsets.UTF_8);
            //签名和验签
            System.out.println("原文：" + content);
            Signature signature = Signature.getInstance("SM3withSm2");
            signature.initSign(priv);
            signature.update(plainText);
            byte[] signValue = signature.sign();
            System.out.println("签名值：" + new String(com.doubleca.b146.c16.util.encoders.Base64.encode(signValue)));
            signature.initVerify(pub);
            signature.update(plainText);
            boolean result = signature.verify(signValue);
            System.out.println("签名验证结果 ：" + result);

            //加解密
            Cipher cipher = Cipher.getInstance("SM2/ECB/NOPadding");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            System.out.println("原文：" + content);
            cipher.update(plainText);
            byte[] cipherByte = cipher.doFinal();
            System.out.println("密文：" + new String(com.doubleca.b146.c16.util.encoders.Base64.encode(cipherByte)));
            cipher.init(Cipher.DECRYPT_MODE, priv);
            byte[] plainByte = cipher.doFinal(cipherByte);
            System.out.println("原文：" + new String(plainByte));




//
//            Signature signature = Signature.getInstance("SM3withSm2", bc);
//
//
//
//            // 计算签名值
//            byte[] signatureValue = signature.sign();
//            String signatureHex = Hex.toHexString(signatureValue);
//            System.out.println("signature: \n" + signatureHex);
//
//
//            System.out.println(signature.toString());
//
//            // 验证签名值
//            //  boolean res = signature.verify(Hex.decode("3045022100ff9a872f21e47d4fba8f37b48a62cc2e6fdde843a40cbc96242536afc10a395e02203bbab982d1bb6a7ee5f5f6b34cd887c255ae4dcc14dd87ecae2e0392611b7a8c"));
//            boolean res = signature.verify(Hex.decode(signatureHex));
//            System.out.println(">> 验证结果:" + res);
//
//
//            byte[] plain = "你好刘晓".getBytes(StandardCharsets.UTF_8);
//            //  byte[] plainEncrypt = Sm2Test2.encrypt(pub,plain);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
