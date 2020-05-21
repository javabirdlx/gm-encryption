package com.jk;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @Description : 测试2
 * @Author : liuxiao
 * @Date: 2020-05-21 17:31
 */
public class Sm2Test2 {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        final BouncyCastleProvider bc = new BouncyCastleProvider();

        /*
        >> 公钥BASE64: MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAESic24soUECzuSh2aYH0e+hQYh+/I01NmfjOnm5mwyUEYQvNCPTzn3BlNyufgMV+DWLUKV+2h0+PVel9jYTfG8Q==
        >> 私钥BASE64: MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg0dYU+I6IdiSe8bvWlsHuWfsjSn3XFZqOGWO3K1814O6gCgYIKoEcz1UBgi2hRANCAARKJzbiyhQQLO5KHZpgfR76FBiH78jTU2Z+M6ebmbDJQRhC80I9POfcGU3K5+AxX4NYtQpX7aHT49V6X2NhN8bx
        signature:
        3045022100ff9a872f21e47d4fba8f37b48a62cc2e6fdde843a40cbc96242536afc10a395e02203bbab982d1bb6a7ee5f5f6b34cd887c255ae4dcc14dd87ecae2e0392611b7a8c
         */
//        // 公私钥是16进制情况下解码
//        byte[] encPub = Hex.decode("...");
//        byte[] encPriv =  Hex.decode("...");
      //  byte[] encPub = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAESic24soUECzuSh2aYH0e+hQYh+/I01NmfjOnm5mwyUEYQvNCPTzn3BlNyufgMV+DWLUKV+2h0+PVel9jYTfG8Q==");
       // byte[] encPriv = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg0dYU+I6IdiSe8bvWlsHuWfsjSn3XFZqOGWO3K1814O6gCgYIKoEcz1UBgi2hRANCAARKJzbiyhQQLO5KHZpgfR76FBiH78jTU2Z+M6ebmbDJQRhC80I9POfcGU3K5+AxX4NYtQpX7aHT49V6X2NhN8bx");

         // String publicKey = "MIIC3zCCAoOgAwIBAgIFQAA3BwAwDAYIKoEcz1UBg3UFADBhMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSAwHgYDVQQDDBdDRkNBIEFDUyBURVNUIFNNMiBPQ0EzMTAeFw0xNzA0MjYxMDQyNDdaFw0yMjA0MjYxMDQyNDdaMIGDMQswCQYDVQQGEwJDTjERMA8GA1UECgwIT0NBMzFTTTIxFTATBgNVBAsMDHNoYW5naGFpVGVjaDEZMBcGA1UECwwQT3JnYW5pemF0aW9uYWwtMjEvMC0GA1UEAwwmU0hUZWNoQOS4reWbvemTtuiBlEA4OTEzMTAwMDA3MzYyMzk4QDIwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASvDqAeYSNshjAJtBdNHsVQ3jJ9tgKuSaKeuqTCWD5kQ7rGc18GiI1FFkhNW/xXXuf16Lbdf1vcDRcrJWgUii8uo4IBATCB/jBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly8yMTAuNzQuNDIuMTE6ODA4NS9vY3NwX3NlcnZlci9vY3NwLzAfBgNVHSMEGDAWgBQEx7z5WQFpPow0NiBiGDzevLW7DDAMBgNVHRMBAf8EAjAAMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly8yMTAuNzQuNDIuMy9PQ0EzMS9TTTIvY3JsNTcuY3JsMA4GA1UdDwEB/wQEAwIGwDAdBgNVHQ4EFgQUjAXTff6jIROxvk4nnewh3SLz7LwwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMAwGCCqBHM9VAYN1BQADSAAwRQIgdhJse3F8tYSZRNv0B/VtkVh7t5FS61ZzcMiNHq/Ebm4CIQCCt5Fkh3ACiybRgGb+wKbh9gWhZTr6O/qZeQlb7XXfrw==";

        String publicKey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEu9wESJetGCf/MtjA7/dZuncEmSvEXc4Wod2JTmTJ0TEYZdFTgGIZTOoyVU3X8Zd+RZfvH9u80VmRH77Vwh+J8w==";
        String privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgEkwtaawtIbBQ6eKfJztxqUcJIPg9fs6qgYTgrXMU7p2hRANCAAS73ARIl60YJ/8y2MDv91m6dwSZK8Rdzhah3YlOZMnRMRhl0VOAYhlM6jJVTdfxl35Fl+8f27zRWZEfvtXCH4nz";

        byte[] encPub = Base64.decode(publicKey);
        byte[] encPriv = Base64.decode(privateKey);
        byte[] plainText = "你好".getBytes(StandardCharsets.UTF_8);

        KeyFactory keyFact = KeyFactory.getInstance("EC", bc);
        // 根据采用的编码结构反序列化公私钥
        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));


        Signature signature = Signature.getInstance("SM3withSm2", bc);


        signature.initSign(priv);
        signature.update(plainText);
        // 计算签名值
        byte[] signatureValue = signature.sign();
        String signatureHex = Hex.toHexString(signatureValue);
        System.out.println("signature: \n" + signatureHex);


        System.out.println(signature.toString());
        signature.initVerify(pub);
        signature.update(plainText);
        // 验证签名值
      //  boolean res = signature.verify(Hex.decode("3045022100ff9a872f21e47d4fba8f37b48a62cc2e6fdde843a40cbc96242536afc10a395e02203bbab982d1bb6a7ee5f5f6b34cd887c255ae4dcc14dd87ecae2e0392611b7a8c"));
        boolean res = signature.verify(Hex.decode(signatureHex));
        System.out.println(">> 验证结果:" + res);


        byte[] plain = "你好刘晓".getBytes(StandardCharsets.UTF_8);
      //  byte[] plainEncrypt = Sm2Test2.encrypt(pub,plain);

    }

    /**
     * ECC公钥加密
     *
     * @param pubKey  ECC公钥
     * @param srcData 源数据
     * @return SM2密文，实际包含三部分：ECC公钥、真正的密文、公钥和原文的SM3-HASH值
     * @throws InvalidCipherTextException
     */
    public static byte[] encrypt(ECPublicKeyParameters pubKey, byte[] srcData)throws InvalidCipherTextException {
        SM2Engine engine = new SM2Engine();
        ParametersWithRandom pwr = new ParametersWithRandom(pubKey, new SecureRandom());
        engine.init(true, pwr);
        return engine.processBlock(srcData, 0, srcData.length);
    }

    /**
     * ECC私钥解密
     *
     * @param priKey        ECC私钥
     * @param sm2CipherText SM2密文，实际包含三部分：ECC公钥、真正的密文、公钥和原文的SM3-HASH值
     * @return 原文
     * @throws InvalidCipherTextException
     */
    public static byte[] decrypt(ECPrivateKeyParameters priKey, byte[] sm2CipherText) throws InvalidCipherTextException {
        SM2Engine engine = new SM2Engine();
        engine.init(false, priKey);
        return engine.processBlock(sm2CipherText, 0, sm2CipherText.length);
    }

}
