package com.jk;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @Description : 国密接口测试
 * @Author : liuxiao
 * @Date: 2020-05-21 19:47
 */
public class GmTest {

    //公钥和私钥
    private static final String publicKey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEu9wESJetGCf/MtjA7/dZuncEmSvEXc4Wod2JTmTJ0TEYZdFTgGIZTOoyVU3X8Zd+RZfvH9u80VmRH77Vwh+J8w==";
    private static final String privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgEkwtaawtIbBQ6eKfJztxqUcJIPg9fs6qgYTgrXMU7p2hRANCAAS73ARIl60YJ/8y2MDv91m6dwSZK8Rdzhah3YlOZMnRMRhl0VOAYhlM6jJVTdfxl35Fl+8f27zRWZEfvtXCH4nz";
    public static final Charset charset = Charset.forName("utf-8");
    private static final String ID = "1234";
    private static final String input = "Hello world";

   // public static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(CURVE, G_POINT, SM2_ECC_N, SM2_ECC_H);

    public static void main(String[] args) throws Exception {
            final BouncyCastleProvider bc = new BouncyCastleProvider();
            byte[] encPub = Base64.decode(publicKey);
            byte[] encPriv = Base64.decode(privateKey);
            KeyFactory factory = KeyFactory.getInstance("SM2");
            //KeyFactory keyFact = KeyFactory.getInstance("EC", bc);
            // 根据采用的编码结构反序列化公私钥
            PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(encPub));
            PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(encPriv));
//        try {
//            ECPrivateKeyParameters ecPrivateKeyParameters = GmTest.buildECPrivateKeyParameters(privateKey);
//            // 签名原文
//            byte[] sign = GmUtil.sign(input.getBytes(charset), ecPrivateKeyParameters, ID.getBytes(charset));
//            // 计算签名值
//            System.out.println("signature: \n" + Hex.toHexString(sign));
//        } catch (Exception e) {
//            e.printStackTrace();
//        }


        try {
            BCECPublicKey localECPublicKey = (BCECPublicKey) publicKey;
            X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
            ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
            ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), ecDomainParameters);

//            SM2KeyPair sm2KeyPair = SM2KeyHelper.generateKeyPair();
//            ECPublicKeyParameters ecPublicKeyParameters = GmTest.buildECPublicKeyParameters(sm2KeyPair);
//            ECPrivateKeyParameters ecPrivateKeyParameters = GmTest.buildECPrivateKeyParameters(sm2KeyPair.getPrivateKey());
            //C1C2C3 mode
            byte[] encryptRet123 = GmUtil.encrypt(input.getBytes(charset), ecPublicKeyParameters, SM2Engine.Mode.C1C2C3);
            System.out.println("SM2 encrypt C1C2C3 mode result:"+ Hex.toHexString(encryptRet123));


            BCECPrivateKey localECPrivateKey = (BCECPrivateKey) privateKey;
            ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(localECPrivateKey.getD(), ecDomainParameters);
            byte[] decryptRet132 = GmUtil.decrypt(encryptRet123, ecPrivateKeyParameters, SM2Engine.Mode.C1C3C2);
            System.out.println("SM2 decrypt C1C2C3 mode result:"+new String(decryptRet132, charset));

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

//    /**
//     * 构建公钥参数
//     * @param sm2KeyPair
//     * @return
//     */
//    public static ECPublicKeyParameters buildECPublicKeyParameters(SM2KeyPair sm2KeyPair){
//        return buildECPublicKeyParameters(sm2KeyPair.getPublicKeyX(), sm2KeyPair.getPublicKeyY());
//    }
//
//    /**
//     * 构建公钥参数
//     * @param publicKeyX
//     * @param publicKeyY
//     * @return
//     */
//    public static ECPublicKeyParameters buildECPublicKeyParameters(byte[] publicKeyX, byte[] publicKeyY){
//        ECPoint pointQ = SM2Constants.CURVE.createPoint(new BigInteger(1, publicKeyX), new BigInteger(1, publicKeyY));
//        return new ECPublicKeyParameters(pointQ, SM2Constants.DOMAIN_PARAMS);
//    }

    /**
     * 构建私钥参数
     * @param privateKey
     * @return
     */
    public static ECPrivateKeyParameters buildECPrivateKeyParameters(byte[] privateKey){
        BigInteger d = new BigInteger(1, privateKey);
        return new ECPrivateKeyParameters(d, GmConstants.DOMAIN_PARAMS);
    }
}
