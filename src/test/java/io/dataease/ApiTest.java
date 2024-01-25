package io.dataease;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.UUID;

public class ApiTest {

    static String accessKey = "y4z835cnqoioub54";
    static String secretKey = "zvvh6bmfxlftmsbs";

    public static void main(String[] args) {
        try {
            URL url = new URL("https://live.fit2cloud.com/de2api/dataVisualization/tree");
            String signature = aesEncrypt(accessKey + "|" + UUID.randomUUID() + "|" + System.currentTimeMillis(), secretKey, accessKey);
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            JWTCreator.Builder builder = JWT.create();
            builder.withClaim("accessKey", accessKey).withClaim("signature", signature);
            String token = builder.sign(algorithm);

            HttpURLConnection urlConnection = (HttpURLConnection)
                    url.openConnection();
            urlConnection.setRequestProperty("Accept",
                    "application/json;charset=UTF-8");
            urlConnection.setRequestProperty("Content-Type",
                    "application/json");
            urlConnection.setRequestProperty("accessKey", accessKey);
            urlConnection.setRequestProperty("signature", signature);
            urlConnection.setRequestProperty("x-de-ask-token", token);
            urlConnection.setRequestMethod("POST");
            urlConnection.setDoInput(true);
            urlConnection.setDoOutput(true);

            String jsonData = "{\"busiFlag\":\"dashboard\"}";
            DataOutputStream outputStream = new
                    DataOutputStream(urlConnection.getOutputStream());
            outputStream.write(jsonData.getBytes());
            outputStream.flush();
            urlConnection.connect();

            // 获取响应体
            BufferedReader reader = new BufferedReader(new
                    InputStreamReader(urlConnection.getInputStream()));
            String line;
            StringBuilder responseBody = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                responseBody.append(line);
            }
            System.out.println("响应体：\n" + responseBody);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static String aesEncrypt(String src, String secretKey, String iv)
            throws Exception {
        byte[] raw = secretKey.getBytes("UTF-8");
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv1 = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv1);
        byte[] encrypted = cipher.doFinal(src.getBytes("UTF-8"));
        return Base64.encodeBase64String(encrypted);
    }
}
