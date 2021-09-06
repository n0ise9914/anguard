package com.example;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.anguard.Anguard;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            String key = "LgiLTuCRuwPYZkyZ";
            Log.e("TAG", "uint8_t key[] = " + Arrays.toString(key.getBytes()).replace("[", "{").replace("]", "};"));
            Anguard.initialize(this);
            String token = String.valueOf(Anguard.getToken("-coin.500"));
            Log.e("TAG", "token: " + token);
            String decrypted = decryptToken(token, key);
            Log.e("TAG", "decrypted: " + decrypted);
            ((TextView) findViewById(R.id.txt)).setText(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String decryptToken(String token, String key) throws Exception {
        byte[] encrypted = Base64.decode(token, Base64.DEFAULT);
        byte[] iv = Arrays.copyOfRange(encrypted, 0, 16);
        byte[] data = Arrays.copyOfRange(encrypted, 16, encrypted.length);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(2, secretKeySpec, ivParameterSpec);
        return new String(cipher.doFinal(data));
    }
}