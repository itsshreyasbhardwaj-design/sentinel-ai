// Intentionally insecure fixture for Sentinel AI's test suite. Do not deploy.
package com.example;

import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Statement;
import java.util.Random;

public class Service {
    public void findUser(Statement statement, String userId) throws Exception {
        // SQL injection through concatenation.
        statement.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
    }

    public Object load(ObjectInputStream stream) throws Exception {
        // Untrusted deserialization.
        return stream.readObject();
    }

    public String hash(String password) throws Exception {
        // Broken hash algorithm.
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return new String(digest.digest(password.getBytes()));
    }

    public String sessionToken() {
        // Predictable random source for a security token.
        return String.valueOf(new Random().nextLong());
    }

    public void runCommand(String host) throws Exception {
        Runtime.getRuntime().exec("ping " + host);
    }
}
