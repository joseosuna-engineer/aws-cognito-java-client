package com.prottonne.cognito;

import com.prottonne.cognito.dto.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Main {

    @Autowired
    private CognitoHelper cognitoHelper;

    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }

    public String auth(Request request) {

        cognitoHelper.init(
                request.getPoolId(),
                request.getClientAppId(),
                request.getRegion()
        );

        String result = cognitoHelper.auth(
                request.getUsername(),
                request.getPassword()
        );

        return result;

    }

}
