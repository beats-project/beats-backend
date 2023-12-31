package com.alibou.security.utils;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCodes {

        // Endpoint - /auth/login
        EMAIL_OR_PASSWORD_INCORRECT("EMAIL_OR_PASSWORD_INCORRECT", "Incorrect email or password", 401,
                        HttpStatusCode.UNAUTHORIZED.getDescription(), HttpStatus.UNAUTHORIZED),

        EMAIL_REQUIRED("EMAIL_REQUIRED", "Required email value", 422,
                        HttpStatusCode.UNPROCESSABLE_ENTITY.getDescription(),
                        HttpStatus.UNPROCESSABLE_ENTITY),

        EMAIL_INVALID("EMAIL_INVALID", "Invalid email", 422, HttpStatusCode.UNPROCESSABLE_ENTITY.getDescription(),
                        HttpStatus.UNPROCESSABLE_ENTITY),

        EMAIL_INCORRECT("EMAIL_INCORRECT", "Incorrect email", 401, HttpStatusCode.UNAUTHORIZED.getDescription(),
                        HttpStatus.UNAUTHORIZED),

        EMAIL_NOT_FOUND("EMAIL_NOT_FOUND", "User with email does not exist", 404,
                        HttpStatusCode.NOT_FOUND.getDescription(),
                        HttpStatus.NOT_FOUND),

        PASSWORD_REQUIRED("PASSWORD_REQUIRED", "Required password value", 422,
                        HttpStatusCode.UNPROCESSABLE_ENTITY.getDescription(), HttpStatus.UNPROCESSABLE_ENTITY),

        PASSWORD_INVALID("PASSWORD", "Invalid password", 422, HttpStatusCode.UNPROCESSABLE_ENTITY.getDescription(),
                        HttpStatus.UNPROCESSABLE_ENTITY),

        PASSWORD_INCORRECT("PASSWORD_INCORRECT", "Incorrect password", 401,
                        HttpStatusCode.UNAUTHORIZED.getDescription(),
                        HttpStatus.UNAUTHORIZED),

        // Endpoint - /** (Protected) EXPIRED_JWT_EXCEPTION | SIGNATURE_EXCEPTION |
        // ACCESS_DENIED_EXCEPTION | MALFORMED_JWT_EXCEPTION | UNSUPPORTED_JWTEXCEPTION
        // | ILLEGAL_ARGUMENT_EXCEPTION
        ACCESS_TOKEN_EXPIRED("ACCESS_TOKEN_EXPIRED", "Access denied", 403, HttpStatusCode.FORBIDDEN.getDescription(),
                        HttpStatus.FORBIDDEN),

        ACCESS_TOKEN_INVALID("ACCESS_TOKEN_INVALID", "Access denied", 403, HttpStatusCode.FORBIDDEN.getDescription(),
                        HttpStatus.FORBIDDEN),

        REFRESH_TOKEN_UNKNOWN("REFRESH_TOKEN_UNKNOWN", "Refresh token unknown or invalid", 403,
                        HttpStatusCode.FORBIDDEN.getDescription(), HttpStatus.FORBIDDEN),

        NO_HANDLER_FOUND("NO_HANDLER_FOUND", "Invalid endpoint", 404, HttpStatusCode.NOT_FOUND.getDescription(),
                        HttpStatus.NOT_FOUND);

        private String code;
        private String details;

        private int statusCode;
        private String statusName;
        private HttpStatus httpStatus;

        ErrorCodes(String code, String details, int statusCode, String statusName, HttpStatus httpStatus) {
                this.code = code;
                this.details = details;
                this.statusCode = statusCode;
                this.statusName = statusName;
                this.httpStatus = httpStatus;
        }

}
