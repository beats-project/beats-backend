package com.alibou.security.exceptions;

public class UnknownRefreshToken extends RuntimeException {
    public UnknownRefreshToken() {
        super("Unknown or invalid refresh token");
    }
}
