package com.alibou.security.exceptions;

public class EmailAlreadyExists extends RuntimeException {
    public EmailAlreadyExists() {
        super("Email already exists");
    }


}
