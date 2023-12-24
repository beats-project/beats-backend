package com.alibou.security.utils;

import org.springframework.security.core.context.SecurityContextHolder;

import com.alibou.security.user.User;

public class Authentication {
    public static User getUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication()
                .getPrincipal();
    }
}
