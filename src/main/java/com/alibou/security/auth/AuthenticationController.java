package com.alibou.security.auth;

import com.alibou.security.payload.GenericResponse;
import com.alibou.security.payload.response.LoginDto;
import com.alibou.security.payload.response.RefreshTokenDto;
import com.alibou.security.payload.response.ResponseMessage;
import com.alibou.security.user.UserResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<GenericResponse<LoginDto>> authenticate(
            @RequestBody AuthenticationRequest request, HttpServletResponse response
    ) throws IOException {
        return ResponseEntity.ok(GenericResponse.success(service.authenticate(request, response), new ResponseMessage("LOGIN_SUCCESS", "Login success"), 200, "Ok"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<GenericResponse<RefreshTokenDto>> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        return ResponseEntity.ok(GenericResponse.success(service.refreshToken(request), new ResponseMessage("REFRESH_TOKEN_SUCCESS", "Token refreshed success"), 200, "Ok"));
    }


}
