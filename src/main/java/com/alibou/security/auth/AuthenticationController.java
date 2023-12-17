package com.alibou.security.auth;

import com.alibou.security.payload.GenericResponse;
import com.alibou.security.payload.response.LoginDto;
import com.alibou.security.payload.response.ResponseMessage;
import com.alibou.security.user.UserResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
      @RequestBody AuthenticationRequest request
  ) throws IOException {
    return ResponseEntity.ok(GenericResponse.success(service.authenticate(request),new ResponseMessage("LOGIN_SUCCESS","Login success"), 200,"Ok"));
  }

  @PostMapping("/refresh-token")
  public void refreshToken(
      HttpServletRequest request,
      HttpServletResponse response
  ) throws IOException {
    service.refreshToken(request, response);
  }


}
