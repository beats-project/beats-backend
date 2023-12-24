package com.alibou.security.auth;

import com.alibou.security.config.JwtService;
import com.alibou.security.exceptions.NoCookiePresent;
import com.alibou.security.exceptions.UnknownRefreshToken;
import com.alibou.security.payload.GenericResponse;
import com.alibou.security.payload.response.LoginDto;
import com.alibou.security.payload.response.RefreshTokenDto;
import com.alibou.security.token.Token;
import com.alibou.security.token.TokenRepository;
import com.alibou.security.token.TokenType;
import com.alibou.security.user.Role;
import com.alibou.security.user.User;
import com.alibou.security.user.UserRepository;
import com.alibou.security.user.UserResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public UserResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedUser = repository.save(user);
//    var jwtToken = jwtService.generateToken(user);
//    var refreshToken = jwtService.generateRefreshToken(user);
//    saveUserToken(savedUser, jwtToken);
        return UserResponse.builder().id(savedUser.getId()).email(savedUser.getEmail()).firstName(savedUser.getFirstName()).lastName(savedUser.getLastName()).build();

    }

    public LoginDto authenticate(AuthenticationRequest request, HttpServletResponse response) throws BadCredentialsException, DisabledException, UsernameNotFoundException, IOException {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Incorrect username or password!");
        } catch (DisabledException disabledException) {
//            response.sendError(HttpServletResponse.SC_NOT_FOUND, "User is not activated");
            return null;
        }

        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        setAuthCookies(accessToken,refreshToken,response);

        return LoginDto.builder()
                .firstName(user.getFirstName())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public RefreshTokenDto refreshToken(
            HttpServletRequest request
    )  {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String refreshToken = null;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UnknownRefreshToken();
        }

        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                return RefreshTokenDto.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
//                var authResponse = AuthenticationResponse.builder()
//                        .accessToken(accessToken)
//                        .refreshToken(refreshToken)
//                        .build();
//                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
        throw new UnknownRefreshToken();
    }

    private void setAuthCookies(String accessToken, String refreshToken, HttpServletResponse response){
//        Cookie cookieAccess = new Cookie("accessToken",accessToken);
//        cookieAccess.setHttpOnly(true);
//        cookieAccess.setMaxAge(3600);
//        cookieAccess.setDomain("localhost");
//        cookieAccess.setPath("http://localhost:8080/");
//        Cookie cookieRefresh = new Cookie("refreshToken",refreshToken);
//        cookieRefresh.setHttpOnly(true);
//        cookieRefresh.setMaxAge(3600);
//        cookieRefresh.setDomain("localhost");
//        cookieRefresh.setPath("http://localhost:8080/");
//        response.addCookie(cookieAccess);
//        response.addCookie(cookieRefresh);

        /*
        Cookie cookieAccess = new Cookie("accessToken", accessToken);
        cookieAccess.setMaxAge(7 * 24 * 60 * 60); // expires in 7 days
        cookieAccess.setHttpOnly(true);
        cookieAccess.setPath("/api/v1/"); // Global
        response.addCookie(cookieAccess);

        Cookie cookieRefresh = new Cookie("refreshToken", refreshToken);
        cookieRefresh.setMaxAge(7 * 24 * 60 * 60); // expires in 7 days
        cookieRefresh.setHttpOnly(true);
        cookieRefresh.setPath("/api/v1/"); // Global
        response.addCookie(cookieRefresh);

         */

        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken) // key & value
                .httpOnly(true)
                .secure(false)
                //    .domain("localhost")  // host
                    .path("/")      // path
                .maxAge(7 * 24 * 60 * 60)
                .sameSite("Lax")  // sameSite
                .build()
                ;
            response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        ResponseCookie cookie1 = ResponseCookie.from("accessToken", accessToken) // key & value
                .httpOnly(true)
                .secure(false)
                //    .domain("localhost")  // host
                .path("/")      // path
                .maxAge(7 * 24 * 60 * 60)
                .sameSite("Lax")  // sameSite
                .build()
                ;
        response.setHeader(HttpHeaders.SET_COOKIE, cookie1.toString());
            //        ResponseCookie cookieAccessToken= ResponseCookie.from("accessToken", accessToken)
//                .httpOnly(true)
//                .secure(true)
//                .path("/auth/login")
//                .maxAge(3600)
//                .domain("example.com")
//                .build();
//        response.addHeader(HttpHeaders.SET_COOKIE, cookieAccessToken.toString());
//        ResponseCookie cookieRefreshToken= ResponseCookie.from("refreshToken", refreshToken)
//                .httpOnly(true)
//                .secure(true)
//                .path("/auth/login")
//                .maxAge(3600)
//                .domain("example.com")
//                .build();
//        response.addHeader(HttpHeaders.SET_COOKIE, cookieRefreshToken.toString());
    }
}

