package com.alibou.security.exceptions;

import com.alibou.security.payload.ExceptionResponse;
import com.alibou.security.payload.GenericResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;


//@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

//    @ExceptionHandler(EmailAlreadyExists.class)
//    public ResponseEntity<Object> handleExceptions(EmailAlreadyExists exception, WebRequest webRequest) {
//        ExceptionResponse response = new ExceptionResponse();
//        response.setDateTime(LocalDateTime.now());
//        response.setMessage(exception.getMessage());
//        response.setStatusCode(409);
//        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
//    }

    @ResponseBody
    @ExceptionHandler(EmailAlreadyExists.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    ExceptionResponse emailAlreadyExistsHandler(HttpServletRequest request,
                                                HttpServletResponse response, Exception ex) {

        // do something with request or response
//        String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
        return new ExceptionResponse(ex.getMessage(), "");
    }

//    @ResponseBody
//    @ExceptionHandler(JwtException.class)
//    @ResponseStatus(HttpStatus.BAD_REQUEST)
//    ExceptionResponse jwtExceptionHandler(HttpServletResponse request, HttpServletResponse response, Exception ex){
//        return new ExceptionResponse(ex.getMessage(),  403);
//    }

    /*
    @ExceptionHandler(value = {UsernameNotFoundException.class})
    public ResponseEntity<Object> handleExpiredJwtException(UsernameNotFoundException ex, WebRequest request) {
        String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
        ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
//        return new ResponseEntity<>(exceptionMessage, new HttpHeaders(), HttpStatus.FORBIDDEN);
        return new ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403), new HttpHeaders(), HttpStatus.FORBIDDEN);
    }
    @ExceptionHandler(value = {SignatureException.class})
    public ResponseEntity<Object> handleExpiredJwtException(SignatureException ex, WebRequest request) {
        String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
        ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
//        return new ResponseEntity<>(exceptionMessage, new HttpHeaders(), HttpStatus.FORBIDDEN);
        return new ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403), new HttpHeaders(), HttpStatus.FORBIDDEN);
    }
    @ExceptionHandler(value = {BadCredentialsException.class})
    public ResponseEntity<Object> handleExpiredJwtException(BadCredentialsException ex, WebRequest request) {
        String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
        ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
//        return new ResponseEntity<>(exceptionMessage, new HttpHeaders(), HttpStatus.FORBIDDEN);
        return new ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403), new HttpHeaders(), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(value = {Exception.class})
    public ResponseEntity<Object> handleOtherExceptions(Exception ex, WebRequest request) {
        String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
        ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
        return new ResponseEntity<>(exceptionMessage, new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

     */
}
