package com.alibou.security.exceptions;

import com.alibou.security.payload.ExceptionResponse;
import com.alibou.security.payload.GenericResponse;
import com.alibou.security.payload.response.ResponseMessage;
import com.alibou.security.utils.ErrorCodes;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;

import com.alibou.security.utils.HttpStatusCode;

@RestControllerAdvice
public class CustomExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleSecurityException(Exception ex, WebRequest request) {
        ProblemDetail detail = null;
        if (ex instanceof BadCredentialsException) {
            // detail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401),
            // ex.getMessage());
            String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
            ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
            return new ResponseEntity<>(
                    GenericResponse.error(
                            new ResponseMessage(ErrorCodes.EMAIL_OR_PASSWORD_INCORRECT.getCode(),
                                    ErrorCodes.EMAIL_OR_PASSWORD_INCORRECT.getDetails()),
                            ErrorCodes.EMAIL_OR_PASSWORD_INCORRECT.getStatusCode(),
                            ErrorCodes.EMAIL_OR_PASSWORD_INCORRECT.getStatusName()),
                    new HttpHeaders(), ErrorCodes.EMAIL_OR_PASSWORD_INCORRECT.getHttpStatus());
        }
        if (ex instanceof UnknownRefreshToken) {
            // detail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401),
            // ex.getMessage());
            String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
            ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
            return new ResponseEntity<>(
                    GenericResponse.error(
                            new ResponseMessage(ErrorCodes.REFRESH_TOKEN_UNKNOWN.getCode(),
                                    ErrorCodes.REFRESH_TOKEN_UNKNOWN.getDetails()),
                            ErrorCodes.REFRESH_TOKEN_UNKNOWN.getStatusCode(),
                            ErrorCodes.REFRESH_TOKEN_UNKNOWN.getStatusName()),
                    new HttpHeaders(), ErrorCodes.REFRESH_TOKEN_UNKNOWN.getHttpStatus());
        }

        if (ex instanceof NoCookiePresent) {
            // detail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401),
            // ex.getMessage());
            String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
            ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
            return new ResponseEntity<>(GenericResponse.error(new ResponseMessage("NO_COOKIE", ex.getMessage()),
                    ErrorCodes.REFRESH_TOKEN_UNKNOWN.getStatusCode(), ErrorCodes.REFRESH_TOKEN_UNKNOWN.getStatusName()),
                    new HttpHeaders(), ErrorCodes.REFRESH_TOKEN_UNKNOWN.getHttpStatus());
        }

        if (ex instanceof ExpiredJwtException) {
            // detail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401),
            // ex.getMessage());
            
            String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
            ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
            return new ResponseEntity<>(
                    GenericResponse.error(
                            new ResponseMessage(ErrorCodes.ACCESS_TOKEN_EXPIRED.getCode(),
                                    ErrorCodes.ACCESS_TOKEN_EXPIRED.getDetails()),
                            ErrorCodes.ACCESS_TOKEN_EXPIRED.getStatusCode(),
                            ErrorCodes.ACCESS_TOKEN_EXPIRED.getStatusName()),
                    new HttpHeaders(), ErrorCodes.ACCESS_TOKEN_EXPIRED.getHttpStatus());
        }
        if (ex instanceof NoHandlerFoundException) {
            // detail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401),
            // ex.getMessage());
            
            String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
            ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
            return new ResponseEntity<>(
                    GenericResponse.error(
                            new ResponseMessage(ErrorCodes.NO_HANDLER_FOUND.getCode(),
                                    ErrorCodes.NO_HANDLER_FOUND.getDetails()),
                            ErrorCodes.NO_HANDLER_FOUND.getStatusCode(),
                            ErrorCodes.NO_HANDLER_FOUND.getStatusName()),
                    new HttpHeaders(), ErrorCodes.NO_HANDLER_FOUND.getHttpStatus());
        }
        if (ex instanceof AccessDeniedException) {
            // detail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403),
            // ex.getMessage());
            String requestUri = ((ServletWebRequest) request).getRequest().getRequestURI().toString();
            ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(), requestUri);
            return new ResponseEntity<>(
                    GenericResponse.error(
                            new ResponseMessage(ErrorCodes.NO_HANDLER_FOUND.getCode(),
                                    ErrorCodes.NO_HANDLER_FOUND.getDetails()),
                            ErrorCodes.NO_HANDLER_FOUND.getStatusCode(),
                            ErrorCodes.NO_HANDLER_FOUND.getStatusName()),
                    new HttpHeaders(), ErrorCodes.NO_HANDLER_FOUND.getHttpStatus());

        }
        if (ex instanceof SignatureException) {
            // detail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403),
            // ex.getMessage());

        }
        // if (ex instanceof ExpiredJwtException) {
        // // detail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403),
        // // ex.getMessage());

        // }
        if (ex instanceof MalformedJwtException) {
            // detail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401),
            // ex.getMessage());

        }
        return new ResponseEntity<>(GenericResponse.error(new ResponseMessage("SERVER-ERROR", ex.getMessage()),
                HttpStatusCode.INTERNAL_SERVER_ERROR.getValue(), HttpStatusCode.INTERNAL_SERVER_ERROR.getDescription()),
                new HttpHeaders(), 500);
    }

    /*
     * @ExceptionHandler(value = {UsernameNotFoundException.class})
     * public ResponseEntity<Object>
     * handleExpiredJwtException(UsernameNotFoundException ex, WebRequest request) {
     * String requestUri = ((ServletWebRequest)
     * request).getRequest().getRequestURI().toString();
     * ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(),
     * requestUri);
     * return new
     * ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403),
     * new HttpHeaders(), HttpStatus.FORBIDDEN);
     * }
     * 
     * @ExceptionHandler(value = {ExpiredJwtException.class})
     * public ResponseEntity<Object> handleExpiredJwtException(ExpiredJwtException
     * ex, WebRequest request) {
     * String requestUri = ((ServletWebRequest)
     * request).getRequest().getRequestURI().toString();
     * ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(),
     * requestUri);
     * return new
     * ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403),
     * new HttpHeaders(), HttpStatus.FORBIDDEN);
     * }
     * 
     * @ExceptionHandler(value = {SignatureException.class})
     * public ResponseEntity<Object> handleExpiredJwtException(SignatureException
     * ex, WebRequest request) {
     * String requestUri = ((ServletWebRequest)
     * request).getRequest().getRequestURI().toString();
     * ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(),
     * requestUri);
     * // return new
     * ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403),
     * new HttpHeaders(), HttpStatus.FORBIDDEN);
     * }
     * 
     * @ExceptionHandler(value = {BadCredentialsException.class})
     * public ResponseEntity<Object>
     * handleExpiredJwtException(BadCredentialsException ex, WebRequest request) {
     * // String requestUri = ((ServletWebRequest)
     * request).getRequest().getRequestURI().toString();
     * // ExceptionResponse exceptionMessage = new
     * ExceptionResponse(ex.getMessage(), requestUri);
     * // return new
     * ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403),
     * new HttpHeaders(), HttpStatus.FORBIDDEN);
     * }
     * 
     * @ExceptionHandler(value = {AccessDeniedException.class})
     * public ResponseEntity<Object> handleExpiredJwtException(AccessDeniedException
     * ex, WebRequest request) {
     * String requestUri = ((ServletWebRequest)
     * request).getRequest().getRequestURI().toString();
     * ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(),
     * requestUri);
     * return new
     * ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403),
     * new HttpHeaders(), HttpStatus.FORBIDDEN);
     * }
     * 
     * @ExceptionHandler(value = {MalformedJwtException.class})
     * public ResponseEntity<Object> handleExpiredJwtException(MalformedJwtException
     * ex, WebRequest request) {
     * String requestUri = ((ServletWebRequest)
     * request).getRequest().getRequestURI().toString();
     * ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(),
     * requestUri);
     * return new
     * ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403),
     * new HttpHeaders(), HttpStatus.FORBIDDEN);
     * }
     * 
     * @ExceptionHandler(value = {UnsupportedJwtException.class})
     * public ResponseEntity<Object>
     * handleExpiredJwtException(UnsupportedJwtException ex, WebRequest request) {
     * String requestUri = ((ServletWebRequest)
     * request).getRequest().getRequestURI().toString();
     * ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(),
     * requestUri);
     * return new
     * ResponseEntity<>(GenericResponse.error(exceptionMessage.getMessage(), 403),
     * new HttpHeaders(), HttpStatus.FORBIDDEN);
     * }
     * 
     * @ExceptionHandler(value = {Exception.class})
     * public ResponseEntity<Object> handleOtherExceptions(Exception ex, WebRequest
     * request) {
     * String requestUri = ((ServletWebRequest)
     * request).getRequest().getRequestURI().toString();
     * ExceptionResponse exceptionMessage = new ExceptionResponse(ex.getMessage(),
     * requestUri);
     * return new ResponseEntity<>(exceptionMessage, new HttpHeaders(),
     * HttpStatus.INTERNAL_SERVER_ERROR);
     * }
     */

}
