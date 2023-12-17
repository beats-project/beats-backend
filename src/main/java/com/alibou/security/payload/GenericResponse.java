package com.alibou.security.payload;

import com.alibou.security.payload.response.ResponseMessage;
import com.alibou.security.utils.HttpStatusCode;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class GenericResponse<T> {
    private boolean success;
    private ResponseMessage message;
    private int statusCode;
    private String statusName;
    private T data;

    public static <T> GenericResponse<T> empty() {
        return success(null,new ResponseMessage(), 500, HttpStatusCode.INTERNAL_SERVER_ERROR.getDescription());
    }

    public static <T> GenericResponse<T> success(T data, ResponseMessage message, int statusCode, String statusName) {
        return GenericResponse.<T>builder()
                .statusCode(statusCode)
                .statusName(statusName)
                .message(message)
                .data(data)
                .success(true)
                .build();
    }

    public static <T> GenericResponse<T> error(ResponseMessage message, int statusCode, String statusName) {
        return GenericResponse.<T>builder()
                .statusCode(statusCode)
                .statusName(statusName)
                .message(message)
                .success(false)
                .build();
    }
}