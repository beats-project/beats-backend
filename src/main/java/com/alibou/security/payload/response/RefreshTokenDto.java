package com.alibou.security.payload.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class RefreshTokenDto {
    private String accessToken;
    private String refreshToken;
}
