package com.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private Long id;
    private String userName;
    private List<String> roles;

    public JwtResponse(String accessToken, Long id, String userName, List<String> roles) {
        this.token = accessToken;
        this.id = id;
        this.userName = userName;
        this.roles = roles;
    }
}
