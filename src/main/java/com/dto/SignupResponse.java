package com.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupResponse {

    private Long id;
    private String userName;
    private String userContact;
    private String userEmail;
}
