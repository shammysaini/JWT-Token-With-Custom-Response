package com.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupRequest {

    @NotBlank(message = "First name should not be empty")
    private String userName;
    @NotBlank(message = "Contact number should not be empty")
    private String userContact;
    @NotBlank(message = "Email should not be empty")
    @Email(message = "Invalid email ID")
    private String userEmail;
    private String password;

}
