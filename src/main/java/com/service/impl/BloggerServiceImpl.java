package com.service.impl;

import com.dto.CommonResponse;
import com.dto.Roles;
import com.dto.SignupRequest;
import com.dto.SignupResponse;
import com.model.UserAccount;
import com.repo.AdminRepo;
import com.service.BloggerService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
public class BloggerServiceImpl implements BloggerService {

    private final AdminRepo adminRepo;
    private final PasswordEncoder passwordEncoder;

    public BloggerServiceImpl(AdminRepo adminRepo, PasswordEncoder passwordEncoder) {
        this.adminRepo = adminRepo;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public CommonResponse<SignupResponse> saveRecord(SignupRequest signupRequest) {
        CommonResponse<SignupResponse> commonResponse = new CommonResponse<>();
        try {
            Optional<UserAccount> optAccounts = adminRepo.findByUserEmail(signupRequest.getUserEmail());
            if (optAccounts.isPresent()) {
                commonResponse.setResult(false);
                commonResponse.setMessage("This email is already registered");
                //commonResponse.setStatus(HttpStatus.BAD_REQUEST.value());
                commonResponse.setStatus(HttpStatus.CONFLICT.value());
                commonResponse.setData(null);
                return commonResponse;
            }
            UserAccount userAccounts = new UserAccount();
            userAccounts.setUserName(signupRequest.getUserName());
            userAccounts.setUserContact(signupRequest.getUserContact());
            userAccounts.setUserEmail(signupRequest.getUserEmail());
            userAccounts.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
            userAccounts.setUserRole(Roles.ADMIN);
            userAccounts = adminRepo.save(userAccounts);
            SignupResponse signupResponse = new SignupResponse();
            signupResponse.setId(userAccounts.getId());
            signupResponse.setUserName(signupRequest.getUserName());
            signupResponse.setUserContact(signupRequest.getUserContact());
            signupResponse.setUserEmail(signupRequest.getUserEmail());
            commonResponse.setResult(true);
            commonResponse.setMessage("record.success");
            commonResponse.setStatus(HttpStatus.OK.value());
            commonResponse.setData(signupResponse);
            return commonResponse;
        } catch (Exception e) {
            // Handle unexpected exceptions
            commonResponse.setResult(false);
            commonResponse.setMessage("An error occurred during user registration.");
            commonResponse.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return commonResponse;
    }
}

