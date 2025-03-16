package com.service;

import com.dto.CommonResponse;
import com.dto.SignupRequest;
import com.dto.SignupResponse;

public interface BloggerService {
    CommonResponse<SignupResponse> saveRecord(SignupRequest signupRequest);
}
