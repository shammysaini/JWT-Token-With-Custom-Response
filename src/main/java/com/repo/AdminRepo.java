package com.repo;

import com.model.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AdminRepo extends JpaRepository<UserAccount, Long> {
    Optional<UserAccount> findByUserEmail(String userEmail);
}
