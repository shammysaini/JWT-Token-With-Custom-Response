package com.security;

import com.dto.Roles;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.model.UserAccount;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public record UserDetailsImpl(
        Long id,
        String username,
        String email,
        Roles roles,
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String password,
        List<GrantedAuthority> authorities
) implements UserDetails {

    public static UserDetailsImpl build(UserAccount user) {
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(user.getUserRole().toString()));
        return new UserDetailsImpl(
                user.getId(),
                user.getUserEmail(),
                user.getUserName(),
                user.getUserRole(),
                user.getPassword(),
                authorities
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}