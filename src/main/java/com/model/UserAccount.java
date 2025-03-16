package com.model;

import com.dto.Roles;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Entity
@Getter
@Setter
@Table(name = "blogger_accounts")
public class UserAccount implements Serializable {

        /**
         *
         */
        private static final long serialVersionUID = 7696179307247795978L;

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private long id;
        @Column(length = 35)
        private String userName;
        @Column(length = 10)
        private String userContact;
        @Column(unique = true, length = 35)
        private String userEmail;
        @Column(length = 60)
        private String password;
        @Enumerated(EnumType.STRING)
        private Roles userRole;


    }
