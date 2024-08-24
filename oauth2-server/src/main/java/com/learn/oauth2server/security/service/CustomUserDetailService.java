package com.learn.oauth2server.security.service;

import com.learn.oauth2server.entity.User;
import com.learn.oauth2server.repo.UserRepo;
import com.learn.oauth2server.security.model.AuthenticationUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Collections;

@Service
public class CustomUserDetailService implements UserDetailsService {

    @Autowired
    private  PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepo userRepo;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.learn.oauth2server.entity.User user = userRepo.findByUsername(username);
        user = new User();
        user.setUsername("test");
        /*
        *password is test
         */
        user.setPassword(passwordEncoder.encode("test"));
        user.set_active(true);
        return  new AuthenticationUser(user);


    }
}
