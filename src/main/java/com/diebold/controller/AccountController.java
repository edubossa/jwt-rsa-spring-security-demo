package com.diebold.controller;

import com.diebold.model.Account;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/accounts")
public class AccountController {

    private List<Account> accounts;

    @PostConstruct
    public void setup() {
        this.accounts = new ArrayList<>();
        this.accounts.add(new Account("0989", "787367-2"));
        this.accounts.add(new Account("9867", "456534-9"));
        this.accounts.add(new Account("2312", "878765-4"));
        this.accounts.add(new Account("6545", "563238-8"));
        this.accounts.add(new Account("6764", "235656-1"));
    }


    @GetMapping
    public ResponseEntity<List<Account>> getAccounts() {
        return new ResponseEntity<>(this.accounts, HttpStatus.OK);
    }

}
