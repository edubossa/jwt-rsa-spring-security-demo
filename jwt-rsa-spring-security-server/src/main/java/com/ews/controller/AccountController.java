package com.ews.controller;

import com.ews.model.Account;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/accounts")
public class AccountController {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

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
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<Account>> getAccounts() {
        return new ResponseEntity<>(this.accounts, HttpStatus.OK);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Account> postAccounts(@RequestBody Account account) {
        log.info(account.toString());
        this.accounts.add(account);
        return new ResponseEntity<Account>(account, HttpStatus.OK);
    }

}
