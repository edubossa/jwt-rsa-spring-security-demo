package com.diebold.model;

public class Account {

    private String agency;
    private String account;

    public Account() {
    }

    public Account(String agency, String account) {
        this.agency = agency;
        this.account = account;
    }

    public String getAgency() {
        return agency;
    }

    public void setAgency(String agency) {
        this.agency = agency;
    }

    public String getAccount() {
        return account;
    }

    public void setAccount(String account) {
        this.account = account;
    }

    @Override
    public String toString() {
        return "Account{" +
                "agency='" + agency + '\'' +
                ", account='" + account + '\'' +
                '}';
    }
}
