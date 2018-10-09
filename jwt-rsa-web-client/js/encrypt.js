/**
 * Biblioteca usada para geração do SHA-256
 * https://www.npmjs.com/package/js-sha256
 * 
 * 
 * Biblioteca usada para encriptação RSA
 * http://travistidwell.com/jsencrypt/
 */
$(function() {

    var authentication = {
        "username": "",
        "password": "",
        "cpf": ""
    };

    $('#sendOFD').click(function() {
        var publicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuTmF+nsSvUgv6rkYvF5n+hOmCM1d3OsYUZBgeaW74wdMTTxQ4BubbyApkr1fZKab0SD7FVj5J+tlwFTc0aKrybHJZz8VcPv6gNPcUk1drTH9JyfT/ufnchWHKrDw8N0CsIIXml5DOxAMw9Gf7oBC            fZC44NYRSm53vez5qNtaNcNe/uDTtrDypMlwQRpTUexllIqlPxwe1Z4imHTcQsmzoI9qGFdO5mep2MsxdZlIE36beyuBYMaHKsQc+xISjR+FFBtmpWwr2YRA0c2DC86TWMif/QOwPR/MJCSH0wdnEWgFoy1tRENkho+Y4NTZzXdoEySGyTbLmit5oxyEfF6OjwIDAQAB-----END PUBLIC KEY-----";
        // Encrypt with the public key...
        var encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKey);
        var encryptedPassword = encrypt.encrypt($('#password').val());

        authentication.username = $('#username').val();
        authentication.password = encryptedPassword;
        authentication.cpf = $('#username').val();

        $.ajax({
            url: "http://localhost:8080/auth",
            cache: false,
            type: "POST",
            headers: {
                "Content-Type":"application/json",
                "X-SERVCore-Business-Key":  Math.floor((Math.random() * 999999))
            },
            data: JSON.stringify(authentication),
            success: function(data) {
                alert(JSON.stringify(data));
            },
            error: function(data) {
                alert(JSON.stringify(data));
            }
          });

    });
    
  });