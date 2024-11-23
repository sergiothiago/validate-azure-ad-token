package com.validate.ad.controller;

import com.validate.ad.service.AzureADValidateTokenService;
import com.validate.ad.vo.tokenVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("validateToken")
public class AzureAdValidateToken {

    @Autowired
    private AzureADValidateTokenService azureADValidateTokenService;

    @PostMapping
    public ResponseEntity<Boolean> isTokenValid(@RequestBody tokenVO tokenVO){

        Boolean isValid = azureADValidateTokenService.isTokenValid(tokenVO.getToken());

        return ResponseEntity.ok(isValid);
    }

}
