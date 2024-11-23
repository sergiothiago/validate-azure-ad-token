package com.validate.ad.vo;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class tokenVO {

    @NotNull(message = "O token não pode ser nulo")
    String token;

}
