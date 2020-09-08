package com.instagram.payload.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class ResetPasswordRequest {
    @NotBlank
    private String userName;

    @NotBlank
    private String newPassword;
}
