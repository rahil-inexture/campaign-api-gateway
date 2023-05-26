package com.campaign.gateway.entity;

import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Entity(name="USER_TOKENS")
public class UserAuth {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name="USER_AUTH_ID")
	private long userAuthId;
	
	@Column(name="UUID")
	private String uuid;
	
	@Column(name="USER_ID")
	@NotNull
	private long userId;
	
	@Column(name="ACCESS_TOKEN",columnDefinition = "text") 
	@NotNull
	private String accessToken;
	
	@Column(name="REFRESH_TOKEN", columnDefinition = "text") 
	private String refreshToken;
	
	@Column(name="EXPIRES_AT")
	@NotNull
	private Date expiresAt;
	
	@Column(name="ISSUED_AT")
	private Date issuedAt;
	

}
