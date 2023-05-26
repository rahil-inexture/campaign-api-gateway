package com.campaign.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.campaign.gateway.filter.TokenAuthenticationFilter;

@Configuration
public class GatewayConfiguration {

	@Autowired
	private TokenAuthenticationFilter filter;

	@Bean
	public RouteLocator routes(RouteLocatorBuilder builder) {
		return builder.routes().route("campaign-auth", r -> r.path("/auth/**").filters(f -> f.filter(filter)).uri("lb://campaign-auth"))
				.route("campaign-analytics", r -> r.path("/api/analytics/**").filters(f -> f.filter(filter)).uri("lb://campaign-analytics"))
				.route("campaign-integration", r -> r.path("/api/integrate/**").filters(f -> f.filter(filter)).uri("lb://campaign-integration"))
				.route("campaign-payment", r -> r.path("/api/payments/**").filters(f -> f.filter(filter)).uri("lb://campaign-payment")).build();
	}
	
}
