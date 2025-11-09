// Package auth provides authentication functionality and singleton access.
// 包 auth 提供认证功能和单例访问。
package auth

import "github.com/goal-web/contracts"

// Defaults holds default configuration values for authentication.
// Defaults 保存认证的默认配置值。
type Defaults struct {
	Guard string // Guard specifies the default guard driver.
	             // Guard 指定默认的守卫驱动。
	User  string // User specifies the default user provider.
	             // User 指定默认的用户提供者。
}

// Config holds authentication configuration.
// Config 保存认证配置。
type Config struct {
	Defaults Defaults                      // Defaults contains default configuration values.
	                                       // Defaults 包含默认配置值。
	Guards   map[string]contracts.Fields  // Guards contains guard-specific configurations.
	                                       // Guards 包含守卫特定配置。
	Users    map[string]contracts.Fields  // Users contains user provider-specific configurations.
	                                       // Users 包含用户提供者特定配置。
}
