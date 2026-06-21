package cache

import "github.com/redis/go-redis/v9"

// NewClient builds a Redis client for the given address (host:port). rspamd's
// bundled redis runs without auth, so no password is configured.
func NewClient(addr string) *redis.Client {
	return redis.NewClient(&redis.Options{Addr: addr})
}
