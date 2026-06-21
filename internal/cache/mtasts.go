package cache

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"rookery/internal/smtp"
)

// RedisPolicyCache stores resolved MTA-STS policies in Redis, using the native
// key TTL as the policy's max_age expiry. It implements smtp.PolicyCache.
type RedisPolicyCache struct {
	rdb *redis.Client
}

func NewRedisPolicyCache(rdb *redis.Client) *RedisPolicyCache {
	return &RedisPolicyCache{rdb: rdb}
}

func policyKey(domain string) string { return "mtasts:policy:" + domain }

func (c *RedisPolicyCache) Get(ctx context.Context, domain string) (*smtp.STSPolicy, bool, error) {
	val, err := c.rdb.Get(ctx, policyKey(domain)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var p smtp.STSPolicy
	if err := json.Unmarshal(val, &p); err != nil {
		return nil, false, err
	}
	return &p, true, nil
}

func (c *RedisPolicyCache) Put(ctx context.Context, domain string, p *smtp.STSPolicy, ttl time.Duration) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, policyKey(domain), b, ttl).Err()
}
