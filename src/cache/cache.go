package cache

import (
	"context"
	log "github.com/sirupsen/logrus"
	"mosquitto-go-auth-k8s/acct_info"
	"time"
)

type CachedUserData struct {
	Info       acct_info.ServiceAccountMetadata
	lastUpdate time.Time
	lastUsed   time.Time
}

type UserDataCache struct {
	entries       map[string]CachedUserData
	cacheValidity time.Duration
	cacheTimeout  time.Duration
}

func NewUserDataCache(cacheValidity time.Duration, cacheTimeout time.Duration) UserDataCache {

	entries := make(map[string]CachedUserData)

	return UserDataCache{cacheValidity: cacheValidity, cacheTimeout: cacheTimeout, entries: entries}
}

func (cache *UserDataCache) EntryIsValid(now time.Time, entry *CachedUserData) bool {
	return now.Sub(entry.lastUpdate) < cache.cacheValidity
}

func (cache *UserDataCache) EntryIsUnused(now time.Time, entry *CachedUserData) bool {
	return now.Sub(entry.lastUsed) < cache.cacheTimeout
}

func (cache *UserDataCache) InitEntry(info acct_info.ServiceAccountMetadata, now time.Time) *CachedUserData {
	entry := CachedUserData{
		Info:       info,
		lastUpdate: now,
		lastUsed:   now,
	}
	cache.entries[info.UserName] = entry
	return &entry
}

func (cache *UserDataCache) Prune(now time.Time) {
	var deletionCandidates []string
	for user, userData := range cache.entries {
		if !cache.EntryIsUnused(now, &userData) {
			deletionCandidates = append(deletionCandidates, user)
		}
	}
	for _, user := range deletionCandidates {
		log.Infof("Pruning cache for user %s", user)
		delete(cache.entries, user)
	}
}

func (cache *UserDataCache) RefreshIfStale(ctx context.Context, username string, client acct_info.K8sAccountsClient) *CachedUserData {
	now := time.Now()
	cacheEntry, ok := cache.entries[username]
	if !ok {
		log.Infof("Have no entry in user cacheEntry for user %s, recreating...", username)
		cacheEntry = CachedUserData{}
	}

	if !ok || !cache.EntryIsValid(now, &cacheEntry) {
		meta, err := client.GetAccountMetadata(ctx, username)

		if err != nil {
			log.Errorf("Failed to receive ServiceAccountMetadata for user %s: %s", username, err)
			delete(cache.entries, username)
			return nil
		}

		cacheEntry.Info = *meta
		cacheEntry.lastUpdate = now
		log.Debugf("Refreshed access info in cacheEntry for user %s", username)
	} else {
		log.Debugf("Get access from cacheEntry for user %s", username)
	}
	cacheEntry.lastUsed = now
	cache.entries[username] = cacheEntry

	// clean up other old cacheEntry entries
	cache.Prune(now)
	return &cacheEntry
}
