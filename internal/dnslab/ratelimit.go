package dnslab

// RateLimiter est un seau à jetons par source (adresse 16 octets hachée sur un
// nombre fixe de seaux, collisions partageant le budget), sans allocation,
// pour un usage mono-goroutine.
type RateLimiter struct {
	perSecond uint32
	burst     uint32
	mask      uint32
	tokens    []float32
	stamps    []int64
}

// NewRateLimiter construit le limiteur ; perSecond et burst sont dans
// [1, 1<<20] pour conserver la résolution du solde float32, buckets est
// une puissance de deux. Toute violation rend ErrRateLimiterContract.
func NewRateLimiter(perSecond, burst, buckets uint32) (*RateLimiter, error) {
	if perSecond == 0 || perSecond > 1<<20 || burst == 0 || burst > 1<<20 || buckets == 0 || buckets&(buckets-1) != 0 {
		return nil, ErrRateLimiterContract
	}
	stamps := make([]int64, buckets)
	for i := range stamps {
		stamps[i] = -1
	}
	return &RateLimiter{perSecond: perSecond, burst: burst, mask: buckets - 1, tokens: make([]float32, buckets), stamps: stamps}, nil
}

// Allow consomme un jeton pour la source à l'instant nowUnixMicro et rend vrai
// si la réponse peut partir.
func (r *RateLimiter) Allow(source [16]byte, nowUnixMicro int64) bool {
	const prime uint64 = 1099511628211
	hash := uint64(14695981039346656037)
	for _, octet := range source {
		hash = (hash ^ uint64(octet)) * prime
	}
	index := uint32(hash) & r.mask
	if r.stamps[index] == -1 {
		r.tokens[index] = float32(r.burst)
		r.stamps[index] = nowUnixMicro
	}
	if elapsed := nowUnixMicro - r.stamps[index]; elapsed > 0 {
		r.tokens[index] = min(float32(r.burst), r.tokens[index]+float32(r.perSecond)*float32(elapsed)/1e6)
		r.stamps[index] = nowUnixMicro
	}
	if r.tokens[index] < 1 {
		return false
	}
	r.tokens[index]--
	return true
}
