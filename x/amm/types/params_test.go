package types

import "testing"

func TestDefaultParamsValidate(t *testing.T) {
	params := DefaultParams()
	if err := params.Validate(); err != nil {
		t.Fatalf("DefaultParams().Validate() = %v", err)
	}
}

func TestParamsIsAllowedFeeBps(t *testing.T) {
	params := DefaultParams()

	tests := []struct {
		poolType PoolType
		feeBps   uint32
		want     bool
	}{
		{PoolType_POOL_TYPE_CONSTANT_PRODUCT, 5, true},
		{PoolType_POOL_TYPE_CONSTANT_PRODUCT, 10, true},
		{PoolType_POOL_TYPE_CONSTANT_PRODUCT, 30, true},
		{PoolType_POOL_TYPE_CONSTANT_PRODUCT, 7, false},
		{PoolType_POOL_TYPE_STABLESWAP, 1, true},
		{PoolType_POOL_TYPE_STABLESWAP, 3, true},
		{PoolType_POOL_TYPE_STABLESWAP, 5, true},
		{PoolType_POOL_TYPE_STABLESWAP, 30, false},
	}

	for _, tc := range tests {
		if got := params.IsAllowedFeeBps(tc.poolType, tc.feeBps); got != tc.want {
			t.Fatalf("IsAllowedFeeBps(%s, %d) = %v, want %v", tc.poolType, tc.feeBps, got, tc.want)
		}
	}
}

func TestParamsValidateRejectsInvalidConfigurations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Params)
	}{
		{
			name: "empty CP tiers",
			mutate: func(p *Params) {
				p.CpFeeTiersBps = nil
			},
		},
		{
			name: "empty stable tiers",
			mutate: func(p *Params) {
				p.StableFeeTiersBps = nil
			},
		},
		{
			name: "duplicate CP tiers",
			mutate: func(p *Params) {
				p.CpFeeTiersBps = []uint32{5, 5, 30}
			},
		},
		{
			name: "unsorted CP tiers",
			mutate: func(p *Params) {
				p.CpFeeTiersBps = []uint32{30, 5, 10}
			},
		},
		{
			name: "tier above max fee",
			mutate: func(p *Params) {
				p.CpFeeTiersBps = []uint32{5, 10, 40}
			},
		},
		{
			name: "default fee not a CP tier",
			mutate: func(p *Params) {
				p.DefaultFeeBps = 7
			},
		},
		{
			name: "max total below sum",
			mutate: func(p *Params) {
				p.MaxTotalFeeBps = p.MaxFeeBps + p.MaxIntegratorFeeBps - 1
			},
		},
		{
			name: "max pools below tier count",
			mutate: func(p *Params) {
				p.MaxPoolsPerPair = uint32(len(p.CpFeeTiersBps) + len(p.StableFeeTiersBps) - 1)
			},
		},
		{
			name: "max pools too high",
			mutate: func(p *Params) {
				p.MaxPoolsPerPair = 65
			},
		},
		{
			name: "zero max fee",
			mutate: func(p *Params) {
				p.MaxFeeBps = 0
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := DefaultParams()
			tc.mutate(&params)
			if err := params.Validate(); err == nil {
				t.Fatal("Validate() = nil, want error")
			}
		})
	}
}

func TestParamsValidateAcceptsCustomTiers(t *testing.T) {
	params := DefaultParams()
	params.CpFeeTiersBps = []uint32{1, 3}
	params.StableFeeTiersBps = []uint32{1}
	params.DefaultFeeBps = 3
	params.MaxPoolsPerPair = 3

	if err := params.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}
