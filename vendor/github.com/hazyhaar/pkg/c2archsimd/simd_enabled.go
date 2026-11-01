//go:build goexperiment.simd && amd64

package c2archsimd

// SimdEnabled indique que la compilation courante active les instructions vectorielles archsimd.
const SimdEnabled = true
