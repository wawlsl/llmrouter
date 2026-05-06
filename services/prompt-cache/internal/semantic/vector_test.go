package semantic

import (
	"math"
	"testing"
)

func TestCosineSimilarity(t *testing.T) {
	tests := []struct {
		name string
		a    []float32
		b    []float32
		want float32
	}{
		{
			name: "Identical vectors",
			a:    []float32{1, 0, 0},
			b:    []float32{1, 0, 0},
			want: 1.0,
		},
		{
			name: "Orthogonal vectors",
			a:    []float32{1, 0, 0},
			b:    []float32{0, 1, 0},
			want: 0.0,
		},
		{
			name: "Opposite vectors",
			a:    []float32{1, 0, 0},
			b:    []float32{-1, 0, 0},
			want: -1.0,
		},
		{
			name: "Similar vectors",
			a:    []float32{1, 1, 0},
			b:    []float32{1, 1, 0},
			want: 1.0, // Normalized, they point in same direction
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CosineSimilarity(tt.a, tt.b)
			if math.Abs(float64(got-tt.want)) > 1e-6 {
				t.Errorf("CosineSimilarity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFloat32BytesConversion(t *testing.T) {
	original := []float32{0.1, 0.2, 0.5, -1.0, 3.14159}

	bytes := Float32ToBytes(original)
	restored := BytesToFloat32(bytes)

	if len(original) != len(restored) {
		t.Fatalf("Length mismatch: got %d, want %d", len(restored), len(original))
	}

	for i := range original {
		if original[i] != restored[i] {
			t.Errorf("Index %d: got %f, want %f", i, restored[i], original[i])
		}
	}
}
