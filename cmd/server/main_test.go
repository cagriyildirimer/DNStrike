package main

import "testing"

func TestEnvBool(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		t.Setenv("DNSTRIKE_TEST_BOOL", "")
		value, err := envBool("DNSTRIKE_TEST_BOOL", true)
		if err != nil || !value {
			t.Fatalf("value = %v, error = %v", value, err)
		}
	})
	t.Run("valid", func(t *testing.T) {
		t.Setenv("DNSTRIKE_TEST_BOOL", "false")
		value, err := envBool("DNSTRIKE_TEST_BOOL", true)
		if err != nil || value {
			t.Fatalf("value = %v, error = %v", value, err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		t.Setenv("DNSTRIKE_TEST_BOOL", "sometimes")
		if _, err := envBool("DNSTRIKE_TEST_BOOL", false); err == nil {
			t.Fatal("expected invalid boolean to be rejected")
		}
	})
}

func TestEnvInt(t *testing.T) {
	t.Run("fallback", func(t *testing.T) {
		t.Setenv("DNSTRIKE_TEST_INT", "")
		value, err := envInt("DNSTRIKE_TEST_INT", 2, 1, 32)
		if err != nil || value != 2 {
			t.Fatalf("value = %d, error = %v", value, err)
		}
	})
	t.Run("valid", func(t *testing.T) {
		t.Setenv("DNSTRIKE_TEST_INT", "8")
		value, err := envInt("DNSTRIKE_TEST_INT", 2, 1, 32)
		if err != nil || value != 8 {
			t.Fatalf("value = %d, error = %v", value, err)
		}
	})
	for _, value := range []string{"zero", "0", "33"} {
		t.Run("invalid_"+value, func(t *testing.T) {
			t.Setenv("DNSTRIKE_TEST_INT", value)
			if _, err := envInt("DNSTRIKE_TEST_INT", 2, 1, 32); err == nil {
				t.Fatalf("expected %q to be rejected", value)
			}
		})
	}
}
