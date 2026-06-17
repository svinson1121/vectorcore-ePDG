package cpucaps

// CPU hardware crypto extension detection.
//
// Two paths in the ePDG benefit from AES-NI:
//
//  1. IKEv2 control plane (Go crypto/aes): aes.NewCipher automatically uses
//     AES-NI assembly on amd64 when the CPU supports it.  This covers IKE SA
//     SK payload encrypt/decrypt at handshake and rekey time — not per-packet,
//     so the impact is modest but measurable under high attach load.
//
//  2. XFRM ESP data plane (kernel crypto API): the "cbc(aes)" algorithm name
//     we write to netlink causes the kernel to select the highest-priority
//     registered implementation.  When aesni_intel is loaded, that is
//     cbc-aes-aesni (priority 300+), which runs AES-NI in kernel context for
//     every ESP packet.  This is the dominant crypto cost at scale.
//
// Neither path has a Go-level on/off switch — hardware acceleration is
// selected automatically by the runtime and the kernel crypto API.  To disable
// AES-NI at the OS level (e.g. for benchmarking): modprobe -r aesni_intel.

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/sys/cpu"
)

// Caps holds detected CPU hardware crypto extension support.
// All fields are false on non-x86 architectures.
type Caps struct {
	AESNI     bool // AES-NI: hardware AES block cipher (ENCR_AES_CBC)
	SSSE3     bool // SSSE3: used by kernel sha256-ssse3 for HMAC-SHA256/SHA512 in ESP
	PCLMULQDQ bool // carry-less multiplication (GCM mode; not currently used)
}

// Detect probes the running CPU for hardware crypto extensions.
func Detect() Caps {
	return Caps{
		AESNI:     cpu.X86.HasAES,
		SSSE3:     cpu.X86.HasSSSE3,
		PCLMULQDQ: cpu.X86.HasPCLMULQDQ,
	}
}

// KernelXFRMUsesAESNI parses /proc/crypto to check whether the kernel has
// loaded an AES-NI-backed implementation of cbc(aes).  This is the algorithm
// the XFRM layer uses for ESP encryption on every data-plane packet.
//
// Returns (true, nil) when cbc(aes) is backed by aesni_intel.
// Returns (false, nil) when cbc(aes) is present but software-only.
// Returns (false, err) when /proc/crypto cannot be read.
func KernelXFRMUsesAESNI() (bool, error) {
	f, err := os.Open("/proc/crypto")
	if err != nil {
		return false, fmt.Errorf("cpucaps: open /proc/crypto: %w", err)
	}
	defer f.Close()

	// /proc/crypto entries are separated by blank lines.  Each entry is a set
	// of "key : value" lines.  We look for any cbc(aes) entry whose driver
	// field contains "aesni" (kernel names it cbc-aes-aesni or similar).
	var (
		inCBCAES bool
		found    bool
	)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			inCBCAES = false
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "name":
			inCBCAES = (v == "cbc(aes)")
		case "driver":
			if inCBCAES && strings.Contains(v, "aesni") {
				found = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("cpucaps: read /proc/crypto: %w", err)
	}
	return found, nil
}

// Log emits structured startup log lines describing hardware crypto availability
// and how each ePDG subsystem is affected.
func (c Caps) Log(log *slog.Logger, kernelAESNI bool) {
	log.Info("CPU hardware crypto extensions",
		"aes_ni", c.AESNI,
		"ssse3", c.SSSE3,
		"pclmulqdq", c.PCLMULQDQ,
		"kernel_xfrm_aes_ni", kernelAESNI,
	)

	switch {
	case c.AESNI && kernelAESNI:
		log.Info("AES-NI active on all crypto paths",
			"ikev2_sk_cipher", "aes-ni (Go runtime auto-selected)",
			"xfrm_esp_cipher", "cbc-aes-aesni (kernel crypto API auto-selected)",
			"xfrm_hmac_sha", fmt.Sprintf("sha-ssse3=%v (kernel crypto API auto-selected)", c.SSSE3),
		)
	case c.AESNI && !kernelAESNI:
		log.Warn("AES-NI present on CPU but kernel XFRM is using software AES",
			"action", "load aesni_intel kernel module to enable hardware ESP encryption",
		)
	case !c.AESNI && kernelAESNI:
		log.Warn("kernel reports AES-NI but CPU detection says it is absent — check virtualization CPU flags")
	default:
		log.Warn("AES-NI not available: IKEv2 and XFRM ESP will use software AES",
			"impact", "significantly reduced IPsec throughput and higher CPU cost per session",
			"action", "use a CPU or VM configuration that exposes AES-NI to the guest",
		)
	}
}
