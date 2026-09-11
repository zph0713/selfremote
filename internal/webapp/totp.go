package webapp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// verifyTOTP checks a 6-digit code with the default ±1 step drift window.
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" || secret == "" {
		return false
	}
	return totp.Validate(code, secret)
}

// handleMFABegin generates a pending TOTP secret for the user.
func (s *Server) handleMFABegin(w http.ResponseWriter, r *http.Request, u *User) {
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/settings", "", "表单校验失败，请重试")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "selfremote",
		AccountName: u.Username,
	})
	if err != nil {
		redirectMsg(w, r, "/settings", "", "生成密钥失败")
		return
	}
	if err := s.setTOTPSecret(r.Context(), u.ID, key.Secret()); err != nil {
		log.Printf("set totp secret: %v", err)
		redirectMsg(w, r, "/settings", "", "保存密钥失败")
		return
	}
	log.Printf("user %s: MFA enrollment started", u.Username)
	http.Redirect(w, r, "/settings?enroll=1", http.StatusSeeOther)
}

// handleMFAQR renders the enrollment QR code (PNG).
func (s *Server) handleMFAQR(w http.ResponseWriter, r *http.Request, u *User) {
	if u.TOTPSecret == "" || u.TOTPEnabled {
		http.NotFound(w, r)
		return
	}
	uri := fmt.Sprintf("otpauth://totp/selfremote:%s?secret=%s&issuer=selfremote",
		u.Username, u.TOTPSecret)
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		http.Error(w, "bad key", http.StatusInternalServerError)
		return
	}
	img, err := key.Image(240, 240)
	if err != nil {
		http.Error(w, "qr render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_ = png.Encode(w, img)
}

// handleMFAConfirm verifies the first code and enables MFA, issuing recovery
// codes (shown exactly once).
func (s *Server) handleMFAConfirm(w http.ResponseWriter, r *http.Request, u *User) {
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/settings", "", "表单校验失败，请重试")
		return
	}
	if u.TOTPSecret == "" {
		redirectMsg(w, r, "/settings", "", "请先生成绑定密钥")
		return
	}
	if !verifyTOTP(u.TOTPSecret, r.FormValue("code")) {
		redirectMsg(w, r, "/settings?enroll=1", "", "验证码不正确，请确认手机时间准确后重试")
		return
	}
	if err := s.enableTOTP(r.Context(), u.ID); err != nil {
		redirectMsg(w, r, "/settings?enroll=1", "", "保存失败")
		return
	}

	// Recovery codes: shown once, stored only as hashes.
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		codes[i] = strings.ToUpper(randomHex(5))
		sum := sha256.Sum256([]byte(codes[i]))
		hashes[i] = hex.EncodeToString(sum[:])
	}
	if err := s.setRecoveryCodes(r.Context(), u.ID, hashes); err != nil {
		log.Printf("set recovery codes: %v", err)
		redirectMsg(w, r, "/settings", "", "恢复码保存失败")
		return
	}
	u.TOTPEnabled = true
	log.Printf("user %s: MFA enabled", u.Username)
	s.render(w, r, "recovery.html", pageData{Title: "MFA 已启用", Data: map[string]any{"Codes": codes}})
}
