package selling_partner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

type AccessTokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type Config struct {
	ClientID     string //SP-API
	ClientSecret string //SP-API
	RefreshToken string //
}

func (o Config) IsValid() (bool, error) {
	if o.RefreshToken == "" {
		return false, errors.New("refresh token is required")
	}
	if o.ClientID == "" {
		return false, errors.New("client id is required")
	}
	if o.ClientSecret == "" {
		return false, errors.New("client secret is required")
	}
	return true, nil
}

var (
	ErrRefreshTokenNeeded = errors.New("refresh token is needed")
	ErrRefreshTokenFail   = errors.New("refresh token fail")
)

type SellingPartner struct {
	cfg               *Config
	accessToken       string
	accessTokenExpiry time.Time
}

func NewSellingPartner(cfg *Config) (*SellingPartner, error) {
	if isValid, err := cfg.IsValid(); !isValid {
		return nil, err
	}

	sp := &SellingPartner{}
	sp.cfg = cfg

	return sp, nil
}

func (s *SellingPartner) RefreshToken() error {
	// refresh token needed
	if s.cfg.RefreshToken == "" {
		return ErrRefreshTokenNeeded
	}

	reqBody, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": s.cfg.RefreshToken,
		"client_id":     s.cfg.ClientID,
		"client_secret": s.cfg.ClientSecret,
	})

	resp, err := http.Post(
		"https://api.amazon.com/auth/o2/token",
		"application/json",
		bytes.NewBuffer(reqBody))

	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	theResp := &AccessTokenResponse{}

	if err = json.Unmarshal(respBodyBytes, theResp); err != nil {
		log.Errorf("RefreshToken response parse failed. Body: ", string(respBodyBytes))
		return err
	}

	if theResp.AccessToken != "" {
		s.accessToken = theResp.AccessToken
		s.accessTokenExpiry = time.Now().UTC().Add(time.Duration(theResp.ExpiresIn) * time.Second) //set expiration time
		return nil
	}

	if theResp.Error != "" {
		log.Errorf("RefreshToken failed with code %s, description %s", theResp.Error, theResp.ErrorDescription)
		return errors.New(theResp.Error)
	}

	log.Errorf("RefreshToken failed with unknown reason. Body: %s", string(respBodyBytes))
	return ErrRefreshTokenFail
}

func (s *SellingPartner) OAuth2(code string) error {

	reqBody, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     s.cfg.ClientID,
		"client_secret": s.cfg.ClientSecret,
	})

	resp, err := http.Post(
		"https://api.amazon.com/auth/o2/token",
		"application/json",
		bytes.NewBuffer(reqBody))

	if err != nil {
		return errors.New("RefreshToken call failed with error " + err.Error())
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("RefreshToken read response with error " + err.Error())
	}

	theResp := &AccessTokenResponse{}

	if err = json.Unmarshal(respBodyBytes, theResp); err != nil {
		return errors.New("RefreshToken response parse failed. Body: " + string(respBodyBytes))
	}

	if theResp.AccessToken != "" {
		s.accessToken = theResp.AccessToken
		s.accessTokenExpiry = time.Now().UTC().Add(time.Duration(theResp.ExpiresIn) * time.Second) //set expiration time
	} else if theResp.Error != "" {
		return errors.New(fmt.Sprintf("RefreshToken failed with code %s, description %s", theResp.Error, theResp.ErrorDescription))
	} else {
		return errors.New(fmt.Sprintf("RefreshToken failed with unknown reason. Body: %s", string(respBodyBytes)))
	}

	return nil
}

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 1 * time.Minute

func (s *SellingPartner) AuthorizeRequest(r *http.Request) error {

	if s.accessToken == "" ||
		s.accessTokenExpiry.IsZero() ||
		s.accessTokenExpiry.Round(0).Add(-expiryDelta).Before(time.Now().UTC()) {
		if err := s.RefreshToken(); err != nil {
			return fmt.Errorf("cannot refresh token. Error: %s", err.Error())
		}
	}

	r.Header.Add("X-Amz-Access-Token", s.accessToken)

	return nil
}
