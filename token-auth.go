package traefik_plugin_token_auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	auth "github.com/LyuHe-uestc/traefik-plugin-token-auth/auth"
	goauth "github.com/containous/go-http-auth"
)

type Config struct {
	AuthKind     string
	SecretPram   string
	SecretValue  string
	SecretKind   string
	Users        []string `json:"users,omitempty" toml:"users,omitempty" yaml:"users,omitempty" loggable:"false"`
	UsersFile    string   `json:"usersFile,omitempty" toml:"usersFile,omitempty" yaml:"usersFile,omitempty"`
	Realm        string   `json:"realm,omitempty" toml:"realm,omitempty" yaml:"realm,omitempty"`
	RemoveHeader bool     `json:"removeHeader,omitempty" toml:"removeHeader,omitempty" yaml:"removeHeader,omitempty" export:"true"`
	HeaderField  string   `json:"headerField,omitempty" toml:"headerField,omitempty" yaml:"headerField,omitempty" export:"true"`
}

func CreateConfig() *Config {
	return &Config{
		AuthKind:     "",
		SecretPram:   "",
		SecretValue:  "",
		SecretKind:   "",
		Users:        []string{},
		UsersFile:    "",
		Realm:        "",
		RemoveHeader: false,
		HeaderField:  "",
	}
}

type Auth struct {
	next         http.Handler
	name         string
	conf         *Config
	auth         *goauth.BasicAuth
	users        map[string]string
	headerField  string
	removeHeader bool
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	users, err := auth.GetUsers(config.UsersFile, config.Users, basicUserParser)
	if err != nil {
		return nil, err
	}

	ba := &Auth{
		next:         next,
		users:        users,
		headerField:  config.HeaderField,
		removeHeader: config.RemoveHeader,
		name:         name,
		conf:         config,
	}

	realm := "traefik"
	if len(config.Realm) > 0 {
		realm = config.Realm
	}

	ba.auth = &goauth.BasicAuth{Realm: realm, Secrets: ba.secretBasic}

	return ba, nil
}

func (a *Auth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if a.conf.AuthKind == "token" {
		secPram := a.conf.SecretPram
		secValue := a.conf.SecretValue
		secKind := a.conf.SecretKind
		switch secKind {
		//判断key的位置
		case "cookie":
			//判断key是否存在
			if req.Header.Get("cookie") != "" {
				little_cookie, _ := req.Cookie(secPram)
				//提取key,判断是否符合
				if little_cookie.Value != secValue {
					http.Error(rw, fmt.Errorf("Wrong Sec Value").Error(), http.StatusUnauthorized)
					return
				}
			}
		case "header":
			//判断key是否存在，提取key，判断是否符合
			if req.Header.Get(secPram) != secValue {
				http.Error(rw, fmt.Errorf("Wrong Sec Value").Error(), http.StatusUnauthorized)
				return
			}
		default:
			http.Error(rw, fmt.Errorf("secretKind must be cookie or header").Error(), http.StatusInternalServerError)
			return
		}

		a.next.ServeHTTP(rw, req)
	} else {

		user, password, ok := req.BasicAuth()
			if ok {
				secret := a.auth.Secrets(user, a.auth.Realm)
				if secret == "" || !goauth.CheckSecret(password, secret) {
					ok = false
				}
			} 
			if !ok {
				a.auth.RequireAuth(rw, req)
				return
			}
			req.URL.User = url.User(user)

			if a.headerField != "" {
				req.Header[a.headerField] = []string{user}
			}

			if a.removeHeader {
				req.Header.Del("Authorization")
			}
		
		a.next.ServeHTTP(rw, req)
	}
}

func reject(rw http.ResponseWriter) {
	statusCode := http.StatusForbidden

	rw.WriteHeader(statusCode)
}

func (b *Auth) secretBasic(user, realm string) string {
	if secret, ok := b.users[user]; ok {
		return secret
	}

	return ""
}

func basicUserParser(user string) (string, string, error) {
	split := strings.Split(user, ":")
	if len(split) != 2 {
		return "", "", fmt.Errorf("error parsing BasicUser: %v", user)
	}
	return split[0], split[1], nil
}
